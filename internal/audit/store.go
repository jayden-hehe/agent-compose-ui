package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agent-compose-ui/internal/dbmigrate"
	_ "modernc.org/sqlite"
)

const (
	defaultFlushInterval = 250 * time.Millisecond
	defaultStartFallback = 2 * time.Second
	defaultMaxPending    = 4096
	// maxBatchSize bounds one transaction independently of the backpressure
	// limit: maxPending says how far behind the writer may fall, this says how
	// long it may hold the write lock at once.
	maxBatchSize      = 512
	maxBatchesPerPass = 8
	cleanupInterval   = 24 * time.Hour
	writeTimeout      = 5 * time.Second
	drainTimeout      = 5 * time.Second
	// closeTimeout must exceed writeTimeout, or Close would report a stall while
	// the final batch is still legitimately inside its own deadline.
	closeTimeout     = drainTimeout + writeTimeout
	maxFlushAttempts = 3
	dropLogInterval  = 30 * time.Second
	readPoolSize     = 4
)

// upsertEventSQL writes one audit event. Every write is an upsert rather than an
// insert-or-update chosen by a flag: a request can finish while the write of its
// "started" row is already in flight, and an insert of an id that a racing batch
// just wrote would abort the whole transaction. Only the four columns that a
// finish can change are updated, so a stale write can never overwrite the
// identity of a completed event.
const upsertEventSQL = `INSERT INTO audit_event(
	id, occurred_at, finished_at, actor_id, actor_source, actor_username, actor_display_name,
	auth_method, category, action, resource_type, resource_id, method, path, outcome, status,
	duration_ms, request_id, remote_ip, user_agent
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
	finished_at=excluded.finished_at, outcome=excluded.outcome,
	status=excluded.status, duration_ms=excluded.duration_ms`

// Store keeps audit events. Writes never happen on the caller's goroutine: they
// are queued in memory and committed in batches by a single writer goroutine, so
// an HTTP request never waits on the database. Reads go through a separate
// read-only pool so a long export cannot queue in front of a write.
type Store struct {
	db     *sql.DB // exactly one connection, owned by the writer goroutine
	readDB *sql.DB // read-only pool used by Query

	retention time.Duration
	logger    *slog.Logger

	// Written before the writer goroutine starts. Tests adjust them between
	// openStore and start.
	flushInterval time.Duration
	startFallback time.Duration
	maxPending    int

	mu         sync.Mutex
	now        func() time.Time // read by the writer goroutine, so guarded by mu
	closed     bool
	started    bool
	pending    map[string]*pendingEvent // started, not yet finished
	ready      []*pendingEvent          // finished, waiting for the next batch
	cleanupReq bool
	forceFlush bool
	flushReq   uint64 // barrier watermark requested by Sync/Cleanup
	flushedSeq uint64 // watermark the writer has committed
	flushDone  chan struct{}
	lastDrop   time.Time

	signalCh chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}

	closeOnce func() error

	dropped atomic.Int64
	flushed atomic.Int64
	failed  atomic.Int64
	batches atomic.Int64
}

// pendingEvent is a queued audit event. It deliberately holds no context: a
// client disconnect must never cancel a batch that carries other requests'
// events.
type pendingEvent struct {
	id         string
	occurredAt time.Time
	actor      Principal
	input      Input
	finished   bool
	finishedAt time.Time
	outcome    string
	status     int
	durationMs int64
	written    bool // a row exists; skip re-emitting it as a "started" placeholder
	attempts   int
}

// flushItem is an immutable snapshot of a pendingEvent taken while mu is held.
// The values are copied so the writer never reads them off the shared pointer
// after releasing the lock; event is kept for identity only (requeue, mark
// written), and is only ever touched under mu.
type flushItem struct {
	event *pendingEvent

	id           string
	occurredAt   int64
	finishedAt   sql.NullInt64
	actor        Principal
	category     string
	action       string
	resourceType string
	resourceID   string
	method       string
	path         string
	outcome      string
	status       int
	durationMs   int64
	requestID    string
	remoteIP     string
	userAgent    string
}

// Stats reports the writer's progress. Dropped events are a security-relevant
// failure, so they are counted rather than only logged.
type Stats struct {
	Dropped int64
	Flushed int64
	Failed  int64
	Batches int64
	Pending int
	Ready   int
}

func OpenStore(path string, retentionDays int) (*Store, error) {
	store, err := openStore(path, retentionDays)
	if err != nil {
		return nil, err
	}
	store.start()
	return store, nil
}

// openStore builds a Store but leaves the writer goroutine stopped, so callers
// can adjust the writer's knobs before it starts. The writer must be started
// last: the startup cleanup below would otherwise race it for the single write
// connection.
func openStore(path string, retentionDays int) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("UI database path is required")
	}
	clean := filepath.Clean(path)
	if err := dbmigrate.Apply(context.Background(), clean); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", writeDSN(clean))
	if err != nil {
		return nil, fmt.Errorf("open audit database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	readDB, err := sql.Open("sqlite", readDSN(clean))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open audit read database: %w", err)
	}
	readDB.SetMaxOpenConns(readPoolSize)
	readDB.SetMaxIdleConns(readPoolSize)

	store := newStore(db, readDB, retentionDays)
	// Retention runs inline here, before the writer exists, so it cannot become
	// a second writer on the single write connection.
	if err := store.cleanupNow(context.Background()); err != nil {
		_ = db.Close()
		_ = readDB.Close()
		return nil, err
	}
	return store, nil
}

func newStore(db, readDB *sql.DB, retentionDays int) *Store {
	store := &Store{
		db:            db,
		readDB:        readDB,
		retention:     time.Duration(retentionDays) * 24 * time.Hour,
		logger:        slog.Default(),
		flushInterval: defaultFlushInterval,
		startFallback: defaultStartFallback,
		maxPending:    defaultMaxPending,
		now:           time.Now,
		pending:       make(map[string]*pendingEvent),
		flushDone:     make(chan struct{}),
		signalCh:      make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	store.closeOnce = sync.OnceValue(store.closeInternal)
	return store
}

// start launches the writer goroutine. It must be called last, after every
// field is set and after the startup cleanup has run.
func (s *Store) start() {
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	go s.run()
}

// Start queues an event in the "started" state. It performs no database work:
// the request path must never inherit a disk stall.
func (s *Store) Start(ctx context.Context, input Input) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	event := &pendingEvent{id: id, actor: normalizePrincipal(input.Actor), input: input}
	s.mu.Lock()
	event.occurredAt = s.now().UTC()
	if s.fullLocked() {
		s.mu.Unlock()
		s.noteDrop()
		return "", nil
	}
	s.pending[id] = event
	s.mu.Unlock()
	s.signal()
	return id, nil
}

// Finish completes a queued event. An unknown or empty id is a no-op, matching
// the behaviour of the synchronous version. Finish never drops: it only moves an
// existing entry, so an event already written as "started" cannot be stranded.
func (s *Store) Finish(ctx context.Context, id, outcome string, status int, duration time.Duration) error {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	event := s.pending[id]
	if event == nil || s.closed {
		s.mu.Unlock()
		return nil
	}
	delete(s.pending, id)
	event.finished = true
	event.finishedAt = s.now().UTC()
	event.outcome = normalizeOutcome(outcome)
	event.status = status
	event.durationMs = max(duration.Milliseconds(), 0)
	s.ready = append(s.ready, event)
	s.mu.Unlock()
	s.signal()
	return nil
}

// Record queues a complete event. The start and finish collapse into a single
// insert, so a fast request costs one statement and no update.
func (s *Store) Record(ctx context.Context, input Input) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.fullLocked() {
		s.mu.Unlock()
		s.noteDrop()
		return nil
	}
	now := s.now().UTC()
	s.ready = append(s.ready, &pendingEvent{
		id: id, occurredAt: now, actor: normalizePrincipal(input.Actor), input: input,
		finished: true, finishedAt: now, outcome: normalizeOutcome(input.Outcome),
		status: input.Status, durationMs: max(input.Duration.Milliseconds(), 0),
	})
	s.mu.Unlock()
	s.signal()
	return nil
}

// Sync flushes every queued event, including in-flight ones, which are written
// as "started", and waits for the batch to commit.
func (s *Store) Sync(ctx context.Context) error {
	return s.barrier(ctx, nil)
}

// Cleanup deletes events older than the retention window. The DELETE runs on the
// writer goroutine and Cleanup waits for it, so a caller that queries right
// afterwards observes the result.
func (s *Store) Cleanup(ctx context.Context) error {
	if s.retention <= 0 {
		return nil
	}
	return s.barrier(ctx, func() { s.cleanupReq = true })
}

// barrier asks the writer for a cycle and waits until one that started after
// this call has committed. Waiting on a plain signal-then-idle check would be
// satisfied by a cycle that began before the caller queued its work.
func (s *Store) barrier(ctx context.Context, mark func()) error {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil
		}
		s.flushReq++
		target := s.flushReq
		done := s.flushDone
		s.forceFlush = true
		if mark != nil {
			mark()
		}
		s.mu.Unlock()
		s.signal()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
		settled := s.flushedSeq >= target
		s.mu.Unlock()
		if settled {
			return nil
		}
	}
}

func (s *Store) run() {
	defer close(s.doneCh)
	defer s.releaseBarrier()
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	retention := time.NewTicker(cleanupInterval)
	defer retention.Stop()
	for {
		select {
		case <-s.stopCh:
			// Drain with a budget of our own: the caller is gone and the caller's
			// context, if any, is not tied to this work.
			ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
			for s.hasWork() && ctx.Err() == nil {
				s.pass(ctx, true)
			}
			cancel()
			return
		case <-ticker.C:
			s.pass(context.Background(), false)
		case <-retention.C:
			s.cleanupNow(context.Background())
		case <-s.signalCh:
			s.pass(context.Background(), false)
		}
	}
}

// pass runs one writer cycle. Cleanup runs before the flush so a Cleanup caller
// waiting on the barrier sees its DELETE already done.
func (s *Store) pass(ctx context.Context, force bool) {
	s.mu.Lock()
	requested := s.cleanupReq
	s.cleanupReq = false
	s.mu.Unlock()
	if requested {
		s.cleanupNow(ctx)
	}
	s.flush(ctx, force)
}

func (s *Store) flush(ctx context.Context, force bool) {
	force = s.consumeForce(force)
	for range maxBatchesPerPass {
		items, watermark, complete := s.takeBatch(force)
		if len(items) > 0 {
			s.writeBatch(ctx, items)
		}
		if complete || len(items) == 0 || ctx.Err() != nil {
			s.advanceBarrier(watermark)
			return
		}
		// The batch cap was reached, not the queue: keep draining in this pass so
		// a Sync does not have to wait a whole tick per batch. The barrier is left
		// alone, because the work up to the watermark is not committed yet.
	}
}

// consumeForce takes the sticky force flag set by Sync/Cleanup. A forced pass
// emits a "started" placeholder for every in-flight event, regardless of age.
func (s *Store) consumeForce(force bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forceFlush {
		force = true
		s.forceFlush = false
	}
	return force
}

// takeBatch snapshots the work for one batch: everything finished, plus any
// in-flight event that has been running long enough to deserve a "started"
// placeholder. A forced batch takes every in-flight event.
//
// It also reports the barrier watermark the batch can satisfy and whether the
// batch drained the queue. Capturing the watermark here rather than reading it
// after the commit is what makes Sync correct: a batch that was already in
// flight when a Sync arrived never saw that request's work, so it must not
// satisfy it. A batch cut short by maxBatchSize must not satisfy it either.
func (s *Store) takeBatch(force bool) ([]flushItem, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	watermark := s.flushReq
	items := make([]flushItem, 0, min(len(s.ready)+len(s.pending), maxBatchSize))
	for index, event := range s.ready {
		if len(items) == maxBatchSize {
			s.ready = s.ready[index:]
			return items, watermark, false
		}
		event.attempts++
		items = append(items, snapshotEvent(event))
	}
	s.ready = nil
	now := s.now().UTC()
	for _, event := range s.pending {
		if event.written || event.attempts >= maxFlushAttempts {
			continue
		}
		if !force && now.Sub(event.occurredAt) < s.startFallback {
			continue
		}
		if len(items) == maxBatchSize {
			return items, watermark, false
		}
		// The event stays in s.pending so a late Finish can still update the row.
		event.attempts++
		items = append(items, snapshotEvent(event))
	}
	return items, watermark, true
}

// hasWork reports whether the shutdown drain still has something to write.
func (s *Store) hasWork() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ready) > 0 {
		return true
	}
	for _, event := range s.pending {
		if !event.written && event.attempts < maxFlushAttempts {
			return true
		}
	}
	return false
}

func snapshotEvent(event *pendingEvent) flushItem {
	item := flushItem{
		event: event, id: event.id, occurredAt: event.occurredAt.UnixMilli(), actor: event.actor,
		category: event.input.Category, action: event.input.Action,
		resourceType: event.input.ResourceType, resourceID: event.input.ResourceID,
		method: event.input.Method, path: event.input.Path,
		requestID: event.input.RequestID, remoteIP: event.input.RemoteIP,
		userAgent: event.input.UserAgent, outcome: "started",
	}
	if event.finished {
		item.finishedAt = sql.NullInt64{Int64: event.finishedAt.UnixMilli(), Valid: true}
		item.outcome = event.outcome
		item.status = event.status
		item.durationMs = event.durationMs
	}
	return item
}

func (item flushItem) args() []any {
	return []any{item.id, item.occurredAt, item.finishedAt, item.actor.ID, item.actor.Source,
		item.actor.Username, item.actor.DisplayName, item.actor.AuthMethod, item.category,
		item.action, item.resourceType, item.resourceID, item.method, item.path, item.outcome,
		item.status, item.durationMs, item.requestID, item.remoteIP, item.userAgent}
}

// writeBatch commits one batch in a single transaction, so a tick costs one
// fsync regardless of how many events it carries.
func (s *Store) writeBatch(parent context.Context, items []flushItem) {
	// Never derive this from a request context: the batch outlives the request.
	ctx, cancel := context.WithTimeout(parent, writeTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.failBatch(items, err)
		return
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, upsertEventSQL, item.args()...); err != nil {
			_ = tx.Rollback()
			s.failBatch(items, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		s.failBatch(items, err)
		return
	}
	s.markWritten(items)
	s.flushed.Add(int64(len(items)))
	s.batches.Add(1)
}

// markWritten records that a row exists for each id, keyed by presence in the
// pending map rather than by pointer identity: a Finish that moved the entry on
// to ready mid-flush must still be marked, or it would be re-emitted forever.
func (s *Store) markWritten(items []flushItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range items {
		if event := s.pending[item.id]; event != nil {
			event.written = true
			event.attempts = 0
		}
	}
}

// failBatch retries a failed batch a bounded number of times. The transaction
// rolled back, so re-sending the same statements cannot double-write. Anything
// past the retry budget is abandoned and counted, not silently forgotten.
func (s *Store) failBatch(items []flushItem, cause error) {
	s.mu.Lock()
	var abandoned int
	for _, item := range items {
		if item.event == nil {
			continue
		}
		if item.event.attempts >= maxFlushAttempts {
			delete(s.pending, item.event.id)
			abandoned++
			continue
		}
		// In-flight events stay in s.pending and are retried by the fallback
		// path; queued ones go back for the next batch.
		if item.event.finished {
			s.ready = append(s.ready, item.event)
		}
	}
	s.mu.Unlock()
	if abandoned > 0 {
		s.failed.Add(int64(abandoned))
	}
	s.logger.Error("audit batch write failed", "events", len(items), "abandoned", abandoned, "error", cause)
}

// advanceBarrier releases every waiting Sync/Cleanup. It runs after each cycle,
// including empty ones, or a barrier on an idle store would wait for the next
// tick. Only the watermark captured by the batch is published, so a Sync that
// arrived mid-flight keeps waiting for a batch that actually saw its work.
func (s *Store) advanceBarrier(watermark uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushedSeq = max(s.flushedSeq, watermark)
	close(s.flushDone)
	s.flushDone = make(chan struct{})
}

// releaseBarrier publishes the current request watermark so no Sync can hang on
// a writer that has already stopped.
func (s *Store) releaseBarrier() {
	s.mu.Lock()
	watermark := s.flushReq
	s.mu.Unlock()
	s.advanceBarrier(watermark)
}

func (s *Store) cleanupNow(ctx context.Context) error {
	if s.retention <= 0 {
		return nil
	}
	s.mu.Lock()
	cutoff := s.now().UTC().Add(-s.retention).UnixMilli()
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_event WHERE occurred_at<?`, cutoff); err != nil {
		// Logged here rather than only returned, because the writer calls this on
		// its own goroutine where there is no caller left to report to.
		s.logger.Error("clean audit events failed", "error", err)
		return fmt.Errorf("clean audit events: %w", err)
	}
	return nil
}

// signal wakes the writer. The channel is buffered to one, so a send that would
// block means a wakeup is already pending and the event is not lost.
func (s *Store) signal() {
	select {
	case s.signalCh <- struct{}{}:
	default:
	}
}

func (s *Store) fullLocked() bool {
	return s.closed || len(s.pending)+len(s.ready) >= s.maxPending
}

func (s *Store) noteDrop() {
	total := s.dropped.Add(1)
	s.mu.Lock()
	now := s.now().UTC()
	loggable := s.lastDrop.IsZero() || now.Sub(s.lastDrop) >= dropLogInterval
	if loggable {
		s.lastDrop = now
	}
	capacity := s.maxPending
	s.mu.Unlock()
	if loggable {
		s.logger.Warn("audit queue is full, dropping events", "dropped_total", total, "capacity", capacity)
	}
}

func (s *Store) Stats() Stats {
	s.mu.Lock()
	pending, ready := len(s.pending), len(s.ready)
	s.mu.Unlock()
	return Stats{
		Dropped: s.dropped.Load(), Flushed: s.flushed.Load(), Failed: s.failed.Load(),
		Batches: s.batches.Load(), Pending: pending, Ready: ready,
	}
}

// setNow swaps the clock. The writer goroutine reads it, so the swap is guarded.
func (s *Store) setNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}

func (s *Store) UpsertOAuthPrincipal(ctx context.Context, provider, subject string, principal Principal) error {
	s.mu.Lock()
	closed := s.closed
	updatedAt := s.now().UTC().Unix()
	s.mu.Unlock()
	if closed {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_principal(provider, subject, principal_id, username, display_name, updated_at)
		VALUES(?,?,?,?,?,?) ON CONFLICT(provider, subject) DO UPDATE SET username=excluded.username,
		display_name=excluded.display_name, updated_at=excluded.updated_at`, provider, subject, principal.ID,
		principal.Username, principal.DisplayName, updatedAt)
	if err != nil {
		return fmt.Errorf("upsert oauth principal: %w", err)
	}
	return nil
}

func (s *Store) Query(ctx context.Context, filter Filter) (Page, error) {
	filter.Limit = min(max(filter.Limit, 1), 500)
	where := []string{"1=1"}
	args := make([]any, 0, 8)
	if !filter.From.IsZero() {
		where = append(where, "occurred_at>=?")
		args = append(args, filter.From.UnixMilli())
	}
	if !filter.To.IsZero() {
		where = append(where, "occurred_at<=?")
		args = append(args, filter.To.UnixMilli())
	}
	for column, value := range map[string]string{"actor_id": filter.Actor, "action": filter.Action, "outcome": filter.Outcome, "resource_type": filter.ResourceType, "resource_id": filter.ResourceID} {
		if value != "" {
			where = append(where, column+"=?")
			args = append(args, value)
		}
	}
	if millis, id, ok := decodeCursor(filter.Cursor); ok {
		where = append(where, "(occurred_at<? OR (occurred_at=? AND id<?))")
		args = append(args, millis, millis, id)
	}
	args = append(args, filter.Limit+1)
	rows, err := s.readDB.QueryContext(ctx, `SELECT id, occurred_at, finished_at, actor_id, actor_source,
		actor_username, actor_display_name, auth_method, category, action, resource_type, resource_id,
		method, path, outcome, status, duration_ms, request_id, remote_ip, user_agent FROM audit_event WHERE `+
		strings.Join(where, " AND ")+` ORDER BY occurred_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return Page{}, fmt.Errorf("query audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]Event, 0, filter.Limit+1)
	for rows.Next() {
		item, err := scanEvent(rows)
		if err != nil {
			return Page{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate audit events: %w", err)
	}
	page := Page{Items: items}
	if len(page.Items) > filter.Limit {
		page.HasMore = true
		page.Items = page.Items[:filter.Limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeCursor(last.OccurredAt.UnixMilli(), last.ID)
	}
	return page, nil
}

// Close flushes everything still queued, stops the writer, and closes both
// handles. It is safe to call more than once.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.closeOnce()
}

func (s *Store) closeInternal() error {
	s.mu.Lock()
	s.closed = true
	started := s.started
	s.mu.Unlock()
	// Only wait for the writer if one was ever launched, or Close would burn the
	// whole deadline waiting on a goroutine that does not exist.
	if started {
		close(s.stopCh)
		select {
		case <-s.doneCh:
		case <-time.After(closeTimeout):
			s.logger.Error("audit writer did not drain before the shutdown deadline")
		}
	}
	return errors.Join(s.db.Close(), s.readDB.Close())
}

// writeDSN configures the single write connection. Pragmas live in the DSN so
// they apply to every connection the pool ever opens, not just the first one.
func writeDSN(path string) string {
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "journal_mode(WAL)")
	// WAL plus NORMAL is the recommended pairing: a process or OS crash is still
	// safe, but a power loss can lose the most recent commits. Batching trades
	// that window for one fsync per batch instead of two per request.
	query.Add("_pragma", "synchronous(NORMAL)")
	// apitoken writes to this same file from a second pool in this process. A
	// deferred transaction that has to upgrade to a write lock fails with
	// SQLITE_BUSY immediately, without consulting busy_timeout, so take the write
	// lock up front.
	query.Set("_txlock", "immediate")
	return fileDSN(path, query)
}

func readDSN(path string) string {
	query := url.Values{}
	query.Set("mode", "ro")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "query_only(true)")
	return fileDSN(path, query)
}

// fileDSN builds a SQLite URI with net/url rather than concatenation, so a path
// containing '?' or '#' cannot truncate the query string.
func fileDSN(path string, query url.Values) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return (&url.URL{Scheme: "file", Path: absolute, RawQuery: query.Encode()}).String()
}

type scanner interface{ Scan(...any) error }

func scanEvent(row scanner) (Event, error) {
	var item Event
	var occurred int64
	var finished sql.NullInt64
	err := row.Scan(&item.ID, &occurred, &finished, &item.Actor.ID, &item.Actor.Source, &item.Actor.Username,
		&item.Actor.DisplayName, &item.Actor.AuthMethod, &item.Category, &item.Action, &item.ResourceType,
		&item.ResourceID, &item.Method, &item.Path, &item.Outcome, &item.Status, &item.DurationMs,
		&item.RequestID, &item.RemoteIP, &item.UserAgent)
	if err != nil {
		return Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	item.OccurredAt = time.UnixMilli(occurred).UTC()
	if finished.Valid {
		value := time.UnixMilli(finished.Int64).UTC()
		item.FinishedAt = &value
	}
	return item, nil
}

func normalizePrincipal(value Principal) Principal {
	if value.ID == "" {
		return PrincipalFromContext(context.Background())
	}
	if value.DisplayName == "" {
		value.DisplayName = value.Username
	}
	return value
}

func normalizeOutcome(value string) string {
	switch value {
	case "success", "denied", "failure", "started":
		return value
	default:
		return "failure"
	}
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
func encodeCursor(millis int64, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(millis, 10) + "|" + id))
}
func decodeCursor(value string) (int64, string, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return 0, "", false
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	millis, err := strconv.ParseInt(parts[0], 10, 64)
	return millis, parts[1], err == nil && parts[1] != ""
}
