package audit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStoreLifecycleQueryAndCleanup(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	store.setNow(func() time.Time { return now })
	input := Input{Actor: Principal{ID: "local:admin", Source: "local", Username: "admin", DisplayName: "Admin", AuthMethod: "password"}, Category: "run", Action: "RunAgent", ResourceType: "project", ResourceID: "project-1", Method: http.MethodPost, Path: "/agentcompose.v2.RunService/RunAgent", Outcome: "success", Status: 200, Duration: 25 * time.Millisecond}
	if err := store.Record(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	syncStore(t, store)
	page, err := store.Query(t.Context(), Filter{Actor: "local:admin", ResourceID: "project-1", Limit: 10})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if page.Items[0].Outcome != "success" || page.Items[0].DurationMs != 25 || page.Items[0].Actor.DisplayName != "Admin" {
		t.Fatalf("event=%#v", page.Items[0])
	}
	store.setNow(func() time.Time { return now.Add(181 * 24 * time.Hour) })
	if err := store.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, _ = store.Query(t.Context(), Filter{Limit: 10})
	if len(page.Items) != 0 {
		t.Fatalf("expired events=%d", len(page.Items))
	}
}

func TestMiddlewareExtractsConnectResourceWithoutSavingBody(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	middleware := NewMiddleware(store, nil)
	payload := append([]byte{0x0a, 0x09}, []byte("project-1")...)
	frame := append([]byte{0, 0, 0, 0, byte(len(payload))}, payload...)
	request := httptest.NewRequest(http.MethodPost, "/agentcompose.v2.RunService/RunAgent", strings.NewReader(string(frame)))
	request = request.WithContext(WithPrincipal(request.Context(), Principal{ID: "local:admin", Source: "local", Username: "admin"}))
	response := httptest.NewRecorder()
	middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(response, request)
	syncStore(t, store)
	page, err := store.Query(t.Context(), Filter{Limit: 10})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if page.Items[0].ResourceType != "project" || page.Items[0].ResourceID != "project-1" {
		t.Fatalf("event=%#v", page.Items[0])
	}
}

func TestOperationClassificationAuditsWritesOnly(t *testing.T) {
	for _, path := range []string{
		"/agentcompose.v2.ProjectService/ValidateProject",
		"/agentcompose.v2.ProjectService/BatchGetLatestSchedulerRuns",
		"/agentcompose.v2.ProjectService/StreamSchedulerRuns",
	} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if operation, ok := inspectOperation(request); ok {
			t.Fatalf("read operation %q classified as write: %#v", path, operation)
		}
	}

	payload := `{"token":"must-not-be-read","input":"must-not-be-read"}`
	request := httptest.NewRequest(http.MethodPost, "/api/webhooks/github", strings.NewReader(payload))
	operation, ok := inspectOperation(request)
	if !ok || operation.Category != "webhook" || operation.ResourceType != "webhook_source" || operation.ResourceID != "github" {
		t.Fatalf("webhook operation = %#v, audited = %v", operation, ok)
	}
	remaining, err := io.ReadAll(request.Body)
	if err != nil || string(remaining) != payload {
		t.Fatalf("webhook body was consumed: %q, err=%v", remaining, err)
	}

	secretLikeSpec := append([]byte{0x0a, 0x0c}, []byte("TOKEN=secret")...)
	resourceType, resourceID := connectResource("/agentcompose.v2.SandboxService/CreateSandbox", secretLikeSpec)
	if resourceType != "" || resourceID != "" {
		t.Fatalf("unapproved request field extracted as resource: %q %q", resourceType, resourceID)
	}
	if safeResourceID("TOKEN=secret") || !safeResourceID("sandbox-123") {
		t.Fatal("safe resource ID validation is too permissive or too restrictive")
	}
	projectID := []byte("project-1")
	projectRef := append([]byte{0x0a, byte(len(projectID))}, projectID...)
	patchRequest := append([]byte{0x0a, byte(len(projectRef))}, projectRef...)
	resourceType, resourceID = connectResource("/agentcompose.v2.ProjectService/PatchProject", patchRequest)
	if resourceType != "project" || resourceID != "project-1" {
		t.Fatalf("PatchProject resource = %q %q", resourceType, resourceID)
	}
	request = httptest.NewRequest(http.MethodPut, "/api/webhook-sources/github", nil)
	operation, ok = inspectOperation(request)
	if !ok || operation.Category != "webhook" || operation.ResourceID != "github" {
		t.Fatalf("webhook source operation = %#v, audited = %v", operation, ok)
	}
}

func TestAuditHTTPListAndExport(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	_ = store.Record(t.Context(), Input{Actor: Principal{ID: "local:admin"}, Category: "token", Action: "token.create", Method: "POST", Path: "/api/ui/v1/tokens", Outcome: "success", Status: 201})
	syncStore(t, store)
	handler := NewHTTPHandler(store)
	for _, path := range []string{"/api/ui/v1/audit/events?limit=10", "/api/ui/v1/audit/export?format=csv"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "token.create") {
			t.Fatalf("%s: %d %q", path, response.Code, response.Body.String())
		}
	}
}

// TestStoreRequestPathNoDBIO is the regression test for the whole change. With
// the writer goroutine stopped, a start/finish/record must succeed, leave no row
// behind, and leave the reader seeing nothing — the request path is decoupled
// from the database entirely, not merely deferred.
func TestStoreRequestPathNoDBIO(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "state.db"), 180)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	id, err := store.Start(t.Context(), testInput())
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if err := store.Finish(t.Context(), id, "success", 200, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(t.Context(), testInput()); err != nil {
		t.Fatal(err)
	}
	if flushed := store.Stats().Flushed; flushed != 0 {
		t.Fatalf("the request path wrote to the database: flushed=%d", flushed)
	}
	if items := queryEvents(t, store, Filter{Limit: 10}); len(items) != 0 {
		t.Fatalf("the request path wrote %d events to the database", len(items))
	}

	store.start()
	syncStore(t, store)
	if items := queryEvents(t, store, Filter{Limit: 10}); len(items) != 2 {
		t.Fatalf("rows=%d, want 2", len(items))
	}
	if flushed := store.Stats().Flushed; flushed != 2 {
		t.Fatalf("flushed=%d, want 2", flushed)
	}
}

// TestStoreRequestPathSurvivesStalledDatabase is the point of the change: a
// stalled or dead database must not be able to park a request.
func TestStoreRequestPathSurvivesStalledDatabase(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		id, err := store.Start(context.Background(), testInput())
		if err != nil {
			done <- err
			return
		}
		if err := store.Finish(context.Background(), id, "success", 200, time.Millisecond); err != nil {
			done <- err
			return
		}
		done <- store.Record(context.Background(), testInput())
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request path blocked on the database")
	}
}

// TestStoreSyncIsABarrier keeps the ticker out of the picture so only Sync can
// flush. A Sync that merely waited for an idle writer would return before its
// own event was committed and fail here.
func TestStoreSyncIsABarrier(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), func(store *Store) {
		store.flushInterval = time.Hour
		store.startFallback = time.Hour
	})
	for index := range 100 {
		if err := store.Record(t.Context(), testInput()); err != nil {
			t.Fatal(err)
		}
		syncStore(t, store)
		if items := queryEvents(t, store, Filter{Limit: 500}); len(items) != index+1 {
			t.Fatalf("after Sync %d: rows=%d, want %d", index, len(items), index+1)
		}
	}
}

// TestStoreFinishAfterFallbackFlushUpdatesRow covers the case that a naive
// implementation breaks: an event written as a "started" placeholder must be
// updated in place, not inserted a second time.
func TestStoreFinishAfterFallbackFlushUpdatesRow(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), func(store *Store) {
		store.flushInterval = 5 * time.Millisecond
		store.startFallback = 10 * time.Millisecond
	})
	id, err := store.Start(t.Context(), testInput())
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	waitFor(t, func() bool { return store.Stats().Flushed == 1 }, "the started placeholder to be flushed")
	items := queryEvents(t, store, Filter{Limit: 10})
	if len(items) != 1 || items[0].Outcome != "started" || items[0].FinishedAt != nil {
		t.Fatalf("placeholder=%#v", items)
	}

	if err := store.Finish(t.Context(), id, "success", 200, 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	syncStore(t, store)
	items = queryEvents(t, store, Filter{Limit: 10})
	if len(items) != 1 {
		t.Fatalf("rows=%d, want 1: %#v", len(items), items)
	}
	if items[0].Outcome != "success" || items[0].Status != 200 || items[0].DurationMs != 5 || items[0].FinishedAt == nil {
		t.Fatalf("event=%#v", items[0])
	}
}

// TestStoreFallbackNoDuplicateRows puts many events through the placeholder path
// and then finishes them all. A duplicate insert aborts the whole batch, so this
// also guards the transaction grouping.
func TestStoreFallbackNoDuplicateRows(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), func(store *Store) {
		store.flushInterval = 5 * time.Millisecond
		store.startFallback = 5 * time.Millisecond
	})
	ids := make([]string, 0, 100)
	for range 100 {
		id, err := store.Start(t.Context(), testInput())
		if err != nil || id == "" {
			t.Fatalf("id=%q err=%v", id, err)
		}
		ids = append(ids, id)
	}
	waitFor(t, func() bool { return store.Stats().Flushed >= 100 }, "the started placeholders to be flushed")
	for _, id := range ids {
		if err := store.Finish(t.Context(), id, "success", 200, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	syncStore(t, store)
	items := pageAll(t, store)
	if len(items) != 100 {
		t.Fatalf("rows=%d, want 100", len(items))
	}
	if seen := countUnique(items); len(seen) != 100 {
		t.Fatalf("distinct ids=%d, want 100", len(seen))
	}
	if failed := store.Stats().Failed; failed != 0 {
		t.Fatalf("failed=%d, want 0", failed)
	}
}

// TestStoreConcurrentRecordNoDuplicateIDs guards the frontend contract: the
// audit list keys its each block on the event id, and Svelte throws if one page
// contains the same id twice.
func TestStoreConcurrentRecordNoDuplicateIDs(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), func(store *Store) {
		store.maxPending = 1 << 20
	})
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			for range 50 {
				if err := store.Record(t.Context(), testInput()); err != nil {
					return
				}
			}
		})
	}
	wg.Wait()
	syncStore(t, store)
	if dropped := store.Stats().Dropped; dropped != 0 {
		t.Fatalf("dropped=%d, want 0", dropped)
	}

	seen := make(map[string]int, 5000)
	cursor := ""
	for {
		page, err := store.Query(t.Context(), Filter{Limit: 500, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		inPage := make(map[string]bool, len(page.Items))
		for _, item := range page.Items {
			if inPage[item.ID] {
				t.Fatalf("id %q appears twice in one page", item.ID)
			}
			inPage[item.ID] = true
			seen[item.ID]++
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 5000 {
		t.Fatalf("distinct ids=%d, want 5000", len(seen))
	}
}

func TestStoreDropsWhenFull(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), func(store *Store) {
		store.maxPending = 8
		store.flushInterval = time.Hour
		store.startFallback = time.Hour
	})
	ids := make([]string, 0, 8)
	for range 20 {
		id, err := store.Start(t.Context(), testInput())
		if err != nil {
			t.Fatal(err)
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) != 8 {
		t.Fatalf("accepted=%d, want 8", len(ids))
	}
	if dropped := store.Stats().Dropped; dropped != 12 {
		t.Fatalf("dropped=%d, want 12", dropped)
	}
	// Finish never drops, or an event already written as "started" could never
	// be completed.
	for _, id := range ids {
		if err := store.Finish(t.Context(), id, "success", 200, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	syncStore(t, store)
	if items := pageAll(t, store); len(items) != 8 {
		t.Fatalf("rows=%d, want 8", len(items))
	}
	if dropped := store.Stats().Dropped; dropped != 12 {
		t.Fatalf("dropped=%d after Finish, want 12", dropped)
	}
}

func TestStoreWritePathIgnoresRequestContext(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.Record(ctx, testInput()); err != nil {
		t.Fatal(err)
	}
	syncStore(t, store)
	if items := queryEvents(t, store, Filter{Limit: 10}); len(items) != 1 {
		t.Fatalf("rows=%d, want 1", len(items))
	}
}

func TestStoreReadPoolIsReadOnly(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	const insert = `INSERT INTO audit_event(id, occurred_at, actor_id, actor_source, actor_username,
		actor_display_name, auth_method, category, action, resource_type, resource_id, method, path,
		outcome, status, duration_ms, request_id, remote_ip, user_agent)
		VALUES('x', 0, '', '', '', '', '', '', '', '', '', '', '', '', 0, 0, '', '', '')`
	if _, err := store.readDB.ExecContext(t.Context(), insert); err == nil {
		t.Fatal("the read pool accepted a write")
	}
}

func TestStorePoolConfiguration(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	if store.db == store.readDB {
		t.Fatal("the write pool and the read pool share a handle")
	}
	if got := store.db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("write pool connections=%d, want 1", got)
	}
	if got := store.readDB.Stats().MaxOpenConnections; got != readPoolSize {
		t.Fatalf("read pool connections=%d, want %d", got, readPoolSize)
	}
}

func TestStoreCloseFlushesPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store := openTestStore(t, path, func(store *Store) {
		store.flushInterval = time.Hour
		store.startFallback = time.Hour
	})
	for range 50 {
		if err := store.Record(t.Context(), testInput()); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if items := pageAll(t, openTestStore(t, path, nil)); len(items) != 50 {
		t.Fatalf("rows=%d, want 50", len(items))
	}
}

func TestStoreCloseDrainsOpenAsStarted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store := openTestStore(t, path, func(store *Store) {
		store.flushInterval = time.Hour
		store.startFallback = time.Hour
	})
	for range 10 {
		if _, err := store.Start(t.Context(), testInput()); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	items := pageAll(t, openTestStore(t, path, nil))
	if len(items) != 10 {
		t.Fatalf("rows=%d, want 10", len(items))
	}
	for _, item := range items {
		if item.Outcome != "started" || item.FinishedAt != nil {
			t.Fatalf("event=%#v", item)
		}
	}
}

func TestStoreCloseIsIdempotent(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), nil)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestStoreCloseWithoutWriter covers openStore's error paths, which close a
// store whose writer goroutine was never launched.
func TestStoreCloseWithoutWriter(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "state.db"), 180)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- store.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited for a writer that was never started")
	}
}

// TestStoreConcurrentCloseAndRecord covers a deferred Finish running after
// Close: the HTTP server can abandon in-flight handlers once its shutdown
// deadline expires, so the store must reject work rather than panic.
func TestStoreConcurrentCloseAndRecord(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), func(store *Store) {
		store.maxPending = 1 << 20
	})
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			for range 100 {
				if err := store.Record(t.Context(), testInput()); err != nil {
					return
				}
			}
		})
	}
	time.Sleep(2 * time.Millisecond)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditExportNoDuplicateIDsUnderWrites(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"), func(store *Store) {
		store.maxPending = 1 << 20
	})
	handler := NewHTTPHandler(store)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			if err := store.Record(t.Context(), testInput()); err != nil {
				return
			}
		}
	})
	syncStore(t, store)
	for range 3 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/ui/v1/audit/export", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("export status=%d", response.Code)
		}
		var payload struct {
			Items []Event `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		seen := make(map[string]bool, len(payload.Items))
		for _, item := range payload.Items {
			if seen[item.ID] {
				t.Fatalf("id %q appears twice in an export", item.ID)
			}
			seen[item.ID] = true
		}
	}
	wg.Wait()
}

func BenchmarkStoreRecord(b *testing.B) {
	store, err := openStore(filepath.Join(b.TempDir(), "state.db"), 180)
	if err != nil {
		b.Fatal(err)
	}
	store.maxPending = 1 << 16
	store.start()
	defer func() { _ = store.Close() }()
	input := testInput()
	b.ReportAllocs()
	queued := 0
	for b.Loop() {
		if err := store.Record(b.Context(), input); err != nil {
			b.Fatal(err)
		}
		// Drain outside the timed region so the queue stays bounded and the
		// measurement is the request path only.
		if queued++; queued == 4096 {
			queued = 0
			b.StopTimer()
			if err := store.Sync(b.Context()); err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
		}
	}
}

func BenchmarkMiddlewareWrap(b *testing.B) {
	store, err := openStore(filepath.Join(b.TempDir(), "state.db"), 180)
	if err != nil {
		b.Fatal(err)
	}
	store.maxPending = 1 << 16
	store.start()
	defer func() { _ = store.Close() }()
	payload := append([]byte{0x0a, 0x09}, []byte("project-1")...)
	frame := append([]byte{0, 0, 0, 0, byte(len(payload))}, payload...)
	handler := NewMiddleware(store, nil).Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	b.ReportAllocs()
	queued := 0
	for b.Loop() {
		request := httptest.NewRequest(http.MethodPost, "/agentcompose.v2.RunService/RunAgent", strings.NewReader(string(frame)))
		request = request.WithContext(WithPrincipal(request.Context(), Principal{ID: "local:admin", Source: "local", Username: "admin"}))
		handler.ServeHTTP(httptest.NewRecorder(), request)
		if queued++; queued == 4096 {
			queued = 0
			b.StopTimer()
			if err := store.Sync(b.Context()); err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
		}
	}
}

func testInput() Input {
	return Input{Actor: Principal{ID: "local:admin", Source: "local", Username: "admin", DisplayName: "admin", AuthMethod: "password"},
		Category: "run", Action: "RunAgent", ResourceType: "project", ResourceID: "project-1",
		Method: http.MethodPost, Path: "/agentcompose.v2.RunService/RunAgent", Outcome: "success", Status: 200}
}

func openTestStore(t *testing.T, path string, mutate func(*Store)) *Store {
	t.Helper()
	store, err := openStore(path, 180)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(store)
	}
	store.start()
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func syncStore(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func queryEvents(t *testing.T, store *Store, filter Filter) []Event {
	t.Helper()
	page, err := store.Query(t.Context(), filter)
	if err != nil {
		t.Fatal(err)
	}
	return page.Items
}

func pageAll(t *testing.T, store *Store) []Event {
	t.Helper()
	items := make([]Event, 0, 64)
	cursor := ""
	for {
		page, err := store.Query(t.Context(), Filter{Limit: 500, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, page.Items...)
		if !page.HasMore {
			return items
		}
		cursor = page.NextCursor
	}
}

func countUnique(items []Event) map[string]bool {
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		seen[item.ID] = true
	}
	return seen
}

func waitFor(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", message)
}
