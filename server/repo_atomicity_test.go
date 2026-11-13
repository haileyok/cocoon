package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRepoWriteAtomicity(t *testing.T) {
	for _, failure := range []string{"record", "head", "blob-cleanup", "block-cleanup", "commit", "event-insert", "event-commit", "cancel", "late-invalid-record", "no-broadcast", "none"} {
		t.Run(failure, func(t *testing.T) {
			s, account := endpointTestServer(t)
			s.repoman = NewRepoMan(s)
			oldCID, old := blobRecord(t, "old payload")
			newCID, replacement := blobRecord(t, "new payload")
			root, blocks, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/existing", "app.bsky.feed.post/remove"}, old, old)
			if code, msg := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, blocks))); code != 200 {
				t.Fatalf("import: %d %s", code, msg)
			}
			uploadTestBlob(t, s, account, "old payload")
			uploadTestBlob(t, s, account, "new payload")
			pool, err := s.db.Client().DB()
			if err != nil {
				t.Fatal(err)
			}
			pool.SetMaxOpenConns(1)
			persister, err := NewDbPersister(s.db.Client(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			s.evtman = events.NewEventManager(persister)
			s.evtpersister = persister
			cursor := persister.Seq
			var published []string
			broadcast := persister.Broadcast
			persister.Broadcast = func(evt *events.XRPCStreamEvent) {
				if evt.RepoCommit != nil {
					current := currentRoot(t, s, account.Did)
					if !current.Equals(cid.Cid(evt.RepoCommit.Commit)) {
						t.Error("published a commit before saving its repository head")
					}
					published = append(published, current.String())
				}
				broadcast(evt)
			}
			if failure == "no-broadcast" {
				persister.Broadcast = nil
			}
			session, err := s.createSession(context.Background(), &mustRepoActor(t, s, account.Did).Repo)
			if err != nil {
				t.Fatal(err)
			}
			head := currentRoot(t, s, account.Did)
			before := importState(t, s, account.Did)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var queries []string
			switch failure {
			case "record":
				queries = []string{"CREATE TRIGGER fail_atomic BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT, 'test failure'); END"}
			case "head":
				queries = []string{"CREATE TRIGGER fail_atomic BEFORE UPDATE ON repos BEGIN SELECT RAISE(ABORT, 'test failure'); END"}
			case "blob-cleanup":
				queries = []string{"CREATE TRIGGER fail_atomic BEFORE DELETE ON blob_parts BEGIN SELECT RAISE(ABORT, 'test failure'); END"}
			case "block-cleanup":
				queries = []string{"CREATE TRIGGER fail_atomic BEFORE DELETE ON blocks BEGIN SELECT RAISE(ABORT, 'test failure'); END"}
			case "event-insert":
				queries = []string{"CREATE TRIGGER fail_atomic BEFORE INSERT ON event_records BEGIN SELECT RAISE(ABORT, 'test failure'); END"}
			case "commit", "event-commit":
				table := "records"
				if failure == "event-commit" {
					table = "event_records"
				}
				queries = []string{
					"PRAGMA foreign_keys = ON",
					"CREATE TABLE atomic_parent (id INTEGER PRIMARY KEY)",
					"CREATE TABLE atomic_guard (id INTEGER REFERENCES atomic_parent(id) DEFERRABLE INITIALLY DEFERRED)",
					"CREATE TRIGGER fail_atomic AFTER INSERT ON " + table + " BEGIN INSERT INTO atomic_guard VALUES (1); END",
				}
			case "cancel":
				if err := s.db.Client().Callback().Raw().Before("gorm:raw").Register("cancel-atomic-head", func(tx *gorm.DB) {
					if tx.Statement.SQL.String() == "UPDATE repos SET root = ?, rev = ? WHERE did = ?" {
						cancel()
					}
				}); err != nil {
					t.Fatal(err)
				}
			}
			for _, query := range queries {
				if err := s.db.Client().Exec(query).Error; err != nil {
					t.Fatal(err)
				}
			}
			request := func(ctx context.Context, invalid bool) *httptest.ResponseRecorder {
				key := "created"
				if invalid {
					key = "invalid/key"
				}
				body := map[string]any{"swapCommit": head.String(), "writes": []any{
					map[string]any{"$type": OpTypeUpdate, "collection": "app.bsky.feed.post", "rkey": "existing", "value": replacement},
					map[string]any{"$type": OpTypeDelete, "collection": "app.bsky.feed.post", "rkey": "remove"},
					map[string]any{"$type": OpTypeCreate, "collection": "app.bsky.feed.post", "rkey": key, "value": postRecord("created")},
				}}
				w := httptest.NewRecorder()
				r := repoSwapRequest(t, account.Did, session.AccessToken, "applyWrites", body).WithContext(ctx)
				s.echo.ServeHTTP(w, r)
				return w
			}
			w := request(ctx, failure == "late-invalid-record")
			if failure != "none" && failure != "no-broadcast" {
				if w.Code < 400 {
					t.Fatalf("expected write failure: %d %s", w.Code, w.Body.String())
				}
				if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
					t.Fatal("failed write left partial repository or blob state")
				}
				if len(published) != 0 {
					t.Fatal("failed write published an event")
				}
				if _, _, ok, err := persister.EventSeqRange(context.Background()); err != nil || ok {
					t.Fatalf("failed write persisted an event: %v", err)
				}
				if err := s.db.Client().Exec("DROP TRIGGER IF EXISTS fail_atomic").Error; err != nil {
					t.Fatal(err)
				}
				if failure == "cancel" {
					if err := s.db.Client().Callback().Raw().Remove("cancel-atomic-head"); err != nil {
						t.Fatal(err)
					}
				}
				// Retry with the same head to exercise the cached tree after rollback.
				w = request(context.Background(), false)
			}
			wantPublished := 1
			if failure == "no-broadcast" {
				wantPublished = 0
			}
			if w.Code != 200 || len(published) != wantPublished {
				t.Fatalf("successful write: %d %s; events: %v", w.Code, w.Body.String(), published)
			}
			leaves := walkMstLeaves(t, s, account.Did)
			if len(leaves) != 2 || leaves["app.bsky.feed.post/remove"].Defined() || !leaves["app.bsky.feed.post/created"].Defined() {
				t.Fatalf("unexpected committed records: %v", leaves)
			}
			for key, record := range map[string]MarshalableMap{"existing": replacement, "created": postRecord("created")} {
				want, err := atdata.MarshalCBOR(record)
				if err != nil {
					t.Fatal(err)
				}
				var stored models.Record
				if err := s.db.Client().Where("did = ? AND nsid = ? AND rkey = ?", account.Did, "app.bsky.feed.post", key).First(&stored).Error; err != nil {
					t.Fatal(err)
				}
				block, err := s.getBlockstore(account.Did).Get(context.Background(), leaves["app.bsky.feed.post/"+key])
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(stored.Value, want) || !bytes.Equal(block.RawData(), want) || stored.Cid != block.Cid().String() {
					t.Fatalf("record %s differs between expected value, index and tree", key)
				}
			}
			assertBlobRefs(t, s, account.Did, newCID, 1)
			var oldCount int64
			if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, oldCID.Bytes()).Count(&oldCount).Error; err != nil || oldCount != 0 {
				t.Fatalf("old blob retained: count=%d err=%v", oldCount, err)
			}
			if blockstoreHas(t, s, account.Did, head) {
				t.Fatal("superseded commit block retained")
			}
			saved := importState(t, s, account.Did)
			var database struct{ File string }
			if err := s.db.Client().Raw("PRAGMA database_list").Scan(&database).Error; err != nil {
				t.Fatal(err)
			}
			pool, err = s.db.Client().DB()
			if err != nil {
				t.Fatal(err)
			}
			if err := pool.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := gorm.Open(sqlite.Open(database.File), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			s.db = db.NewDB(reopened)
			s.repoman = NewRepoMan(s)
			pool, err = reopened.DB()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pool.Close() })
			if !reflect.DeepEqual(saved, importState(t, s, account.Did)) {
				t.Fatal("committed state changed after reopening database")
			}
			restarted, err := NewDbPersister(reopened, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			var replayed []*events.XRPCStreamEvent
			if err := restarted.Playback(context.Background(), cursor, func(evt *events.XRPCStreamEvent) error {
				replayed = append(replayed, evt)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(replayed) != 1 || replayed[0].RepoCommit == nil {
				t.Fatalf("expected one retained commit after restart, got %v", replayed)
			}
			commit := replayed[0].RepoCommit
			if commit.Repo != account.Did || !cid.Cid(commit.Commit).Equals(currentRoot(t, s, account.Did)) || commit.Seq <= cursor || len(commit.Ops) != 3 || len(commit.Blocks) == 0 {
				t.Fatalf("retained event does not describe the committed write: %+v", commit)
			}
			if err := restarted.Playback(context.Background(), commit.Seq, func(*events.XRPCStreamEvent) error {
				t.Error("replayed an event at or before the cursor")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			blobContext, blobResponse := newRequestContext("GET", fmt.Sprintf("/xrpc/com.atproto.sync.getBlob?did=%s&cid=%s", account.Did, newCID), "", nil)
			if err := s.handleSyncGetBlob(blobContext); err != nil || blobResponse.Code != 200 || blobResponse.Body.String() != "new payload" {
				t.Fatalf("public blob after restart: %d %q %v", blobResponse.Code, blobResponse.Body.String(), err)
			}
		})
	}
}

func TestRepoWriteEventOrdering(t *testing.T) {
	s, alice := endpointTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = s.newTestEvtman(t)
	bob := s.createTestAccount(t, "bob.pds.test")
	pool, err := s.db.Client().DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	live, unsubscribe, err := s.evtman.Subscribe(ctx, "ordering", func(*events.XRPCStreamEvent) bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unsubscribe()
	var writes []func() error
	for _, account := range []*testAccount{alice, bob} {
		s.seedGenesisRepo(t, account.Did, account.SigningKey)
		session, err := s.createSession(ctx, &mustRepoActor(t, s, account.Did).Repo)
		if err != nil {
			t.Fatal(err)
		}
		req := repoSwapRequest(t, account.Did, session.AccessToken, "createRecord", map[string]any{
			"collection": "app.bsky.feed.post", "rkey": "one", "record": postRecord(account.Handle),
		}).WithContext(ctx)
		writes = append(writes, func() error {
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, req)
			if w.Code != 200 {
				return fmt.Errorf("write: %d %s", w.Code, w.Body.String())
			}
			return nil
		})
	}
	writes = append(writes, func() error {
		return s.evtpersister.Persist(ctx, &events.XRPCStreamEvent{RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Did: alice.Did, Active: true, Time: time.Now().Format(time.RFC3339Nano),
		}})
	})
	start, done := make(chan struct{}), make(chan error, len(writes))
	for _, write := range writes {
		go func() {
			<-start
			done <- write()
		}()
	}
	close(start)
	for range writes {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent writes did not finish")
		}
	}
	var replayed []*events.XRPCStreamEvent
	if err := s.evtpersister.Playback(ctx, 0, func(evt *events.XRPCStreamEvent) error {
		replayed = append(replayed, evt)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(replayed) != len(writes) {
		t.Fatalf("retained %d events for %d successful writes", len(replayed), len(writes))
	}
	var previous int64
	for _, retained := range replayed {
		select {
		case evt := <-live:
			if evt.Sequence() <= previous || evt.Sequence() != retained.Sequence() {
				t.Fatalf("live/playback sequence mismatch: previous=%d live=%d retained=%d", previous, evt.Sequence(), retained.Sequence())
			}
			previous = evt.Sequence()
			got, err := serializeEvent(evt)
			if err != nil {
				t.Fatal(err)
			}
			want, err := serializeEvent(retained)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("live/playback payload mismatch: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("missing live event")
		}
	}
}
