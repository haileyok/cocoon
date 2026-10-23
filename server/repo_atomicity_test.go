package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRepoWriteAtomicity(t *testing.T) {
	for _, failure := range []string{"record", "head", "blob-cleanup", "block-cleanup", "commit", "cancel", "late-invalid-record", "none"} {
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
			case "commit":
				queries = []string{
					"PRAGMA foreign_keys = ON",
					"CREATE TABLE atomic_parent (id INTEGER PRIMARY KEY)",
					"CREATE TABLE atomic_guard (id INTEGER REFERENCES atomic_parent(id) DEFERRABLE INITIALLY DEFERRED)",
					"CREATE TRIGGER fail_atomic AFTER INSERT ON records BEGIN INSERT INTO atomic_guard VALUES (1); END",
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
			if failure != "none" {
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
			if w.Code != 200 || len(published) != 1 {
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
			blobContext, blobResponse := newRequestContext("GET", fmt.Sprintf("/xrpc/com.atproto.sync.getBlob?did=%s&cid=%s", account.Did, newCID), "", nil)
			if err := s.handleSyncGetBlob(blobContext); err != nil || blobResponse.Code != 200 || blobResponse.Body.String() != "new payload" {
				t.Fatalf("public blob after restart: %d %q %v", blobResponse.Code, blobResponse.Body.String(), err)
			}
		})
	}
}
