package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/mattn/go-sqlite3"
	"github.com/multiformats/go-multihash"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func blobRecord(t *testing.T, payload string) (cid.Cid, MarshalableMap) {
	t.Helper()
	c, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	blob := atdata.Blob{Ref: atdata.CIDLink(c), MimeType: "text/plain", Size: int64(len(payload))}
	return c, MarshalableMap{"$type": "app.bsky.feed.post", "embed": map[string]any{
		"images": []any{map[string]any{"image": blob}, map[string]any{"image": blob}},
	}}
}

func uploadTestBlob(t *testing.T, s *Server, account *testAccount, payload string) {
	t.Helper()
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	c, w := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", payload, map[string]string{"Content-Type": "text/plain"})
	c.Set("repo", repo)
	if err := s.handleRepoUploadBlob(c); err != nil || w.Code != 200 {
		t.Fatalf("upload: %d %s %v", w.Code, w.Body.String(), err)
	}
}

func assertBlobRefs(t *testing.T, s *Server, did string, c cid.Cid, want int) {
	t.Helper()
	var blobs []models.Blob
	if err := s.db.Client().Where("did = ? AND cid = ?", did, c.Bytes()).Find(&blobs).Error; err != nil {
		t.Fatal(err)
	}
	if len(blobs) == 0 {
		t.Fatal("blob missing")
	}
	for _, blob := range blobs {
		if blob.RefCount != want {
			t.Fatalf("blob ref_count = %d, want %d", blob.RefCount, want)
		}
	}
}

func TestImportedBlobReferences(t *testing.T) {
	for _, order := range []string{"repo-first", "blob-first"} {
		t.Run(order, func(t *testing.T) {
			s := newTestServer(t)
			s.repoman = NewRepoMan(s)
			s.evtman = newTestEvtman(t)
			account := s.createTestAccount(t, "blob-import.pds.test")
			other := s.createTestAccount(t, "other-blob.pds.test")
			const payload = "shared imported image"
			blobCID, rec := blobRecord(t, payload)
			uploadTestBlob(t, s, other, payload)
			if order == "blob-first" {
				uploadTestBlob(t, s, account, payload)
			}
			root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/one", "app.bsky.feed.post/two"}, rec, rec)
			body := importCAR(t, []cid.Cid{root}, all)
			for range 2 {
				if code, msg := callImportRepo(t, s, account, bytes.NewReader(body)); code != 200 {
					t.Fatalf("import: %d %s", code, msg)
				}
			}
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			ctx, w := newRequestContext("GET", "/xrpc/com.atproto.repo.listMissingBlobs", "", nil)
			ctx.Set("repo", repo)
			if err := s.handleListMissingBlobs(ctx); err != nil {
				t.Fatal(err)
			}
			var missing ComAtprotoRepoListMissingBlobsResponse
			if err := json.Unmarshal(w.Body.Bytes(), &missing); err != nil {
				t.Fatal(err)
			}
			if order == "repo-first" {
				if len(missing.Blobs) != 1 || missing.Blobs[0].Cid != blobCID.String() {
					t.Fatalf("missing blobs: %+v", missing)
				}
				uploadTestBlob(t, s, account, payload)
			} else if len(missing.Blobs) != 0 {
				t.Fatalf("uploaded blob reported missing: %+v", missing)
			}
			assertBlobRefs(t, s, account.Did, blobCID, 2)
			assertBlobRefs(t, s, other.Did, blobCID, 0)
			// A repeated upload must not reset the existing references.
			uploadTestBlob(t, s, account, payload)
			assertBlobRefs(t, s, account.Did, blobCID, 2)
			var database struct{ File string }
			if err := s.db.Client().Raw("PRAGMA database_list").Scan(&database).Error; err != nil {
				t.Fatal(err)
			}
			pool, err := s.db.Client().DB()
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
			pool, err = reopened.DB()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pool.Close() })
			s.repoman = NewRepoMan(s)
			assertBlobRefs(t, s, account.Did, blobCID, 2)
			mustApply(t, s, account.Did, Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("one")})
			assertBlobRefs(t, s, account.Did, blobCID, 1)
			ctx, w = newRequestContext("GET", fmt.Sprintf("/xrpc/com.atproto.sync.getBlob?did=%s&cid=%s", account.Did, blobCID), "", nil)
			if err := s.handleSyncGetBlob(ctx); err != nil || w.Code != 200 || w.Body.String() != payload {
				t.Fatalf("public blob: %d %q %v", w.Code, w.Body.String(), err)
			}
			mustApply(t, s, account.Did, Op{Type: OpTypeUpdate, Collection: "app.bsky.feed.post", Rkey: strPtr("two"), Record: &rec})
			assertBlobRefs(t, s, account.Did, blobCID, 1)
			mustApply(t, s, account.Did, Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("two")})
			var count int64
			if err := s.db.Client().Model(&models.Blob{}).Where("did = ?", account.Did).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("unreferenced blob was not removed")
			}
			assertBlobRefs(t, s, other.Did, blobCID, 0)
		})
	}
}

func TestBlobReferenceExtraction(t *testing.T) {
	c, rec := blobRecord(t, "nested blob")
	otherCID, other := blobRecord(t, "another blob")
	rec["other"] = map[string]any(other)
	rec["ordinaryLink"] = atdata.CIDLink(cid.MustParse("bafkreigh2akiscaildc5fyk3eg6s6yxu2o2geslabjmxxmjmwkw2lxqg2e"))
	raw, err := atdata.MarshalCBOR(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := getBlobCidsFromCbor(raw)
	if err != nil || len(got) != 2 || !((got[0] == c && got[1] == otherCID) || (got[0] == otherCID && got[1] == c)) {
		t.Fatalf("blob refs = %v, %v; want one reference per record", got, err)
	}
}

func TestBlobCleanupChecksExistingRecords(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = newTestEvtman(t)
	account := s.createTestAccount(t, "old-refs.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	c, rec := blobRecord(t, "old payload")
	uploadTestBlob(t, s, account, "old payload")
	for _, key := range []string{"one", "two"} {
		mustApply(t, s, account.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &key, Record: &rec})
	}
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ?", account.Did).Update("ref_count", 1).Error; err != nil {
		t.Fatal(err)
	}
	mustApply(t, s, account.Did, Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("one")})
	assertBlobRefs(t, s, account.Did, c, 1)
}

func TestImportBlobRefsRollbackAndReplacement(t *testing.T) {
	for _, fail := range []string{"blobs", "repos", "none"} {
		t.Run(fail, func(t *testing.T) {
			s := newTestServer(t)
			s.repoman = NewRepoMan(s)
			s.evtman = newTestEvtman(t)
			account := s.createTestAccount(t, "rollback-blobs.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			oldCID, old := blobRecord(t, "old")
			newCID, replacement := blobRecord(t, "new")
			uploadTestBlob(t, s, account, "old")
			uploadTestBlob(t, s, account, "new")
			mustApply(t, s, account.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("old"), Record: &old})
			before := importState(t, s, account.Did)
			if fail != "none" {
				if err := s.db.Exec(context.Background(), "CREATE TRIGGER fail_blob_import BEFORE UPDATE ON "+fail+" BEGIN SELECT RAISE(ABORT, 'test failure'); END", nil).Error; err != nil {
					t.Fatal(err)
				}
			}
			root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/new"}, replacement)
			status, msg := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all)))
			if fail != "none" {
				if status != 500 || !reflect.DeepEqual(before, importState(t, s, account.Did)) {
					t.Fatalf("failed import changed state: %d %s", status, msg)
				}
			} else {
				if status != 200 {
					t.Fatalf("import: %d %s", status, msg)
				}
				assertBlobRefs(t, s, account.Did, oldCID, 0)
				assertBlobRefs(t, s, account.Did, newCID, 1)
				root, all, _ = importFixture(t, account.Did, nil)
				if status, _ := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all))); status != 200 {
					t.Fatalf("empty import: %d", status)
				}
				assertBlobRefs(t, s, account.Did, newCID, 0)
			}
		})
	}
}

func TestBlobReferencesWithinWriteBatch(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = newTestEvtman(t)
	account := s.createTestAccount(t, "batch-blobs.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	c, rec := blobRecord(t, "moved blob")
	uploadTestBlob(t, s, account, "moved blob")
	mustApply(t, s, account.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("old"), Record: &rec})
	mustApply(t, s, account.Did,
		Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("old")},
		Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("new"), Record: &rec},
		Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("temporary"), Record: &rec},
		Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("temporary")},
	)
	assertBlobRefs(t, s, account.Did, c, 1)
	ctx, w := newRequestContext("GET", fmt.Sprintf("/xrpc/com.atproto.sync.getBlob?did=%s&cid=%s", account.Did, c), "", nil)
	if err := s.handleSyncGetBlob(ctx); err != nil || w.Code != 200 || w.Body.String() != "moved blob" {
		t.Fatalf("public blob: %d %q %v", w.Code, w.Body.String(), err)
	}
}

func TestIndexRecordsConcurrentSQLiteWriter(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "concurrent-index.pds.test")
	c, rec := blobRecord(t, "indexed blob")
	uploadTestBlob(t, s, account, "indexed blob")
	raw, err := atdata.MarshalCBOR(rec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := s.db.Client().DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(2)
	other, err := pool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
		t.Fatal(err)
	}
	paused, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	if err := s.db.Client().Callback().Create().Before("gorm:create").Register("pause-index-insert", func(tx *gorm.DB) {
		if tx.Statement.Table == "records" {
			close(paused)
			select {
			case <-resume:
			case <-ctx.Done():
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.repoman.indexRecords(ctx, account.Did, []models.Record{{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: "one", Cid: c.String(), Value: raw}})
		done <- err
	}()
	select {
	case <-paused:
	case err := <-done:
		t.Fatalf("index did not reach insert: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, competingErr := other.ExecContext(ctx, "INSERT INTO blobs (did, ref_count) VALUES (?, 0)", "did:web:unrelated.test")
	release()
	if err := <-done; err != nil {
		t.Fatalf("index failed after concurrent writer: %v", err)
	}
	var busy sqlite3.Error
	if !errors.As(competingErr, &busy) || busy.Code != sqlite3.ErrBusy {
		t.Fatalf("index did not reserve SQLite write intent: %v", competingErr)
	}
	if _, err := other.ExecContext(ctx, "INSERT INTO blobs (did, ref_count) VALUES (?, 0)", "did:web:unrelated.test"); err != nil {
		t.Fatalf("writer failed after indexing committed: %v", err)
	}
	assertBlobRefs(t, s, account.Did, c, 1)
	var record models.Record
	if err := s.db.Client().Where("did = ? AND rkey = ?", account.Did, "one").First(&record).Error; err != nil || !bytes.Equal(record.Value, raw) {
		t.Fatalf("indexed record missing or changed: %v", err)
	}
}

func TestUploadPublicationSerializesWithImport(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "upload-import.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "concurrent imported blob"
	blobCID, rec := blobRecord(t, payload)
	root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/one", "app.bsky.feed.post/two"}, rec, rec)
	upload, uploadResponse := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", payload, nil)
	upload.Set("repo", repo)
	importRequest, importResponse := newRequestContext("POST", "/xrpc/com.atproto.repo.importRepo", "", nil)
	importRequest.Set("repo", repo)
	importRequest.Request().Body = io.NopCloser(bytes.NewReader(importCAR(t, []cid.Cid{root}, all)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	upload.SetRequest(upload.Request().WithContext(ctx))
	importRequest.SetRequest(importRequest.Request().WithContext(ctx))
	paused, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	if err := s.db.Client().Callback().Raw().Before("gorm:raw").Register("pause-upload-publication", func(tx *gorm.DB) {
		if tx.Statement.SQL.String() == "UPDATE blobs SET cid = ?, ref_count = ? WHERE id = ?" {
			close(paused)
			select {
			case <-resume:
			case <-ctx.Done():
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	uploadDone := make(chan error, 1)
	go func() { uploadDone <- s.handleRepoUploadBlob(upload) }()
	select {
	case <-paused:
	case err := <-uploadDone:
		t.Fatalf("upload did not reach publication: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	importDone := make(chan error, 1)
	go func() { importDone <- s.handleRepoImportRepo(importRequest) }()
	select {
	case err := <-importDone:
		release()
		<-uploadDone
		t.Fatalf("import finished before upload publication: %d %v", importResponse.Code, err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if err := <-uploadDone; err != nil || uploadResponse.Code != 200 {
		t.Fatalf("upload: %d %v", uploadResponse.Code, err)
	}
	if err := <-importDone; err != nil || importResponse.Code != 200 {
		t.Fatalf("import: %d %v", importResponse.Code, err)
	}
	assertBlobRefs(t, s, account.Did, blobCID, 2)
	get, response := newRequestContext("GET", fmt.Sprintf("/xrpc/com.atproto.sync.getBlob?did=%s&cid=%s", account.Did, blobCID), "", nil)
	if err := s.handleSyncGetBlob(get); err != nil || response.Code != 200 || response.Body.String() != payload {
		t.Fatalf("public blob: %d %q %v", response.Code, response.Body.String(), err)
	}
}
