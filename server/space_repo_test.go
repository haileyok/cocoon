package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"gorm.io/gorm"
)

const (
	testSpaceRef = "at://did:example:authority/space/com.example.space/space"
	testAuthor   = "did:example:alice"
)

func testSpaceRecord(text string) map[string]any {
	return map[string]any{
		"$type":     "com.example.post",
		"text":      text,
		"createdAt": "2024-01-01T00:00:00Z",
	}
}

func TestSpaceRepoAtomicBatchAndCIDPrevSemantics(t *testing.T) {
	s := newTestServer(t)
	man := NewSpaceRepoMan(s)
	ctx := context.Background()

	created, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{
		Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "first", Record: testSpaceRecord("one"),
	}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Rev == "" || len(created.Changes) != 1 || created.Changes[0].PreviousCID != "" {
		t.Fatalf("unexpected create result: %+v", created)
	}
	if _, err := space.CIDForCBOR(mustRecordCBOR(t, testSpaceRecord("one"))); err != nil {
		t.Fatalf("CID helper: %v", err)
	}

	updated, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{
		{Type: SpaceRepoOpUpdate, Collection: "com.example.post", Rkey: "first", Record: testSpaceRecord("two")},
		{Type: SpaceRepoOpDelete, Collection: "com.example.post", Rkey: "first"},
	})
	if err != nil {
		t.Fatalf("update+delete batch: %v", err)
	}
	if updated.Rev == created.Rev || updated.Changes[0].PreviousCID == "" || updated.Changes[1].PreviousCID == "" {
		t.Fatalf("missing shared rev or previous CID: created=%+v updated=%+v", created, updated)
	}
	if updated.Changes[0].CID == updated.Changes[0].PreviousCID {
		t.Fatal("update did not produce a new CID")
	}
	if _, err := man.GetRecord(ctx, testSpaceRef, testAuthor, "com.example.post", "first"); !errors.Is(err, gormErrRecordNotFound()) {
		t.Fatalf("deleted record lookup error = %v, want not found", err)
	}
	var ops []models.SpaceRepoOp
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).Order("rev, idx").Find(&ops).Error; err != nil {
		t.Fatalf("load ops: %v", err)
	}
	if len(ops) != 3 || ops[1].Rev != ops[2].Rev || ops[1].CurrentCID == nil || ops[1].PreviousCID == nil || ops[2].CurrentCID != nil || ops[2].PreviousCID == nil {
		t.Fatalf("unexpected op CID semantics: %+v", ops)
	}
}

func TestSpaceRepoRollbackAtEachFailureStage(t *testing.T) {
	stages := []SpaceRepoFailureStage{
		SpaceRepoFailureAfterRepoCreation,
		SpaceRepoFailureAfterRecordMutation,
		SpaceRepoFailureAfterBlobMutation,
		SpaceRepoFailureAfterOplogInsertion,
		SpaceRepoFailureAfterHeadUpdate,
	}
	for _, stage := range stages {
		t.Run(string(stage), func(t *testing.T) {
			s := newTestServer(t)
			man := NewSpaceRepoMan(s)
			ctx := context.Background()
			if stage != SpaceRepoFailureAfterRepoCreation {
				if _, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "seed", Record: testSpaceRecord("seed")}}); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			restore := man.SetFailureStage(stage)
			defer restore()
			if _, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "new", Record: testSpaceRecord("new")}}); err == nil {
				t.Fatalf("stage %s did not fail", stage)
			}
			var repos []models.SpaceRepo
			if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).Find(&repos).Error; err != nil {
				t.Fatalf("load repos: %v", err)
			}
			var records []models.SpaceRecord
			if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).Find(&records).Error; err != nil {
				t.Fatalf("load records: %v", err)
			}
			var opCount int64
			s.db.Client().Model(&models.SpaceRepoOp{}).Where("space = ? AND author = ?", testSpaceRef, testAuthor).Count(&opCount)
			var writerCount int64
			s.db.Client().Model(&models.SpaceWriter{}).Where("space = ? AND author = ?", testSpaceRef, testAuthor).Count(&writerCount)
			wantRows := int64(btoi(stage != SpaceRepoFailureAfterRepoCreation))
			if len(repos) != int(wantRows) || len(records) != int(wantRows) || opCount != wantRows || writerCount != wantRows {
				t.Fatalf("transaction leaked at %s: repos=%d records=%d ops=%d writers=%d", stage, len(repos), len(records), opCount, writerCount)
			}
		})
	}
}

func TestSpaceRepoConcurrentWritesAndIdentityIsolation(t *testing.T) {
	s := newTestServer(t)
	man := NewSpaceRepoMan(s)
	ctx := context.Background()
	const writers = 12
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "r" + string(rune('a'+i)), Record: testSpaceRecord("parallel")}})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}
	rows, _, err := man.ListRecords(ctx, testSpaceRef, testAuthor, "", 100)
	if err != nil || len(rows) != writers {
		t.Fatalf("concurrent records: len=%d err=%v", len(rows), err)
	}
	if _, err := man.Apply(ctx, testSpaceRef, "did:example:bob", []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "same", Record: testSpaceRecord("bob")}}); err != nil {
		t.Fatalf("author isolation: %v", err)
	}
	otherSpace := "at://did:example:authority/space/com.example.space/other"
	if _, err := man.Apply(ctx, otherSpace, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "same", Record: testSpaceRecord("other")}}); err != nil {
		t.Fatalf("space isolation: %v", err)
	}
}

func TestSpaceRepoPutAuthorizationRejectsCreateAfterConcurrentDelete(t *testing.T) {
	s := newTestServer(t)
	man := NewSpaceRepoMan(s)
	ctx := context.Background()
	if _, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "raced", Record: testSpaceRecord("before")}}); err != nil {
		t.Fatal(err)
	}

	preflightReady := make(chan struct{})
	continuePut := make(chan struct{})
	putErr := make(chan error, 1)
	go func() {
		if _, err := man.GetRecord(ctx, testSpaceRef, testAuthor, "com.example.post", "raced"); err != nil {
			putErr <- err
			return
		}
		close(preflightReady)
		<-continuePut
		_, err := man.PutRecordWithAuthorization(ctx, testSpaceRef, testAuthor, "com.example.post", "raced", testSpaceRecord("after"), SpaceRepoAllowedActions{SpaceRepoOpUpdate: true}.Authorize)
		putErr <- err
	}()
	<-preflightReady
	if _, err := man.DeleteRecord(ctx, testSpaceRef, testAuthor, "com.example.post", "raced"); err != nil {
		t.Fatal(err)
	}
	close(continuePut)
	if err := <-putErr; err == nil {
		t.Fatal("put unexpectedly created a record with update-only authorization")
	} else {
		var scopeErr *SpaceRepoInsufficientScopeError
		if !errors.As(err, &scopeErr) || scopeErr.Action.Type != SpaceRepoOpCreate {
			t.Fatalf("put error = %v, want create insufficient scope", err)
		}
	}
	if _, err := man.GetRecord(ctx, testSpaceRef, testAuthor, "com.example.post", "raced"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("record after rejected create = %v, want not found", err)
	}
}

func TestSpaceRepoPutAuthorizationRejectsUpdateAfterConcurrentCreate(t *testing.T) {
	s := newTestServer(t)
	man := NewSpaceRepoMan(s)
	ctx := context.Background()

	preflightReady := make(chan struct{})
	continuePut := make(chan struct{})
	putErr := make(chan error, 1)
	go func() {
		if !errors.Is(func() error {
			_, err := man.GetRecord(ctx, testSpaceRef, testAuthor, "com.example.post", "raced")
			return err
		}(), gorm.ErrRecordNotFound) {
			putErr <- errors.New("preflight unexpectedly found record")
			return
		}
		close(preflightReady)
		<-continuePut
		_, err := man.PutRecordWithAuthorization(ctx, testSpaceRef, testAuthor, "com.example.post", "raced", testSpaceRecord("unauthorized-update"), SpaceRepoAllowedActions{SpaceRepoOpCreate: true}.Authorize)
		putErr <- err
	}()
	<-preflightReady
	if _, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "raced", Record: testSpaceRecord("concurrent-create")}}); err != nil {
		t.Fatal(err)
	}
	close(continuePut)
	if err := <-putErr; err == nil {
		t.Fatal("put unexpectedly updated a record with create-only authorization")
	} else {
		var scopeErr *SpaceRepoInsufficientScopeError
		if !errors.As(err, &scopeErr) || scopeErr.Action.Type != SpaceRepoOpUpdate {
			t.Fatalf("put error = %v, want update insufficient scope", err)
		}
	}
	row, err := man.GetRecord(ctx, testSpaceRef, testAuthor, "com.example.post", "raced")
	if err != nil {
		t.Fatal(err)
	}
	if string(row.CanonicalCBOR) == string(mustRecordCBOR(t, testSpaceRecord("unauthorized-update"))) {
		t.Fatal("rejected update changed the concurrently created record")
	}
}

func TestSpaceRepoNestedBlobRefsAndDelete(t *testing.T) {
	s := newTestServer(t)
	man := NewSpaceRepoMan(s)
	ctx := context.Background()
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum([]byte("uploaded"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(ctx, &models.Blob{Did: testAuthor, Cid: blobCID.Bytes()}, nil).Error; err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	blob := atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "image/png", Size: 8}
	record := testSpaceRecord("with blob")
	record["nested"] = []any{map[string]any{"inside": blob}, []any{blob}}
	if _, err := man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "blob", Record: record}}); err != nil {
		t.Fatalf("blob create: %v", err)
	}
	var refs []models.SpaceBlobRef
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).Find(&refs).Error; err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].CID != blobCID.String() {
		t.Fatalf("nested refs = %+v", refs)
	}
	if _, err := man.DeleteRecord(ctx, testSpaceRef, testAuthor, "com.example.post", "blob"); err != nil {
		t.Fatalf("blob delete: %v", err)
	}
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).Find(&refs).Error; err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("refs survived delete: %+v", refs)
	}
}

func TestSpaceRepoRejectsBlobMetadataMismatch(t *testing.T) {
	cases := []struct {
		name       string
		storedMime string
		storedSize int64
		want       string
	}{
		{"mime", "image/jpeg", 8, "MIME type"},
		{"size", "image/png", 7, "size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			man := NewSpaceRepoMan(s)
			ctx := context.Background()
			blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum([]byte(tc.name))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.db.Create(ctx, &models.Blob{
				Did: testAuthor, Cid: blobCID.Bytes(), MimeType: tc.storedMime, Size: tc.storedSize,
			}, nil).Error; err != nil {
				t.Fatal(err)
			}
			record := testSpaceRecord("metadata mismatch")
			record["blob"] = atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "image/png", Size: 8}
			_, err = man.Apply(ctx, testSpaceRef, testAuthor, []SpaceRepoOperation{{
				Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: tc.name, Record: record,
			}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("blob metadata error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSpaceRepoRejectsInvalidAndNonexistentOperations(t *testing.T) {
	s := newTestServer(t)
	man := NewSpaceRepoMan(s)
	ctx := context.Background()
	cases := []struct {
		name   string
		space  string
		author string
		op     SpaceRepoOperation
	}{
		{"bad-space", "not-a-space", testAuthor, SpaceRepoOperation{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "one", Record: testSpaceRecord("x")}},
		{"bad-author", testSpaceRef, "not-a-did", SpaceRepoOperation{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "one", Record: testSpaceRecord("x")}},
		{"bad-collection", testSpaceRef, testAuthor, SpaceRepoOperation{Type: SpaceRepoOpCreate, Collection: "bad", Rkey: "one", Record: testSpaceRecord("x")}},
		{"bad-rkey", testSpaceRef, testAuthor, SpaceRepoOperation{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "bad/key", Record: testSpaceRecord("x")}},
		{"missing-update", testSpaceRef, testAuthor, SpaceRepoOperation{Type: SpaceRepoOpUpdate, Collection: "com.example.post", Rkey: "missing", Record: testSpaceRecord("x")}},
		{"missing-delete", testSpaceRef, testAuthor, SpaceRepoOperation{Type: SpaceRepoOpDelete, Collection: "com.example.post", Rkey: "missing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := man.Apply(ctx, tc.space, tc.author, []SpaceRepoOperation{tc.op}); err == nil {
				t.Fatal("invalid operation unexpectedly succeeded")
			}
		})
	}
}

func mustRecordCBOR(t *testing.T, record map[string]any) []byte {
	t.Helper()
	data, err := atdata.MarshalCBOR(record)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}

// Kept in one helper so this test remains independent of GORM's concrete error
// value while still checking the intended not-found behavior.
func gormErrRecordNotFound() error {
	return gorm.ErrRecordNotFound
}
