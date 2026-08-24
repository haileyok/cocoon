package server

import (
	"context"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
)

func newApplyWritesServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
	return s, acct.Did
}

func postRecord(text string) MarshalableMap {
	return MarshalableMap{
		"$type":     "app.bsky.feed.post",
		"text":      text,
		"createdAt": "2024-01-01T00:00:00Z",
	}
}

// TestApplyWritesCreateThenDeleteSameRkey reproduces the atomic create+delete
// applyWrites path (create rkey A and delete rkey A in one batch).
func TestApplyWritesCreateThenDeleteSameRkey(t *testing.T) {
	ctx := context.Background()
	s, did := newApplyWritesServer(t)
	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}

	rkey := "3laaaaaaaaa2x"
	rec := postRecord("hello")
	ops := []Op{
		{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: &rec},
		{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: &rkey},
	}
	if _, err := s.repoman.applyWrites(ctx, urepo.Repo, ops, nil); err != nil {
		t.Fatalf("applyWrites create+delete (same rkey): %v", err)
	}
}

// TestApplyWritesCreateAndDeleteOther creates a new record and deletes a
// pre-existing record in one atomic batch.
func TestApplyWritesCreateAndDeleteOther(t *testing.T) {
	ctx := context.Background()
	s, did := newApplyWritesServer(t)
	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}

	// Seed an existing record B.
	rkeyB := "3lbbbbbbbbb2x"
	recB := postRecord("first")
	if _, err := s.repoman.applyWrites(ctx, urepo.Repo, []Op{
		{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkeyB, Record: &recB},
	}, nil); err != nil {
		t.Fatalf("seed record B: %v", err)
	}

	// Reload repo head/rev.
	urepo, err = s.getRepoActorByDid(ctx, did)
	if err != nil {
		t.Fatalf("reload repo: %v", err)
	}

	// Atomic: create A, delete B.
	rkeyA := "3laaaaaaaaa2x"
	recA := postRecord("second")
	if _, err := s.repoman.applyWrites(ctx, urepo.Repo, []Op{
		{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkeyA, Record: &recA},
		{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: &rkeyB},
	}, nil); err != nil {
		t.Fatalf("applyWrites create A + delete B: %v", err)
	}
}

func testBlobRecord(cids ...cid.Cid) MarshalableMap {
	record := MarshalableMap{
		"$type": "app.bsky.feed.post",
		"text":  "blob record",
	}
	if len(cids) > 0 {
		record["blob"] = atdata.Blob{Ref: atdata.CIDLink(cids[0]), MimeType: "text/plain", Size: 1}
	}
	if len(cids) > 1 {
		record["blob2"] = atdata.Blob{Ref: atdata.CIDLink(cids[1]), MimeType: "text/plain", Size: 1}
	}
	return record
}

func seedTestBlob(t *testing.T, s *Server, did string, blobCID cid.Cid, storage string) {
	t.Helper()
	blob := &models.Blob{
		Did:      did,
		Cid:      blobCID.Bytes(),
		Storage:  storage,
		RefCount: 0,
	}
	if storage == "s3" {
		blob.Bucket = "test-bucket"
		blob.ObjectKey = "blobs/" + did + "/" + blobCID.String() + "/generation"
	}
	if err := s.db.Create(t.Context(), blob, nil).Error; err != nil {
		t.Fatalf("seed blob %s: %v", blobCID, err)
	}
}

func applyTestPublicRecord(t *testing.T, s *Server, did, rkey string, opType OpType, record MarshalableMap) error {
	t.Helper()
	actor, err := s.getRepoActorByDid(t.Context(), did)
	if err != nil {
		return err
	}
	_, err = s.repoman.applyWrites(t.Context(), actor.Repo, []Op{{
		Type:       opType,
		Collection: "app.bsky.feed.post",
		Rkey:       &rkey,
		Record:     &record,
	}}, nil)
	return err
}

func loadTestBlobRows(t *testing.T, s *Server, did string, blobCID cid.Cid) []models.Blob {
	t.Helper()
	var rows []models.Blob
	if err := s.db.Client().Where("did = ? AND cid = ?", did, blobCID.Bytes()).Find(&rows).Error; err != nil {
		t.Fatalf("load blob %s: %v", blobCID, err)
	}
	return rows
}

func TestApplyWritesUpdateBlobReferencesChangedValue(t *testing.T) {
	s, did := newApplyWritesServer(t)
	blobA := testBlobCID(t, "public-update-a")
	blobB := testBlobCID(t, "public-update-b")
	seedTestBlob(t, s, did, blobA, "sqlite")
	seedTestBlob(t, s, did, blobB, "sqlite")

	const rkey = "3lblobupdate"
	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeCreate, testBlobRecord(blobA)); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeUpdate, testBlobRecord(blobB)); err != nil {
		t.Fatalf("update A to B: %v", err)
	}

	if rows := loadTestBlobRows(t, s, did, blobA); len(rows) != 0 {
		t.Fatalf("old blob rows = %+v, want cleaned up", rows)
	}
	rows := loadTestBlobRows(t, s, did, blobB)
	if len(rows) != 1 || rows[0].RefCount != 1 {
		t.Fatalf("new blob rows = %+v, want one row with ref_count 1", rows)
	}
}

func TestApplyWritesUpdateBlobReferencesRemovedValue(t *testing.T) {
	s, did := newApplyWritesServer(t)
	blobA := testBlobCID(t, "public-update-removed")
	seedTestBlob(t, s, did, blobA, "sqlite")

	const rkey = "3lblobremoved"
	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeCreate, testBlobRecord(blobA)); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeUpdate, postRecord("no blob")); err != nil {
		t.Fatalf("update A to no blob: %v", err)
	}
	if rows := loadTestBlobRows(t, s, did, blobA); len(rows) != 0 {
		t.Fatalf("removed blob rows = %+v, want cleaned up", rows)
	}
}

func TestApplyWritesUpdateBlobReferencesSameValueIsNetZero(t *testing.T) {
	s, did := newApplyWritesServer(t)
	blobA := testBlobCID(t, "public-update-same")
	seedTestBlob(t, s, did, blobA, "sqlite")

	const rkey = "3lblobsame"
	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeCreate, testBlobRecord(blobA)); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeUpdate, testBlobRecord(blobA, blobA)); err != nil {
		t.Fatalf("update A to duplicate A: %v", err)
	}
	rows := loadTestBlobRows(t, s, did, blobA)
	if len(rows) != 1 || rows[0].RefCount != 1 {
		t.Fatalf("same blob rows = %+v, want one row with ref_count 1", rows)
	}
	var deletions int64
	if err := s.db.Client().Model(&models.BlobDeletion{}).Count(&deletions).Error; err != nil {
		t.Fatal(err)
	}
	if deletions != 0 {
		t.Fatalf("same blob deletion outbox rows = %d, want 0", deletions)
	}
}

func TestApplyWritesUpdateBlobReferencesRollsBackRecordRefsAndOutbox(t *testing.T) {
	s, did := newApplyWritesServer(t)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Bucket: "test-bucket", Region: "test"}
	blobA := testBlobCID(t, "public-update-rollback-a")
	blobB := testBlobCID(t, "public-update-rollback-b")
	seedTestBlob(t, s, did, blobA, "s3")
	seedTestBlob(t, s, did, blobB, "s3")

	const rkey = "3lblobrollback"
	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeCreate, testBlobRecord(blobA)); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := s.db.Client().Exec(`CREATE TRIGGER fail_public_blob_increment BEFORE UPDATE OF ref_count ON blobs WHEN NEW.ref_count > OLD.ref_count BEGIN SELECT RAISE(ABORT, 'forced ref increment failure'); END`).Error; err != nil {
		t.Fatal(err)
	}

	if err := applyTestPublicRecord(t, s, did, rkey, OpTypeUpdate, testBlobRecord(blobB)); err == nil {
		t.Fatal("update unexpectedly succeeded")
	}

	var record models.Record
	if err := s.db.Client().Where("did = ? AND nsid = ? AND rkey = ?", did, "app.bsky.feed.post", rkey).First(&record).Error; err != nil {
		t.Fatalf("load rolled-back record: %v", err)
	}
	cids, err := getBlobCidsFromCbor(record.Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(cids) != 1 || cids[0] != blobA {
		t.Fatalf("rolled-back record blob refs = %v, want [%s]", cids, blobA)
	}
	rowsA := loadTestBlobRows(t, s, did, blobA)
	rowsB := loadTestBlobRows(t, s, did, blobB)
	if len(rowsA) != 1 || rowsA[0].RefCount != 1 {
		t.Fatalf("rolled-back A rows = %+v, want ref_count 1", rowsA)
	}
	if len(rowsB) != 1 || rowsB[0].RefCount != 0 {
		t.Fatalf("rolled-back B rows = %+v, want ref_count 0", rowsB)
	}
	var deletions int64
	if err := s.db.Client().Model(&models.BlobDeletion{}).Where("object_key = ?", rowsA[0].ObjectKey).Count(&deletions).Error; err != nil {
		t.Fatal(err)
	}
	if deletions != 0 {
		t.Fatalf("rolled-back deletion outbox rows = %d, want 0", deletions)
	}
}
