package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"gorm.io/gorm"
)

type fakeBlobDeletionS3 struct {
	mu         sync.Mutex
	calls      []string
	failures   int
	alwaysFail bool
}

func (f *fakeBlobDeletionS3) DeleteObject(input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, aws.StringValue(input.Bucket)+"/"+aws.StringValue(input.Key))
	if f.alwaysFail || f.failures > 0 {
		if f.failures > 0 {
			f.failures--
		}
		return nil, errors.New("provider endpoint includes sensitive details")
	}
	return &s3.DeleteObjectOutput{}, nil
}

func (f *fakeBlobDeletionS3) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func testBlobCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	parsed, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestAccountDeletionEnqueuesOnlyS3Blobs(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.s3Config = &S3Config{Bucket: "blob-bucket", Region: "test-region"}
	account := s.createTestAccount(t, "s3-delete.pds.test")
	s3CID := testBlobCID(t, "s3-delete")
	localCID := testBlobCID(t, "sqlite-delete")
	s3Blob := &models.Blob{Did: account.Did, Cid: s3CID.Bytes(), Storage: "s3"}
	localBlob := &models.Blob{Did: account.Did, Cid: localCID.Bytes(), Storage: "sqlite"}
	if err := s.db.Create(context.Background(), s3Blob, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(context.Background(), localBlob, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(context.Background(), &models.BlobPart{BlobID: localBlob.ID, Idx: 0, Data: []byte("local")}, nil).Error; err != nil {
		t.Fatal(err)
	}
	const deleteCode = "delete-s3-blob"
	if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Updates(map[string]any{
		"account_delete_code":            deleteCode,
		"account_delete_code_expires_at": time.Now().UTC().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.deleteAccount", `{"did":"`+account.Did+`","password":"`+account.Password+`","token":"`+deleteCode+`"}`, nil)
	if err := s.handleServerDeleteAccount(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	var deletion models.BlobDeletion
	if err := s.db.Client().Where("object_key = ?", "blobs/"+account.Did+"/"+s3CID.String()).First(&deletion).Error; err != nil {
		t.Fatalf("load S3 deletion outbox: %v", err)
	}
	if deletion.Bucket != "blob-bucket" || deletion.Status != BlobDeletionPending {
		t.Fatalf("unexpected deletion row: %+v", deletion)
	}
	var localDeletionCount int64
	if err := s.db.Client().Model(&models.BlobDeletion{}).Where("object_key LIKE ?", "%sqlite-delete%").Count(&localDeletionCount).Error; err != nil {
		t.Fatal(err)
	}
	if localDeletionCount != 0 {
		t.Fatalf("local blob unexpectedly queued: %d", localDeletionCount)
	}
}

func TestBlobDeletionWorkerCommitCouplingAndRollback(t *testing.T) {
	s := newTestServer(t)
	fake := &fakeBlobDeletionS3{}
	worker := NewBlobDeletionWorkerForDB(s.db, fake, func() time.Time { return time.Unix(100, 0).UTC() })
	worker.SetOptions(BlobDeletionWorkerOptions{BaseDelay: time.Second, MaxDelay: time.Minute, MaxAttempts: 3, BatchSize: 10})
	ctx := context.Background()
	row := models.BlobDeletion{IdempotencyKey: "commit-key", Bucket: "bucket", ObjectKey: "blobs/did/cid", Status: BlobDeletionPending}
	tx := s.db.Begin(ctx)
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	if err := db.NewDB(tx).Create(ctx, &row, nil).Error; err != nil {
		t.Fatal(err)
	}
	if n, err := worker.RunOnce(ctx, 1); err != nil || n != 0 {
		t.Fatalf("uncommitted worker run n=%d err=%v", n, err)
	}
	if fake.callCount() != 0 {
		t.Fatal("S3 deletion happened before transaction commit")
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if n, err := worker.RunOnce(ctx, 1); err != nil || n != 1 {
		t.Fatalf("committed worker run n=%d err=%v", n, err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("S3 calls=%d, want 1", fake.callCount())
	}

	rolledBack := models.BlobDeletion{IdempotencyKey: "rollback-key", Bucket: "bucket", ObjectKey: "blobs/did/rollback", Status: BlobDeletionPending}
	tx = s.db.Begin(ctx)
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	if err := db.NewDB(tx).Create(ctx, &rolledBack, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback().Error; err != nil {
		t.Fatal(err)
	}
	if n, err := worker.RunOnce(ctx, 1); err != nil || n != 0 {
		t.Fatalf("rolled-back worker run n=%d err=%v", n, err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("rollback caused S3 call; calls=%d", fake.callCount())
	}
}

func TestBlobDeletionWorkerRetryRestartAndIdempotency(t *testing.T) {
	s := newTestServer(t)
	now := time.Unix(200, 0).UTC()
	row := &models.BlobDeletion{IdempotencyKey: "retry-key", Bucket: "bucket", ObjectKey: "blobs/did/retry", Status: BlobDeletionPending}
	if err := s.db.Create(context.Background(), row, nil).Error; err != nil {
		t.Fatal(err)
	}
	fake := &fakeBlobDeletionS3{failures: 1}
	worker := NewBlobDeletionWorkerForDB(s.db, fake, func() time.Time { return now })
	worker.SetOptions(BlobDeletionWorkerOptions{BaseDelay: time.Second, MaxDelay: 2 * time.Second, MaxAttempts: 3, BatchSize: 10})
	if n, err := worker.RunOnce(context.Background(), 1); err != nil || n != 1 {
		t.Fatalf("retry run n=%d err=%v", n, err)
	}
	var afterFailure models.BlobDeletion
	if err := s.db.Client().Where("id = ?", row.ID).First(&afterFailure).Error; err != nil {
		t.Fatal(err)
	}
	if afterFailure.Status != BlobDeletionRetry || afterFailure.AttemptCount != 1 || afterFailure.NextAttemptAt == nil || afterFailure.LastError != blobDeletionFailureMessage {
		t.Fatalf("unexpected retry row: %+v", afterFailure)
	}

	now = now.Add(time.Second)
	// A new worker instance proves retry state is durable across restart.
	worker = NewBlobDeletionWorkerForDB(s.db, fake, func() time.Time { return now })
	worker.SetOptions(BlobDeletionWorkerOptions{BaseDelay: time.Second, MaxDelay: 2 * time.Second, MaxAttempts: 3, BatchSize: 10})
	if n, err := worker.RunOnce(context.Background(), 1); err != nil || n != 1 {
		t.Fatalf("restart run n=%d err=%v", n, err)
	}
	var afterSuccess models.BlobDeletion
	if err := s.db.Client().Where("id = ?", row.ID).First(&afterSuccess).Error; err != nil {
		t.Fatal(err)
	}
	if afterSuccess.Status != BlobDeletionDeleted || afterSuccess.NextAttemptAt != nil || afterSuccess.DeletedAt == nil || fake.callCount() != 2 {
		t.Fatalf("unexpected success row/calls: %+v/%d", afterSuccess, fake.callCount())
	}
	if n, err := worker.RunOnce(context.Background(), 1); err != nil || n != 0 {
		t.Fatalf("repeat run n=%d err=%v", n, err)
	}
	if fake.callCount() != 2 {
		t.Fatal("terminal deletion row was retried")
	}
}

func TestBlobDeletionWorkerTreatsMissingObjectAsSuccess(t *testing.T) {
	s := newTestServer(t)
	row := &models.BlobDeletion{IdempotencyKey: "missing-key", Bucket: "bucket", ObjectKey: "blobs/did/missing", Status: BlobDeletionPending}
	if err := s.db.Create(context.Background(), row, nil).Error; err != nil {
		t.Fatal(err)
	}
	fake := missingObjectBlobDeletionS3{}
	worker := NewBlobDeletionWorkerForDB(s.db, fake, time.Now)
	if _, err := worker.RunOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	var got models.BlobDeletion
	if err := s.db.Client().First(&got, "id = ?", row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != BlobDeletionDeleted {
		t.Fatalf("missing object status=%q", got.Status)
	}
}

type missingObjectBlobDeletionS3 struct{}

func (missingObjectBlobDeletionS3) DeleteObject(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return nil, awserr.NewRequestFailure(awserr.New("NotFound", "missing", nil), http.StatusNotFound, "")
}

func TestNotificationExpiryRunsBeforeReplayCleanup(t *testing.T) {
	s := newTestServer(t)
	now := time.Unix(300, 0).UTC()
	if err := s.db.Create(context.Background(), &models.SpaceNotifyRegistration{Space: "at://did:web:owner.test/space/com.example.test/one", Service: "did:web:service.test#space", ExpiresAt: now.Add(-time.Second)}, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Migrator().DropTable(&models.SpaceReplayJTI{}); err != nil {
		t.Fatal(err)
	}
	worker := NewSpaceNotificationWorkerForDB(s.db, nil, func() time.Time { return now }, nil)
	if _, err := worker.RunOnce(context.Background(), 1); err == nil {
		t.Fatal("expected replay cleanup failure")
	}
	var count int64
	if err := s.db.Client().Model(&models.SpaceNotifyRegistration{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired registration remained after replay cleanup failure: %d", count)
	}
}

func TestBlobGenerationDeletionIsolationBeforeAndAfterWorker(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	did := "did:plc:reincarnated"
	cidValue := testBlobCID(t, "same-cid")
	oldKey, err := newS3BlobObjectKey(did, cidValue.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := newS3BlobObjectKey(did, cidValue.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if oldKey == newKey {
		t.Fatal("same DID/CID generations reused an S3 key")
	}
	for _, blob := range []models.Blob{
		{Did: did, Cid: cidValue.Bytes(), Storage: "s3", Bucket: "bucket", ObjectKey: oldKey},
		{Did: did, Cid: cidValue.Bytes(), Storage: "s3", Bucket: "bucket", ObjectKey: newKey},
	} {
		if err := s.db.Create(ctx, &blob, nil).Error; err != nil {
			t.Fatal(err)
		}
	}
	oldDeletion := &models.BlobDeletion{IdempotencyKey: oldKey, Bucket: "bucket", ObjectKey: oldKey, Status: BlobDeletionPending}
	if err := s.db.Create(ctx, oldDeletion, nil).Error; err != nil {
		t.Fatal(err)
	}
	fake := &fakeBlobDeletionS3{}
	worker := NewBlobDeletionWorkerForDB(s.db, fake, time.Now)
	if _, err := worker.RunOnce(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if fake.callCount() != 1 || fake.calls[0] != "bucket/"+oldKey {
		t.Fatalf("old generation deletion calls = %v", fake.calls)
	}
	var newBlob models.Blob
	if err := s.db.Client().Where("object_key = ?", newKey).First(&newBlob).Error; err != nil {
		t.Fatalf("new generation disappeared: %v", err)
	}
	newDeletion := &models.BlobDeletion{IdempotencyKey: newKey, Bucket: "bucket", ObjectKey: newKey, Status: BlobDeletionPending}
	if err := s.db.Create(ctx, newDeletion, nil).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if fake.callCount() != 2 || fake.calls[1] != "bucket/"+newKey {
		t.Fatalf("generation deletion calls = %v", fake.calls)
	}
}

func TestBlobDeletionWorkerFactoryFailureLeavesAttemptsUntouched(t *testing.T) {
	s := newTestServer(t)
	row := &models.BlobDeletion{IdempotencyKey: "factory-key", Bucket: "bucket", ObjectKey: "object", Status: BlobDeletionPending}
	if err := s.db.Create(context.Background(), row, nil).Error; err != nil {
		t.Fatal(err)
	}
	worker := NewBlobDeletionWorkerForDB(s.db, nil, time.Now)
	worker.clientFactory = func() (BlobDeletionS3Client, error) { return nil, errors.New("temporary client configuration") }
	if n, err := worker.RunOnce(context.Background(), 1); n != 0 || err == nil {
		t.Fatalf("factory failure n=%d err=%v", n, err)
	}
	var got models.BlobDeletion
	if err := s.db.Client().First(&got, "id = ?", row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.AttemptCount != 0 || got.Status != BlobDeletionPending || got.NextAttemptAt != nil {
		t.Fatalf("factory failure mutated row: %+v", got)
	}
}

func TestBlobDeletionWorkerRetriesPastMaxAttemptsAndRecovers(t *testing.T) {
	s := newTestServer(t)
	now := time.Unix(500, 0).UTC()
	row := &models.BlobDeletion{IdempotencyKey: "long-outage", Bucket: "bucket", ObjectKey: "object", Status: BlobDeletionPending}
	if err := s.db.Create(context.Background(), row, nil).Error; err != nil {
		t.Fatal(err)
	}
	fake := &fakeBlobDeletionS3{alwaysFail: true}
	worker := NewBlobDeletionWorkerForDB(s.db, fake, func() time.Time { return now })
	worker.SetOptions(BlobDeletionWorkerOptions{BaseDelay: time.Second, MaxDelay: 2 * time.Second, MaxAttempts: 1, BatchSize: 1})
	for i := 0; i < 4; i++ {
		if _, err := worker.RunOnce(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
	}
	var afterOutage models.BlobDeletion
	if err := s.db.Client().First(&afterOutage, "id = ?", row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if afterOutage.Status != BlobDeletionRetry || afterOutage.AttemptCount != 4 {
		t.Fatalf("outage became terminal: %+v", afterOutage)
	}
	fake.alwaysFail = false
	if _, err := worker.RunOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().First(&afterOutage, "id = ?", row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if afterOutage.Status != BlobDeletionDeleted {
		t.Fatalf("recovered outage status = %q", afterOutage.Status)
	}
}

func TestAccountDeletionMissingS3BucketRollsBack(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.s3Config = &S3Config{Region: "test-region"}
	account := s.createTestAccount(t, "missing-bucket.pds.test")
	blobCID := testBlobCID(t, "missing-bucket")
	if err := s.db.Create(context.Background(), &models.Blob{Did: account.Did, Cid: blobCID.Bytes(), Storage: "s3"}, nil).Error; err != nil {
		t.Fatal(err)
	}
	code := "missing-bucket-delete"
	if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Updates(map[string]any{"account_delete_code": code, "account_delete_code_expires_at": time.Now().UTC().Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.deleteAccount", `{"did":"`+account.Did+`","password":"`+account.Password+`","token":"`+code+`"}`, nil)
	_ = s.handleServerDeleteAccount(e)
	if rec.Code < 400 {
		t.Fatalf("missing bucket deletion status = %d", rec.Code)
	}
	if _, err := s.getRepoActorByDid(context.Background(), account.Did); err != nil {
		t.Fatalf("account deletion was not rolled back: %v", err)
	}
	var count int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ?", account.Did).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("blob count after rollback = %d", count)
	}
}

func TestLegacyBlobTargetCompatibility(t *testing.T) {
	cidValue := testBlobCID(t, "legacy")
	bucket, objectKey, err := blobS3Target(models.Blob{Did: "did:plc:legacy", Cid: cidValue.Bytes(), Storage: "s3"}, &S3Config{Bucket: "legacy-bucket"})
	if err != nil {
		t.Fatal(err)
	}
	if bucket != "legacy-bucket" || objectKey != "blobs/did:plc:legacy/"+cidValue.String() {
		t.Fatalf("legacy target = %q/%q", bucket, objectKey)
	}
}

func TestBlobDeletionWorkerPrunesWithoutActiveWorkAndAfterRestart(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	now := time.Unix(650, 0).UTC()
	deletedAt := now.Add(-time.Hour)
	row := &models.BlobDeletion{IdempotencyKey: "prune-only", Bucket: "bucket", ObjectKey: "old", Status: BlobDeletionDeleted, DeletedAt: &deletedAt}
	if err := s.db.Create(ctx, row, nil).Error; err != nil {
		t.Fatal(err)
	}
	worker := NewBlobDeletionWorkerForDB(s.db, nil, func() time.Time { return now })
	worker.SetOptions(BlobDeletionWorkerOptions{DeletedRetention: time.Hour, BatchSize: 1})
	if n, err := worker.RunOnce(ctx, 1); err != nil || n != 0 {
		t.Fatalf("prune-only run n=%d err=%v", n, err)
	}
	var got models.BlobDeletion
	if err := s.db.Client().Where("id = ?", row.ID).First(&got).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("pruned row lookup=%v, want deleted", err)
	}

	boundary := now.Add(-time.Hour)
	hidden := &models.BlobDeletion{IdempotencyKey: "prune-hidden", Bucket: "bucket", ObjectKey: "hidden", Status: BlobDeletionDeleted, DeletedAt: &boundary}
	tx := s.db.Begin(ctx)
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	if err := db.NewDB(tx).Create(ctx, hidden, nil).Error; err != nil {
		t.Fatal(err)
	}
	if n, err := worker.RunOnce(ctx, 1); err != nil || n != 0 {
		t.Fatalf("uncommitted prune run n=%d err=%v", n, err)
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}
	worker = NewBlobDeletionWorkerForDB(s.db, nil, func() time.Time { return now })
	worker.SetOptions(BlobDeletionWorkerOptions{DeletedRetention: time.Hour, BatchSize: 1})
	if n, err := worker.RunOnce(ctx, 1); err != nil || n != 0 {
		t.Fatalf("restart prune run n=%d err=%v", n, err)
	}
	if err := s.db.Client().Where("id = ?", hidden.ID).First(&got).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("committed hidden row lookup=%v, want deleted", err)
	}
}

func TestBlobDeletionPrunesOnlyOldDeletedRows(t *testing.T) {
	s := newTestServer(t)
	now := time.Unix(700, 0).UTC()
	oldDeletedAt := now.Add(-2 * time.Hour)
	recentDeletedAt := now.Add(-time.Hour / 2)
	rows := []models.BlobDeletion{
		{IdempotencyKey: "old-deleted", Bucket: "b", ObjectKey: "old", Status: BlobDeletionDeleted, DeletedAt: &oldDeletedAt},
		{IdempotencyKey: "recent-deleted", Bucket: "b", ObjectKey: "recent", Status: BlobDeletionDeleted, DeletedAt: &recentDeletedAt},
		{IdempotencyKey: "pending-old", Bucket: "b", ObjectKey: "pending", Status: BlobDeletionPending, DeletedAt: &oldDeletedAt},
		{IdempotencyKey: "retry-old", Bucket: "b", ObjectKey: "retry", Status: BlobDeletionRetry, DeletedAt: &oldDeletedAt},
	}
	for i := range rows {
		if err := s.db.Create(context.Background(), &rows[i], nil).Error; err != nil {
			t.Fatal(err)
		}
	}
	worker := NewBlobDeletionWorkerForDB(s.db, &fakeBlobDeletionS3{}, func() time.Time { return now })
	worker.SetOptions(BlobDeletionWorkerOptions{DeletedRetention: time.Hour, BatchSize: 1})
	if n, err := worker.PruneDeleted(context.Background()); err != nil || n != 1 {
		t.Fatalf("pruned=%d err=%v", n, err)
	}
	var remaining []models.BlobDeletion
	if err := s.db.Client().Order("id").Find(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 3 {
		t.Fatalf("remaining rows=%d, want 3", len(remaining))
	}
	for _, row := range remaining {
		if row.IdempotencyKey == "old-deleted" {
			t.Fatal("old deleted row was not pruned")
		}
	}
}

func TestMarkSimpleSpaceDeletedExcludesExpiredRegistrations(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	now := time.Unix(900, 0).UTC()
	spaceURI := "at://did:web:owner.test/space/com.example.test/expired"
	for _, registration := range []models.SpaceNotifyRegistration{
		{Space: spaceURI, Service: "did:web:active.test#space", ExpiresAt: now.Add(time.Hour)},
		{Space: spaceURI, Service: "did:web:expired.test#space", ExpiresAt: now.Add(-time.Hour)},
	} {
		if err := s.db.Create(ctx, &registration, nil).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := markSimpleSpaceDeleted(s.db, ctx, spaceURI, "did:web:owner.test", now, nil); err != nil {
		t.Fatal(err)
	}
	var deliveries []models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ?", spaceURI).Find(&deliveries).Error; err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].Service != "did:web:active.test#space" {
		t.Fatalf("deletion deliveries = %+v", deliveries)
	}
}
