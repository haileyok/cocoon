package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"github.com/multiformats/go-multihash"
)

func TestSpaceBlobReferenceAuthorizationAndOAuthBlobScope(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	bob := s.createTestAccount(t, "bob.pds.test")
	spaceURI := testSpaceURI(t, alice.Did)
	blobBytes := []byte("not-public-space-data")
	blobCID, err := space.CIDForCBOR(blobBytes)
	if err != nil {
		t.Fatalf("blob CID: %v", err)
	}
	blob := models.Blob{Did: alice.Did, Cid: blobCID.Bytes(), MimeType: "text/plain", Size: int64(len(blobBytes)), Storage: "sqlite"}
	if err := s.db.Create(t.Context(), &blob, nil).Error; err != nil {
		t.Fatalf("create blob: %v", err)
	}
	if err := s.db.Create(t.Context(), &models.BlobPart{BlobID: blob.ID, Idx: 0, Data: blobBytes}, nil).Error; err != nil {
		t.Fatalf("create blob part: %v", err)
	}
	value := map[string]any{"image": atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "text/plain", Size: int64(len(blobBytes))}}
	applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "one", value)
	base := "/xrpc/com.atproto.space.getBlob?space=" + spaceURI + "&did=" + alice.Did + "&cid=" + blobCID.String()
	e, rec := newRequestContext(http.MethodGet, base, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetBlob(e); err != nil {
		t.Fatalf("credential getBlob: %v", err)
	}
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), blobBytes) {
		t.Fatalf("credential blob response = %d %q", rec.Code, rec.Body.Bytes())
	}
	if got := rec.Header().Get(echo.HeaderContentType); got != "text/plain" {
		t.Fatalf("credential blob content type = %q, want text/plain", got)
	}

	e, rec = newRequestContext(http.MethodGet, base, "", nil)
	setSpaceOAuth(e, alice.Did, spaceURI, "read_self")
	if err := s.handleSpaceGetBlob(e); err != nil {
		t.Fatalf("OAuth without blob scope: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("OAuth without blob scope status = %d, want 403", rec.Code)
	}

	e, rec = newRequestContext(http.MethodGet, base, "", nil)
	setSpaceOAuth(e, alice.Did, spaceURI, "read_self", "blob:*/*")
	if err := s.handleSpaceGetBlob(e); err != nil {
		t.Fatalf("OAuth blob scope: %v", err)
	}
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), blobBytes) {
		t.Fatalf("OAuth blob response = %d %q", rec.Code, rec.Body.Bytes())
	}

	otherSpace := testSpaceURI(t, bob.Did)
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getBlob?space="+otherSpace+"&did="+alice.Did+"&cid="+blobCID.String(), "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetBlob(e); err != nil {
		t.Fatalf("mismatched credential blob: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched credential blob status = %d, want 403", rec.Code)
	}

	// A permissioned reference must not make the upload visible through the
	// unauthenticated public sync API.
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.listBlobs?did="+alice.Did, "", nil)
	if err := s.handleSyncListBlobs(e); err != nil {
		t.Fatalf("public listBlobs: %v", err)
	}
	var publicList ComAtprotoSyncListBlobsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &publicList); err != nil {
		t.Fatalf("decode public listBlobs: %v", err)
	}
	if len(publicList.Cids) != 0 {
		t.Fatalf("permissioned blob leaked through public listBlobs: %v", publicList.Cids)
	}

	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.getBlob?did="+alice.Did+"&cid="+blobCID.String(), "", nil)
	if err := s.handleSyncGetBlob(e); err != nil {
		t.Fatalf("public getBlob: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("permissioned blob public get status = %d, want 400", rec.Code)
	}
}

func TestOAuthUploadBlobRequiresMatchingBlobScope(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	alice := s.createTestAccount(t, "upload-scope.pds.test")
	actor, err := s.getRepoActorByDid(t.Context(), alice.Did)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("space upload")

	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "image/png"})
	e.Set("repo", actor)
	SetPrincipal(e, &OAuthPrincipal{Subject: alice.Did, Repo: actor, Scopes: []string{"space:*?authority=*&action=read"}})
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("upload without blob scope = %d %s", rec.Code, rec.Body.String())
	}

	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "image/png"})
	e.Set("repo", actor)
	SetPrincipal(e, &OAuthPrincipal{Subject: alice.Did, Repo: actor, Scopes: []string{"blob:image/*"}})
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("upload with blob scope = %d %s", rec.Code, rec.Body.String())
	}
	var uploaded models.Blob
	if err := s.db.Client().Where("did = ?", alice.Did).Order("id DESC").First(&uploaded).Error; err != nil {
		t.Fatal(err)
	}
	if uploaded.MimeType != "image/png" || uploaded.Size != int64(len(payload)) {
		t.Fatalf("uploaded blob metadata = %q/%d, want image/png/%d", uploaded.MimeType, uploaded.Size, len(payload))
	}

	// A duplicate upload must return the immutable persisted metadata, not the
	// MIME type supplied by a later request for the same CID.
	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "text/plain"})
	e.Set("repo", actor)
	SetPrincipal(e, &OAuthPrincipal{Subject: alice.Did, Repo: actor, Scopes: []string{"blob:text/*"}})
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	var duplicate ComAtprotoRepoUploadBlobResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &duplicate); err != nil {
		t.Fatal(err)
	}
	if duplicate.Blob.MimeType != "image/png" || duplicate.Blob.Size != len(payload) {
		t.Fatalf("duplicate upload metadata = %q/%d, want image/png/%d", duplicate.Blob.MimeType, duplicate.Blob.Size, len(payload))
	}
}

type uploadLifecycleS3 struct {
	putStarted  chan struct{}
	allowPut    chan struct{}
	putOnce     sync.Once
	putErr      error
	deleteErr   error
	cancelOnPut func()

	mu          sync.Mutex
	putCalls    int
	putBucket   string
	putKey      string
	object      []byte
	deleteCalls []string
}

func (f *uploadLifecycleS3) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	if f.putStarted != nil {
		f.putOnce.Do(func() { close(f.putStarted) })
	}
	if f.allowPut != nil {
		<-f.allowPut
	}
	data, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.putCalls++
	f.putBucket, f.putKey, f.object = aws.StringValue(input.Bucket), aws.StringValue(input.Key), append([]byte(nil), data...)
	f.mu.Unlock()
	if f.cancelOnPut != nil {
		f.cancelOnPut()
	}
	if f.putErr != nil {
		return nil, f.putErr
	}
	return &s3.PutObjectOutput{}, nil
}

func (f *uploadLifecycleS3) GetObject(input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	data := append([]byte(nil), f.object...)
	f.mu.Unlock()
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func (f *uploadLifecycleS3) DeleteObject(input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	f.deleteCalls = append(f.deleteCalls, aws.StringValue(input.Key))
	f.mu.Unlock()
	return &s3.DeleteObjectOutput{}, f.deleteErr
}

func TestS3UploadPublishesMetadataOnlyAfterObjectDurability(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Region: "test", Bucket: "blob-bucket"}
	fake := &uploadLifecycleS3{putStarted: make(chan struct{}), allowPut: make(chan struct{})}
	s.s3Client = fake
	account := s.createTestAccount(t, "s3-upload-race.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("blocked until S3 is durable")
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "text/plain"})
	e.Set("repo", actor)
	uploadDone := make(chan error, 1)
	go func() { uploadDone <- s.handleRepoUploadBlob(e) }()
	<-fake.putStarted

	var blobCount int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).Count(&blobCount).Error; err != nil {
		t.Fatal(err)
	}
	if blobCount != 0 {
		t.Fatalf("Blob metadata became visible while PutObject was blocked: %d", blobCount)
	}

	publicRecord := MarshalableMap{
		"$type": "app.bsky.feed.post",
		"text":  "public reference",
		"blob":  atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "text/plain", Size: int64(len(payload))},
	}
	rkey := "3lblockedpublic"
	if _, err := s.repoman.applyWrites(t.Context(), actor.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: &publicRecord}}, nil); err == nil {
		t.Fatal("public record unexpectedly committed while upload was blocked")
	}
	var publicRows int64
	if err := s.db.Client().Model(&models.Record{}).Where("did = ? AND rkey = ?", account.Did, rkey).Count(&publicRows).Error; err != nil {
		t.Fatal(err)
	}
	if publicRows != 0 {
		t.Fatalf("public record remained after missing-blob rejection: %d", publicRows)
	}

	spaceMan := NewSpaceRepoMan(s)
	spaceRecord := map[string]any{
		"$type": "com.example.post",
		"text":  "Space reference",
		"blob":  atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "text/plain", Size: int64(len(payload))},
	}
	if _, err := spaceMan.Apply(t.Context(), testSpaceRef, account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "blockedspace", Record: spaceRecord}}); err == nil {
		t.Fatal("Space record unexpectedly committed while upload was blocked")
	}
	var spaceRows int64
	if err := s.db.Client().Model(&models.SpaceRecord{}).Where("author = ? AND rkey = ?", account.Did, "blockedspace").Count(&spaceRows).Error; err != nil {
		t.Fatal(err)
	}
	if spaceRows != 0 {
		t.Fatalf("Space record remained after missing-blob rejection: %d", spaceRows)
	}

	close(fake.allowPut)
	if err := <-uploadDone; err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("upload response = %d %s", rec.Code, rec.Body.String())
	}
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).Count(&blobCount).Error; err != nil {
		t.Fatal(err)
	}
	if blobCount != 1 {
		t.Fatalf("published Blob rows = %d, want 1", blobCount)
	}
}

func TestBlobReadersSkipIncompleteOlderSQLiteGeneration(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "verified-generation-reads.pds.test")
	payload := []byte("complete generation content")
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
	if err != nil {
		t.Fatal(err)
	}

	old := models.Blob{Did: account.Did, Cid: blobCID.Bytes(), RefCount: 1, Storage: "sqlite"}
	if err := s.db.Create(t.Context(), &old, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(t.Context(), &models.BlobPart{BlobID: old.ID, Idx: 0, Data: []byte("partial")}, nil).Error; err != nil {
		t.Fatal(err)
	}
	complete := models.Blob{Did: account.Did, Cid: blobCID.Bytes(), RefCount: 1, Storage: "sqlite"}
	if err := s.db.Create(t.Context(), &complete, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(t.Context(), &models.BlobPart{BlobID: complete.ID, Idx: 0, Data: payload}, nil).Error; err != nil {
		t.Fatal(err)
	}

	publicURL := "/xrpc/com.atproto.sync.getBlob?did=" + account.Did + "&cid=" + blobCID.String()
	e, rec := newRequestContext(http.MethodGet, publicURL, "", nil)
	if err := s.handleSyncGetBlob(e); err != nil {
		t.Fatalf("public getBlob: %v", err)
	}
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatalf("public verified blob response = %d %q", rec.Code, rec.Body.Bytes())
	}

	spaceURI := testSpaceURI(t, account.Did)
	applySpaceRecord(t, s, spaceURI, account.Did, "com.example.record", "verified", map[string]any{
		"blob": atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "text/plain", Size: int64(len(payload))},
	})
	permissionedURL := "/xrpc/com.atproto.space.getBlob?space=" + spaceURI + "&did=" + account.Did + "&cid=" + blobCID.String()
	e, rec = newRequestContext(http.MethodGet, permissionedURL, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetBlob(e); err != nil {
		t.Fatalf("permissioned getBlob: %v", err)
	}
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatalf("permissioned verified blob response = %d %q", rec.Code, rec.Body.Bytes())
	}
}

func TestFindReadyBlobCleansUnreferencedInvalidSQLiteGeneration(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "invalid-generation-cleanup.pds.test")
	payload := []byte("expected content")
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	blob := models.Blob{Did: account.Did, Cid: blobCID.Bytes(), Storage: "sqlite"}
	if err := s.db.Create(t.Context(), &blob, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(t.Context(), &models.BlobPart{BlobID: blob.ID, Idx: 1, Data: []byte("orphan")}, nil).Error; err != nil {
		t.Fatal(err)
	}
	ready, err := s.findReadyBlob(t.Context(), account.Did, blobCID.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if ready != nil {
		t.Fatalf("invalid generation reported ready: %+v", ready)
	}
	var blobs, parts int64
	if err := s.db.Client().Model(&models.Blob{}).Where("id = ?", blob.ID).Count(&blobs).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Model(&models.BlobPart{}).Where("blob_id = ?", blob.ID).Count(&parts).Error; err != nil {
		t.Fatal(err)
	}
	if blobs != 0 || parts != 0 {
		t.Fatalf("invalid generation cleanup = blobs %d parts %d", blobs, parts)
	}
}

type differentCIDBlockingS3 struct {
	started chan struct{}
	release chan struct{}

	mu    sync.Mutex
	calls int
}

func (f *differentCIDBlockingS3) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()
	if call == 1 {
		close(f.started)
		<-f.release
	}
	if _, err := io.ReadAll(input.Body); err != nil {
		return nil, err
	}
	return &s3.PutObjectOutput{}, nil
}

func (f *differentCIDBlockingS3) GetObject(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(nil))}, nil
}

func (f *differentCIDBlockingS3) DeleteObject(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return &s3.DeleteObjectOutput{}, nil
}

func TestS3UploadsDifferentCIDsDoNotShareUploadLock(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Region: "test", Bucket: "blob-bucket"}
	fake := &differentCIDBlockingS3{started: make(chan struct{}), release: make(chan struct{})}
	s.s3Client = fake
	account := s.createTestAccount(t, "s3-different-cid-lock.pds.test")
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	first, second := []byte("first blocked CID"), []byte("second unblocked CID")
	e1, _ := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(first), map[string]string{"content-type": "text/plain"})
	e1.Set("repo", actor)
	e2, _ := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(second), map[string]string{"content-type": "text/plain"})
	e2.Set("repo", actor)
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- s.handleRepoUploadBlob(e1) }()
	<-fake.started
	go func() { secondDone <- s.handleRepoUploadBlob(e2) }()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("different-CID upload: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("different-CID upload blocked behind unrelated S3 upload")
	}
	close(fake.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestCanceledS3PutFailureStillPersistsCleanupOutbox(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Region: "test", Bucket: "blob-bucket"}
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &uploadLifecycleS3{putErr: errors.New("put failed after persistence"), deleteErr: errors.New("delete unavailable")}
	fake.cancelOnPut = cancel
	s.s3Client = fake
	account := s.createTestAccount(t, "s3-canceled-cleanup.pds.test")
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "canceled upload", map[string]string{"content-type": "text/plain"})
	e.SetRequest(e.Request().WithContext(cancelCtx))
	e.Set("repo", actor)
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("canceled PutObject status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	fake.mu.Lock()
	objectKey := fake.putKey
	fake.mu.Unlock()
	var deletion models.BlobDeletion
	if err := s.db.Client().Where("idempotency_key = ?", objectKey).First(&deletion).Error; err != nil {
		t.Fatalf("canceled PutObject cleanup outbox: %v", err)
	}
	if deletion.ObjectKey != objectKey || deletion.Status != BlobDeletionPending {
		t.Fatalf("canceled cleanup row = %+v", deletion)
	}
}

func TestS3UploadMetadataFailureEnqueuesExactGenerationCleanup(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Region: "test", Bucket: "blob-bucket"}
	fake := &uploadLifecycleS3{allowPut: make(chan struct{}), deleteErr: errors.New("delete unavailable")}
	close(fake.allowPut)
	s.s3Client = fake
	account := s.createTestAccount(t, "s3-upload-failure.pds.test")
	if err := s.db.Client().Exec("CREATE TRIGGER fail_blob_publication BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT, 'metadata publication failed'); END").Error; err != nil {
		t.Fatal(err)
	}

	payload := []byte("metadata must not publish")
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "text/plain"})
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	e.Set("repo", actor)
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code == http.StatusOK {
		t.Fatal("metadata failure returned success")
	}
	var blobs int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).Count(&blobs).Error; err != nil {
		t.Fatal(err)
	}
	if blobs != 0 {
		t.Fatalf("dangling Blob rows after metadata failure: %d", blobs)
	}
	fake.mu.Lock()
	bucket, objectKey, deletes := fake.putBucket, fake.putKey, append([]string(nil), fake.deleteCalls...)
	fake.mu.Unlock()
	if bucket != "blob-bucket" || objectKey == "" {
		t.Fatalf("uploaded target = %q/%q", bucket, objectKey)
	}
	if len(deletes) != 1 || deletes[0] != objectKey {
		t.Fatalf("direct cleanup targets = %v, want [%s]", deletes, objectKey)
	}
	var deletion models.BlobDeletion
	if err := s.db.Client().Where("object_key = ?", objectKey).First(&deletion).Error; err != nil {
		t.Fatal(err)
	}
	if deletion.Bucket != bucket || deletion.ObjectKey != objectKey || deletion.IdempotencyKey != objectKey {
		t.Fatalf("deletion target = %+v, want exact uploaded generation", deletion)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("metadata failure status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestSQLiteBlobUploadRollsBackAllPartsAndRejectsReferences(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "sqlite-upload-rollback.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Exec("CREATE TRIGGER fail_blob_part BEFORE INSERT ON blob_parts WHEN NEW.idx = 1 BEGIN SELECT RAISE(ABORT, 'part publication failed'); END").Error; err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("x"), blockSize+1)
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "application/octet-stream"})
	e.Set("repo", actor)
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("part failure status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	var blobs, parts int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).Count(&blobs).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Model(&models.BlobPart{}).Count(&parts).Error; err != nil {
		t.Fatal(err)
	}
	if blobs != 0 || parts != 0 {
		t.Fatalf("transaction leaked after part failure: blobs=%d parts=%d", blobs, parts)
	}

	publicRecord := MarshalableMap{
		"$type": "app.bsky.feed.post",
		"text":  "must reject failed upload",
		"blob":  atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "application/octet-stream", Size: int64(len(payload))},
	}
	rkey := "3lrollbackblob"
	if _, err := s.repoman.applyWrites(t.Context(), actor.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: &publicRecord}}, nil); err == nil {
		t.Fatal("public record committed for rolled-back blob")
	}
	if err := s.db.Client().Model(&models.Record{}).Where("did = ? AND rkey = ?", account.Did, rkey).Count(&blobs).Error; err != nil {
		t.Fatal(err)
	}
	if blobs != 0 {
		t.Fatalf("public record remained after failed upload: %d", blobs)
	}

	spaceMan := NewSpaceRepoMan(s)
	spaceRecord := map[string]any{
		"$type": "com.example.post",
		"blob":  atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "application/octet-stream", Size: int64(len(payload))},
	}
	if _, err := spaceMan.Apply(t.Context(), testSpaceRef, account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "failed-upload", Record: spaceRecord}}); err == nil {
		t.Fatal("Space record committed for rolled-back blob")
	}
	if err := s.db.Client().Model(&models.SpaceBlobRef{}).Where("author = ? AND cid = ?", account.Did, blobCID.String()).Count(&parts).Error; err != nil {
		t.Fatal(err)
	}
	if parts != 0 {
		t.Fatalf("Space reference remained after failed upload: %d", parts)
	}
}

func TestSQLiteBlobUploadDoesNotExposeUncommittedBlobToPublicOrSpace(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = newTestEvtman(t)
	account := s.createTestAccount(t, "sqlite-upload-visibility.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("y"), blockSize+1)
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	uploadErr := make(chan error, 1)
	blob := &models.Blob{Did: account.Did, Cid: blobCID.Bytes(), Storage: "sqlite"}
	go func() {
		uploadErr <- publishSQLiteBlob(t.Context(), s.db, blob, payload, func() {
			close(started)
			<-release
		})
	}()
	<-started

	publicRecord := MarshalableMap{
		"$type": "app.bsky.feed.post",
		"text":  "must wait for blob commit",
		"blob":  atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "application/octet-stream", Size: int64(len(payload))},
	}
	rkey := "3lvisibilityblob"
	if _, err := s.repoman.applyWrites(t.Context(), actor.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: &publicRecord}}, nil); err == nil {
		t.Fatal("public record committed before SQLite blob transaction commit")
	}
	spaceRecord := map[string]any{
		"$type": "com.example.post",
		"blob":  atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "application/octet-stream", Size: int64(len(payload))},
	}
	if _, err := NewSpaceRepoMan(s).Apply(t.Context(), testSpaceRef, account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "visibility", Record: spaceRecord}}); err == nil {
		t.Fatal("Space record committed before SQLite blob transaction commit")
	}
	close(release)
	if err := <-uploadErr; err != nil {
		t.Fatal(err)
	}
	var partCount int64
	if err := s.db.Client().Model(&models.BlobPart{}).Where("blob_id = ?", blob.ID).Count(&partCount).Error; err != nil {
		t.Fatal(err)
	}
	if partCount != 2 {
		t.Fatalf("committed SQLite parts = %d, want 2", partCount)
	}
	if _, err := s.repoman.applyWrites(t.Context(), actor.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: &publicRecord}}, nil); err != nil {
		t.Fatalf("public record after blob commit: %v", err)
	}
	if _, err := NewSpaceRepoMan(s).Apply(t.Context(), testSpaceRef, account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "visibility", Record: spaceRecord}}); err != nil {
		t.Fatalf("Space record after blob commit: %v", err)
	}
}

func TestRepeatedS3BlobUploadReusesReadyGenerationConcurrently(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Region: "test", Bucket: "blob-bucket"}
	fake := &uploadLifecycleS3{putStarted: make(chan struct{}), allowPut: make(chan struct{})}
	s.s3Client = fake
	account := s.createTestAccount(t, "s3-upload-dedup.pds.test")
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("one immutable generation")
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
	if err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		e, _ := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "text/plain"})
		e.Set("repo", actor)
		go func(e echo.Context) { errs <- s.handleRepoUploadBlob(e) }(e)
	}
	<-fake.putStarted
	var count int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("Blob row became visible before first upload commit: %d", count)
	}
	close(fake.allowPut)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	putCalls := fake.putCalls
	fake.mu.Unlock()
	if count != 1 || putCalls != 1 {
		t.Fatalf("deduplicated upload rows/puts = %d/%d, want 1/1", count, putCalls)
	}

	// A later ready upload must take the fast path without contacting S3.
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "text/plain"})
	e.Set("repo", actor)
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("re-upload status = %d", rec.Code)
	}
	fake.mu.Lock()
	putCalls = fake.putCalls
	fake.mu.Unlock()
	if putCalls != 1 {
		t.Fatalf("re-upload put calls = %d, want 1", putCalls)
	}
}

func TestS3PutErrorEnqueuesExactGenerationBeforeDirectCleanup(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Region: "test", Bucket: "blob-bucket"}
	fake := &uploadLifecycleS3{putErr: errors.New("put failed after persistence"), deleteErr: errors.New("delete unavailable")}
	s.s3Client = fake
	account := s.createTestAccount(t, "s3-upload-put-error.pds.test")
	actor, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("persisted before put error")
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", string(payload), map[string]string{"content-type": "text/plain"})
	e.Set("repo", actor)
	if err := s.handleRepoUploadBlob(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PutObject error status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var blobCount int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ?", account.Did).Count(&blobCount).Error; err != nil {
		t.Fatal(err)
	}
	if blobCount != 0 {
		t.Fatalf("published Blob rows after PutObject error = %d", blobCount)
	}
	fake.mu.Lock()
	bucket, objectKey, deletes := fake.putBucket, fake.putKey, append([]string(nil), fake.deleteCalls...)
	fake.mu.Unlock()
	if len(deletes) != 1 || deletes[0] != objectKey {
		t.Fatalf("direct cleanup calls = %v, want [%s]", deletes, objectKey)
	}
	var deletion models.BlobDeletion
	if err := s.db.Client().Where("idempotency_key = ?", objectKey).First(&deletion).Error; err != nil {
		t.Fatal(err)
	}
	if deletion.Bucket != bucket || deletion.ObjectKey != objectKey || deletion.Status != BlobDeletionPending {
		t.Fatalf("PutObject-error outbox row = %+v", deletion)
	}
}

func TestPublicBlobDeleteCleansEveryLegacyS3Generation(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.s3Config = &S3Config{BlobstoreEnabled: true, Region: "test", Bucket: "blob-bucket"}
	account := s.createTestAccount(t, "s3-duplicate-generations.pds.test")
	blobCID := testBlobCID(t, "duplicate-generation")
	keys := []string{"blobs/" + account.Did + "/" + blobCID.String() + "/old", "blobs/" + account.Did + "/" + blobCID.String() + "/new"}
	for _, key := range keys {
		blob := models.Blob{Did: account.Did, Cid: blobCID.Bytes(), RefCount: 1, Storage: "s3", Bucket: "blob-bucket", ObjectKey: key}
		if err := s.db.Create(t.Context(), &blob, nil).Error; err != nil {
			t.Fatal(err)
		}
	}
	publicCBOR := mustRecordCBOR(t, map[string]any{"blob": atdata.Blob{Ref: atdata.CIDLink(blobCID)}})
	if _, err := s.repoman.decrementBlobRefs(t.Context(), models.Repo{Did: account.Did}, publicCBOR); err != nil {
		t.Fatal(err)
	}
	var remaining int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).Count(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("legacy generation rows after public delete = %d", remaining)
	}
	var deletions []models.BlobDeletion
	if err := s.db.Client().Where("bucket = ?", "blob-bucket").Order("id").Find(&deletions).Error; err != nil {
		t.Fatal(err)
	}
	if len(deletions) != len(keys) {
		t.Fatalf("queued generation deletions = %d, want %d", len(deletions), len(keys))
	}
	for i, deletion := range deletions {
		if deletion.ObjectKey != keys[i] || deletion.IdempotencyKey != keys[i] {
			t.Fatalf("deletion %d = %+v, want key %s", i, deletion, keys[i])
		}
	}
	fake := &fakeBlobDeletionS3{}
	worker := NewBlobDeletionWorkerForDB(s.db, fake, time.Now)
	if n, err := worker.RunOnce(t.Context(), len(keys)); err != nil || n != len(keys) {
		t.Fatalf("generation cleanup worker n=%d err=%v", n, err)
	}
	if fake.callCount() != len(keys) {
		t.Fatalf("generation delete calls = %d, want %d", fake.callCount(), len(keys))
	}
}

func TestPublicAndSpaceBlobReferencesShareCleanupLifetime(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	ctx := t.Context()
	account := s.createTestAccount(t, "shared-blob-lifetime.pds.test")
	blobData := []byte("shared content")
	blobCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(blobData)
	if err != nil {
		t.Fatal(err)
	}
	blob := models.Blob{Did: account.Did, Cid: blobCID.Bytes(), RefCount: 1, Storage: "sqlite"}
	if err := s.db.Create(ctx, &blob, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(ctx, &models.BlobPart{BlobID: blob.ID, Idx: 0, Data: blobData}, nil).Error; err != nil {
		t.Fatal(err)
	}

	spaceMan := NewSpaceRepoMan(s)
	record := map[string]any{
		"$type": "com.example.post",
		"text":  "shared",
		"blob":  atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "text/plain", Size: int64(len(blobData))},
	}
	if _, err := spaceMan.Apply(ctx, testSpaceRef, account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "shared", Record: record}}); err != nil {
		t.Fatal(err)
	}
	publicCBOR := mustRecordCBOR(t, record)
	if _, err := s.repoman.decrementBlobRefs(ctx, models.Repo{Did: account.Did}, publicCBOR); err != nil {
		t.Fatal(err)
	}
	var retained models.Blob
	if err := s.db.Client().Where("did = ? AND cid = ?", account.Did, blobCID.Bytes()).First(&retained).Error; err != nil {
		t.Fatalf("blob after public delete: %v", err)
	}
	if retained.RefCount != 0 {
		t.Fatalf("ref_count after public delete = %d, want 0", retained.RefCount)
	}
	e, _ := newRequestContext(http.MethodGet, "/", "", nil)
	loaded, _, err := s.loadSpaceBlob(e, account.Did, blobCID)
	if err != nil || !bytes.Equal(loaded, blobData) {
		t.Fatalf("Space blob after public delete = %q, err=%v", loaded, err)
	}

	if _, err := spaceMan.DeleteRecord(ctx, testSpaceRef, account.Did, "com.example.post", "shared"); err != nil {
		t.Fatal(err)
	}
	var remaining int64
	if err := s.db.Client().Model(&models.Blob{}).Where("id = ?", blob.ID).Count(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("blob rows after final Space delete = %d, want 0", remaining)
	}
	if err := s.db.Client().Model(&models.BlobPart{}).Where("blob_id = ?", blob.ID).Count(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("blob parts after final Space delete = %d, want 0", remaining)
	}
}

func TestSpaceListBlobsIsDistinctAndScoped(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	spaceURI := testSpaceURI(t, alice.Did)
	first := []byte("first")
	second := []byte("second")
	firstCID, _ := space.CIDForCBOR(first)
	secondCID, _ := space.CIDForCBOR(second)
	for i, item := range []struct {
		cid  string
		data []byte
	}{
		{firstCID.String(), first},
		{secondCID.String(), second},
	} {
		blob := models.Blob{Did: alice.Did, Cid: []byte(firstCID.Bytes()), Storage: "sqlite"}
		if i == 1 {
			blob.Cid = secondCID.Bytes()
		}
		if err := s.db.Create(t.Context(), &blob, nil).Error; err != nil {
			t.Fatalf("create list blob: %v", err)
		}
		if err := s.db.Create(t.Context(), &models.BlobPart{BlobID: blob.ID, Idx: 0, Data: item.data}, nil).Error; err != nil {
			t.Fatalf("create list blob part: %v", err)
		}
	}
	applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "one", map[string]any{"blob": atdata.Blob{Ref: atdata.CIDLink(firstCID), Size: int64(len(first))}})
	applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "two", map[string]any{"blob": atdata.Blob{Ref: atdata.CIDLink(firstCID), Size: int64(len(first))}})
	applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "three", map[string]any{"blob": atdata.Blob{Ref: atdata.CIDLink(secondCID), Size: int64(len(second))}})

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listBlobs?space="+spaceURI+"&repo="+alice.Did, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceListBlobs(e); err != nil {
		t.Fatalf("list blobs: %v", err)
	}
	var response ComAtprotoSpaceListBlobsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode list blobs: %v", err)
	}
	if rec.Code != http.StatusOK || len(response.CIDs) != 2 {
		t.Fatalf("list blobs response = %d %#v", rec.Code, response)
	}

	// The lexicon pins this parameter as repo; did must not be accepted as an
	// alias, since accepting it would make the wire contract ambiguous.
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listBlobs?space="+spaceURI+"&did="+alice.Did, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceListBlobs(e); err != nil {
		t.Fatalf("list blobs with did alias: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("list blobs with did alias status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	invalidLimit, invalidLimitRec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listBlobs?space="+spaceURI+"&repo="+alice.Did+"&limit=1001", "", nil)
	setSpaceCredential(invalidLimit, spaceURI)
	if err := s.handleSpaceListBlobs(invalidLimit); err != nil {
		t.Fatalf("list blobs with invalid limit: %v", err)
	}
	if invalidLimitRec.Code != http.StatusBadRequest {
		t.Fatalf("list blobs limit 1001 status = %d, want %d", invalidLimitRec.Code, http.StatusBadRequest)
	}

	pageReq1, firstRec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listBlobs?space="+spaceURI+"&repo="+alice.Did+"&limit=1", "", nil)
	setSpaceCredential(pageReq1, spaceURI)
	if err := s.handleSpaceListBlobs(pageReq1); err != nil {
		t.Fatalf("first paginated list blobs: %v", err)
	}
	var page1 ComAtprotoSpaceListBlobsResponse
	if err := json.Unmarshal(firstRec.Body.Bytes(), &page1); err != nil {
		t.Fatalf("decode first paginated list blobs: %v", err)
	}
	if len(page1.CIDs) != 1 || page1.Cursor == nil {
		t.Fatalf("first paginated list blobs = %#v", page1)
	}
	pageReq2, secondRec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listBlobs?space="+spaceURI+"&repo="+alice.Did+"&limit=1&cursor="+url.QueryEscape(*page1.Cursor), "", nil)
	setSpaceCredential(pageReq2, spaceURI)
	if err := s.handleSpaceListBlobs(pageReq2); err != nil {
		t.Fatalf("second paginated list blobs: %v", err)
	}
	var page2 ComAtprotoSpaceListBlobsResponse
	if err := json.Unmarshal(secondRec.Body.Bytes(), &page2); err != nil {
		t.Fatalf("decode second paginated list blobs: %v", err)
	}
	if len(page2.CIDs) != 1 || page2.Cursor != nil || page1.CIDs[0] == page2.CIDs[0] {
		t.Fatalf("paginated list blobs pages = %#v, %#v", page1, page2)
	}
}

func TestPublicListBlobsPaginationUsesRequestedLimit(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "public-blob-pages.pds.test")
	const createdAt = "2030-01-03T00:00:00Z"
	publicCIDs := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		payload := []byte{byte(i + 1)}
		blobCID := testBlobCID(t, string(payload))
		publicCIDs = append(publicCIDs, blobCID.String())
		blob := models.Blob{Did: alice.Did, Cid: blobCID.Bytes(), Storage: "sqlite", RefCount: 1, CreatedAt: createdAt}
		if err := s.db.Create(t.Context(), &blob, nil).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Create(t.Context(), &models.BlobPart{BlobID: blob.ID, Idx: 0, Data: payload}, nil).Error; err != nil {
			t.Fatal(err)
		}
	}
	privateCID, err := space.CIDForCBOR([]byte("space-only"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(t.Context(), &models.Blob{Did: alice.Did, Cid: privateCID.Bytes(), Storage: "sqlite", RefCount: 0, CreatedAt: createdAt}, nil).Error; err != nil {
		t.Fatal(err)
	}

	first, firstRec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.listBlobs?did="+alice.Did+"&limit=2", "", nil)
	if err := s.handleSyncListBlobs(first); err != nil {
		t.Fatal(err)
	}
	var page1 ComAtprotoSyncListBlobsResponse
	if err := json.Unmarshal(firstRec.Body.Bytes(), &page1); err != nil {
		t.Fatal(err)
	}
	if len(page1.Cids) != 2 || page1.Cursor == nil {
		t.Fatalf("first page = %#v", page1)
	}
	if page1.Cids[0] != publicCIDs[2] || page1.Cids[1] != publicCIDs[1] {
		t.Fatalf("first page order = %#v, want [%s %s]", page1.Cids, publicCIDs[2], publicCIDs[1])
	}
	if containsString(page1.Cids, privateCID.String()) {
		t.Fatalf("space-only blob leaked through public list: %#v", page1.Cids)
	}
	if _, legacy := decodeSyncListBlobsCursor(*page1.Cursor); legacy {
		t.Fatalf("first page cursor is not opaque: %q", *page1.Cursor)
	}
	secondURL := "/xrpc/com.atproto.sync.listBlobs?did=" + alice.Did + "&limit=2&cursor=" + url.QueryEscape(*page1.Cursor)
	second, secondRec := newRequestContext(http.MethodGet, secondURL, "", nil)
	if err := s.handleSyncListBlobs(second); err != nil {
		t.Fatal(err)
	}
	var page2 ComAtprotoSyncListBlobsResponse
	if err := json.Unmarshal(secondRec.Body.Bytes(), &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2.Cids) != 1 || page2.Cursor != nil {
		t.Fatalf("terminal page = %#v", page2)
	}
	if page2.Cids[0] != publicCIDs[0] {
		t.Fatalf("terminal page = %#v, want [%s]", page2.Cids, publicCIDs[0])
	}

	// Older servers emitted the timestamp alone. It remains an accepted input
	// cursor, even though only newly emitted opaque cursors handle ties safely.
	legacyReq, legacyRec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.listBlobs?did="+alice.Did+"&limit=2&cursor="+url.QueryEscape(createdAt), "", nil)
	if err := s.handleSyncListBlobs(legacyReq); err != nil {
		t.Fatalf("legacy timestamp cursor: %v", err)
	}
	var legacyPage ComAtprotoSyncListBlobsResponse
	if err := json.Unmarshal(legacyRec.Body.Bytes(), &legacyPage); err != nil {
		t.Fatalf("decode legacy timestamp page: %v", err)
	}
	if legacyRec.Code != http.StatusOK || len(legacyPage.Cids) != 0 {
		t.Fatalf("legacy timestamp page = %d %#v", legacyRec.Code, legacyPage)
	}

	for _, invalidLimit := range []string{"-1", "0", "1001"} {
		req, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.listBlobs?did="+alice.Did+"&limit="+invalidLimit, "", nil)
		if err := s.handleSyncListBlobs(req); err != nil {
			t.Fatalf("limit %s returned handler error: %v", invalidLimit, err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("limit %s status = %d, want %d", invalidLimit, rec.Code, http.StatusBadRequest)
		}
	}
}

func seedPublicSQLiteBlob(t *testing.T, s *Server, did string, blobCID cid.Cid, payload []byte, createdAt string) models.Blob {
	t.Helper()
	blob := models.Blob{Did: did, Cid: blobCID.Bytes(), Storage: "sqlite", RefCount: 1, CreatedAt: createdAt}
	if err := s.db.Create(t.Context(), &blob, nil).Error; err != nil {
		t.Fatalf("create public blob: %v", err)
	}
	if payload != nil {
		if err := s.db.Create(t.Context(), &models.BlobPart{BlobID: blob.ID, Idx: 0, Data: payload}, nil).Error; err != nil {
			t.Fatalf("create public blob part: %v", err)
		}
	}
	return blob
}

func publicListBlobsPage(t *testing.T, s *Server, did string, limit int, cursor string) ComAtprotoSyncListBlobsResponse {
	t.Helper()
	path := "/xrpc/com.atproto.sync.listBlobs?did=" + did + "&limit=" + strconv.Itoa(limit)
	if cursor != "" {
		path += "&cursor=" + url.QueryEscape(cursor)
	}
	e, rec := newRequestContext(http.MethodGet, path, "", nil)
	if err := s.handleSyncListBlobs(e); err != nil {
		t.Fatalf("public listBlobs: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("public listBlobs status = %d, want %d", rec.Code, http.StatusOK)
	}
	var page ComAtprotoSyncListBlobsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode public listBlobs: %v", err)
	}
	return page
}

func TestPublicListBlobsDeduplicatesGenerationsAcrossPages(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "public-blob-duplicate-pages.pds.test")
	firstPayload := []byte("first-public-blob")
	secondPayload := []byte("second-public-blob")
	firstCID := testBlobCID(t, string(firstPayload))
	secondCID := testBlobCID(t, string(secondPayload))
	seedPublicSQLiteBlob(t, s, alice.Did, firstCID, firstPayload, "2030-01-01T00:00:00Z")
	seedPublicSQLiteBlob(t, s, alice.Did, secondCID, secondPayload, "2030-01-01T00:00:00Z")
	seedPublicSQLiteBlob(t, s, alice.Did, firstCID, firstPayload, "2030-01-01T00:00:00Z")

	page1 := publicListBlobsPage(t, s, alice.Did, 1, "")
	if len(page1.Cids) != 1 || page1.Cursor == nil || page1.Cids[0] != firstCID.String() {
		t.Fatalf("first duplicate page = %#v", page1)
	}
	page2 := publicListBlobsPage(t, s, alice.Did, 1, *page1.Cursor)
	if len(page2.Cids) != 1 || page2.Cursor != nil || page2.Cids[0] != secondCID.String() {
		t.Fatalf("second duplicate page = %#v", page2)
	}
	if page1.Cids[0] == page2.Cids[0] {
		t.Fatal("duplicate logical CID crossed page boundary")
	}
}

func TestPublicListBlobsOmitsMalformedOnlyReferencedGeneration(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "public-blob-malformed-only.pds.test")
	if err := s.db.Create(t.Context(), &models.Blob{
		Did: alice.Did, Cid: []byte("not-a-cid"), Storage: "sqlite", RefCount: 1,
		CreatedAt: "2030-01-02T00:00:00Z",
	}, nil).Error; err != nil {
		t.Fatal(err)
	}
	payload := []byte("valid-public-blob")
	validCID := testBlobCID(t, string(payload))
	seedPublicSQLiteBlob(t, s, alice.Did, validCID, payload, "2030-01-01T00:00:00Z")

	page := publicListBlobsPage(t, s, alice.Did, 10, "")
	if len(page.Cids) != 1 || page.Cids[0] != validCID.String() || page.Cursor != nil {
		t.Fatalf("malformed-only page = %#v", page)
	}
}

func TestPublicListBlobsFallsBackFromMalformedNewestGeneration(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "public-blob-malformed-newest.pds.test")
	payload := []byte("fallback-public-blob")
	blobCID := testBlobCID(t, string(payload))
	seedPublicSQLiteBlob(t, s, alice.Did, blobCID, payload, "2030-01-01T00:00:00Z")
	seedPublicSQLiteBlob(t, s, alice.Did, blobCID, nil, "2030-01-02T00:00:00Z")

	page := publicListBlobsPage(t, s, alice.Did, 10, "")
	if len(page.Cids) != 1 || page.Cids[0] != blobCID.String() || page.Cursor != nil {
		t.Fatalf("malformed-newest page = %#v", page)
	}
	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.getBlob?did="+alice.Did+"&cid="+url.QueryEscape(blobCID.String()), "", nil)
	if err := s.handleSyncGetBlob(e); err != nil {
		t.Fatalf("public getBlob fallback: %v", err)
	}
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatalf("public getBlob fallback = %d %q", rec.Code, rec.Body.Bytes())
	}
}

func TestPublicListBlobsLimitOneSkipsInvalidAndDuplicateCandidates(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "public-blob-limit-one.pds.test")
	firstPayload := []byte("limit-one-first")
	secondPayload := []byte("limit-one-second")
	firstCID := testBlobCID(t, string(firstPayload))
	secondCID := testBlobCID(t, string(secondPayload))
	seedPublicSQLiteBlob(t, s, alice.Did, firstCID, firstPayload, "2030-01-01T00:00:00Z")
	seedPublicSQLiteBlob(t, s, alice.Did, firstCID, firstPayload, "2030-01-01T00:00:00Z")
	seedPublicSQLiteBlob(t, s, alice.Did, secondCID, secondPayload, "2030-01-01T00:00:00Z")
	if err := s.db.Create(t.Context(), &models.Blob{
		Did: alice.Did, Cid: []byte("malformed-limit-one"), Storage: "sqlite", RefCount: 1,
		CreatedAt: "2030-01-02T00:00:00Z",
	}, nil).Error; err != nil {
		t.Fatal(err)
	}

	page1 := publicListBlobsPage(t, s, alice.Did, 1, "")
	if len(page1.Cids) != 1 || page1.Cursor == nil || page1.Cids[0] != secondCID.String() {
		t.Fatalf("limit-one first page = %#v", page1)
	}
	page2 := publicListBlobsPage(t, s, alice.Did, 1, *page1.Cursor)
	if len(page2.Cids) != 1 || page2.Cursor != nil || page2.Cids[0] != firstCID.String() {
		t.Fatalf("limit-one second page = %#v", page2)
	}
}
