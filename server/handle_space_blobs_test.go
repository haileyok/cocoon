package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
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
	blob := models.Blob{Did: alice.Did, Cid: blobCID.Bytes(), Storage: "sqlite"}
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

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listBlobs?space="+spaceURI+"&did="+alice.Did, "", nil)
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
}
