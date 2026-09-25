package server

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
)

func checkAccountStatus(t *testing.T, s *Server, account *testAccount) ComAtprotoServerCheckAccountStatusResponse {
	t.Helper()
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	c, w := newRequestContext("GET", "/xrpc/com.atproto.server.checkAccountStatus", "", nil)
	c.Set("repo", repo)
	if err := s.handleServerCheckAccountStatus(c); err != nil || w.Code != 200 {
		t.Fatalf("checkAccountStatus: %d %s %v", w.Code, w.Body.String(), err)
	}
	var status ComAtprotoServerCheckAccountStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestCheckAccountStatusActivated(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "status.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	for _, deactivated := range []bool{false, true, false} {
		if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Update("deactivated", deactivated).Error; err != nil {
			t.Fatal(err)
		}
		if status := checkAccountStatus(t, s, account); status.Activated == deactivated {
			t.Fatalf("activated = %t when deactivated = %t", status.Activated, deactivated)
		}
	}
}

func TestCheckAccountStatusBlobCounts(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "blob-status.pds.test")
	other := s.createTestAccount(t, "other-status.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	assertCounts := func(expected, imported, records int64) {
		t.Helper()
		status := checkAccountStatus(t, s, account)
		if status.ExpectedBlobs != expected || status.ImportedBlobs != imported || status.IndexedRecords != records {
			t.Fatalf("got expected=%d imported=%d records=%d; want %d/%d/%d", status.ExpectedBlobs, status.ImportedBlobs, status.IndexedRecords, expected, imported, records)
		}
	}
	assertCounts(0, 0, 0)
	uploadTestBlob(t, s, account, "unreferenced")
	uploadTestBlob(t, s, other, "second")
	_, foreign := blobRecord(t, "foreign-only")
	otherRoot, otherBlocks, _ := importFixture(t, other.Did, []string{"app.bsky.feed.post/foreign"}, foreign)
	if code, msg := callImportRepo(t, s, other, bytes.NewReader(importCAR(t, []cid.Cid{otherRoot}, otherBlocks))); code != 200 {
		t.Fatalf("other account import: %d %s", code, msg)
	}
	_, first := blobRecord(t, "first")
	_, second := blobRecord(t, "second")
	assertCounts(0, 1, 0)
	root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/one", "app.bsky.feed.post/two", "app.bsky.feed.post/three"}, first, first, second)
	if code, msg := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all))); code != 200 {
		t.Fatalf("import: %d %s", code, msg)
	}
	assertCounts(2, 1, 3)
	uploadTestBlob(t, s, account, "first")
	uploadTestBlob(t, s, account, "first")
	for _, incomplete := range []models.Blob{{Did: account.Did}, {Did: account.Did, Cid: []byte{}}} {
		if err := s.db.Client().Create(&incomplete).Error; err != nil {
			t.Fatal(err)
		}
	}
	assertCounts(2, 2, 3)
	uploadTestBlob(t, s, account, "second")
	assertCounts(2, 3, 3)
}
