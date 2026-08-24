package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
)

func TestSpaceListReposUsesWriterSetNotMembers(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	bob := s.createTestAccount(t, "bob.pds.test")
	spaceURI := testSpaceURI(t, alice.Did)
	if err := s.db.Create(t.Context(), &models.SimpleSpaceMember{Space: spaceURI, DID: bob.Did}, nil).Error; err != nil {
		t.Fatalf("create member: %v", err)
	}
	ltHash, err := space.NewLtHash()
	if err != nil {
		t.Fatalf("new lthash: %v", err)
	}
	if err := s.db.Create(t.Context(), &models.SpaceWriter{Space: spaceURI, Author: alice.Did, Rev: "bafyrev", Hash: ltHash.State()}, nil).Error; err != nil {
		t.Fatalf("create writer: %v", err)
	}

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listRepos?space="+spaceURI, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceListRepos(e); err != nil {
		t.Fatalf("list repos: %v", err)
	}
	var response ComAtprotoSpaceListReposResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode list repos: %v", err)
	}
	if rec.Code != http.StatusOK || len(response.Repos) != 1 {
		t.Fatalf("list repos response = %d %#v", rec.Code, response)
	}
	if response.Repos[0].DID != alice.Did || response.Repos[0].Rev != "bafyrev" || response.Repos[0].Hash == "" {
		t.Fatalf("writer ref = %#v", response.Repos[0])
	}
	if response.Repos[0].DID == bob.Did {
		t.Fatal("membership row leaked into writer list")
	}

	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listRepos?space="+spaceURI, "", nil)
	setSpaceOAuth(e, alice.Did, spaceURI, "read")
	if err := s.handleSpaceListRepos(e); err != nil {
		t.Fatalf("OAuth list repos: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("OAuth list repos status = %d, want 403", rec.Code)
	}
}

func TestSpaceListReposIncludesLocalOAuthWriterHead(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	service := "did:web:syncer.test#space"
	if err := s.db.Create(t.Context(), &models.SpaceNotifyRegistration{Space: ref.String(), Service: service, ExpiresAt: time.Now().Add(time.Hour)}, nil).Error; err != nil {
		t.Fatalf("seed notification registration: %v", err)
	}
	body := map[string]any{
		"space": ref.String(), "repo": account.Did, "collection": "com.example.post", "rkey": "first",
		"record": map[string]any{"$type": "com.example.post", "text": "one"},
	}
	status, output := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.createRecord", body, []string{oauthSpaceScope(ref, "create", "com.example.post")}, s.handleSpaceCreateRecord)
	if status != http.StatusOK || output["cid"] == nil {
		t.Fatalf("OAuth create = %d/%v", status, output)
	}

	var firstRepo models.SpaceRepo
	if err := s.db.Client().Where("space = ? AND author = ?", ref.String(), account.Did).First(&firstRepo).Error; err != nil {
		t.Fatalf("load first repo head: %v", err)
	}
	firstHash := spaceHashHex(firstRepo.LtHash)
	if firstRepo.Rev == "" || firstHash == "" {
		t.Fatalf("first repo head = %+v", firstRepo)
	}

	body["record"] = map[string]any{"$type": "com.example.post", "text": "two"}
	status, output = invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.putRecord", body, []string{oauthSpaceScope(ref, "update", "com.example.post")}, s.handleSpacePutRecord)
	if status != http.StatusOK || output["cid"] == nil {
		t.Fatalf("OAuth update = %d/%v", status, output)
	}
	var secondRepo models.SpaceRepo
	if err := s.db.Client().Where("space = ? AND author = ?", ref.String(), account.Did).First(&secondRepo).Error; err != nil {
		t.Fatalf("load second repo head: %v", err)
	}
	secondHash := spaceHashHex(secondRepo.LtHash)
	if secondRepo.Rev == firstRepo.Rev || secondHash == firstHash {
		t.Fatalf("repo head did not advance: first=%+v second=%+v", firstRepo, secondRepo)
	}

	var writer models.SpaceWriter
	if err := s.db.Client().Where("space = ? AND author = ?", ref.String(), account.Did).First(&writer).Error; err != nil {
		t.Fatalf("load local writer: %v", err)
	}
	if writer.Author != account.Did || writer.Rev != secondRepo.Rev || spaceHashHex(writer.Hash) != secondHash || writer.Host != s.config.Did {
		t.Fatalf("local writer = %+v, want author=%q rev=%q hash=%q host=%q", writer, account.Did, secondRepo.Rev, secondHash, s.config.Did)
	}

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listRepos?space="+ref.String(), "", nil)
	setSpaceCredential(e, ref.String())
	if err := s.handleSpaceListRepos(e); err != nil {
		t.Fatalf("credential list repos: %v", err)
	}
	var response ComAtprotoSpaceListReposResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode list repos: %v", err)
	}
	if rec.Code != http.StatusOK || len(response.Repos) != 1 {
		t.Fatalf("list repos response = %d %#v", rec.Code, response)
	}
	if got := response.Repos[0]; got.DID != account.Did || got.Rev != secondRepo.Rev || got.Hash != secondHash {
		t.Fatalf("list repos writer = %#v, want did=%q rev=%q hash=%q", got, account.Did, secondRepo.Rev, secondHash)
	}

	// Replaying the already-observed first revision must be monotonic and must
	// not create another public forwarding delivery or overwrite the self host.
	if err := s.RecordSpaceNotifyWrite(t.Context(), ref.String(), account.Did, firstRepo.Rev, firstRepo.LtHash, "did:web:stale-host.test"); err != nil {
		t.Fatalf("stale notifyWrite: %v", err)
	}
	var afterStale models.SpaceWriter
	if err := s.db.Client().Where("space = ? AND author = ?", ref.String(), account.Did).First(&afterStale).Error; err != nil {
		t.Fatalf("load writer after stale notification: %v", err)
	}
	if afterStale.Rev != secondRepo.Rev || afterStale.Host != s.config.Did || spaceHashHex(afterStale.Hash) != secondHash {
		t.Fatalf("stale notification regressed writer = %+v", afterStale)
	}
	var deliveries []models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ? AND service = ?", ref.String(), service).Find(&deliveries).Error; err != nil {
		t.Fatalf("load notification deliveries: %v", err)
	}
	if len(deliveries) != 2 || deliveries[0].Rev == deliveries[1].Rev {
		t.Fatalf("notification deliveries = %+v, want one per local revision", deliveries)
	}

	var publicRecords int64
	if err := s.db.Client().Model(&models.Record{}).Where("did = ?", account.Did).Count(&publicRecords).Error; err != nil {
		t.Fatalf("count public records: %v", err)
	}
	if publicRecords != 0 || s.evtman != nil {
		t.Fatalf("local Space write leaked public state: records=%d evtman=%v", publicRecords, s.evtman != nil)
	}
}
