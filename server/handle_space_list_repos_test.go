package server

import (
	"encoding/json"
	"net/http"
	"testing"

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
