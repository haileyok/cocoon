package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
)

func testSpaceURI(t *testing.T, authority string) string {
	t.Helper()
	ref, err := space.NewSpaceURI(authority, "com.example.space", "one")
	if err != nil {
		t.Fatalf("space URI: %v", err)
	}
	return ref.String()
}

func applySpaceRecord(t *testing.T, s *Server, spaceURI, author, collection, rkey string, value map[string]any) SpaceRepoBatch {
	t.Helper()
	if s.spaceRepoMan == nil {
		s.spaceRepoMan = NewSpaceRepoMan(s)
	}
	batch, err := s.spaceRepoMan.Apply(t.Context(), spaceURI, author, []SpaceRepoOperation{{
		Type: SpaceRepoOpPut, Collection: collection, Rkey: rkey, Record: value,
	}})
	if err != nil {
		t.Fatalf("apply space record: %v", err)
	}
	return batch
}

func setSpaceOAuth(e echo.Context, did, spaceURI string, action string, extra ...string) {
	ref, err := space.ParseSpaceURI(spaceURI)
	if err != nil {
		panic(err)
	}
	scope := "space:" + string(ref.SpaceType) + "?authority=" + string(ref.AuthorityDID) + "&action=" + action
	scopes := append([]string{scope}, extra...)
	SetPrincipal(e, &OAuthPrincipal{Subject: did, Scopes: scopes})
}

func setSpaceCredential(e echo.Context, spaceURI string) {
	SetPrincipal(e, &SpaceCredentialPrincipal{SpaceURI: spaceURI})
}

func TestSpaceRepoReadAuthorizationAndCurrentRecords(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	bob := s.createTestAccount(t, "bob.pds.test")
	spaceURI := testSpaceURI(t, alice.Did)
	applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "one", map[string]any{"text": "alice"})
	applySpaceRecord(t, s, spaceURI, bob.Did, "com.example.record", "one", map[string]any{"text": "bob"})

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getRecord?space="+spaceURI+"&did="+alice.Did+"&collection=com.example.record&rkey=one", "", nil)
	setSpaceOAuth(e, alice.Did, spaceURI, "read_self")
	if err := s.handleSpaceGetRecord(e); err != nil {
		t.Fatalf("own getRecord: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("own status = %d, want 200", rec.Code)
	}

	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getRecord?space="+spaceURI+"&did="+bob.Did+"&collection=com.example.record&rkey=one", "", nil)
	setSpaceOAuth(e, alice.Did, spaceURI, "read")
	if err := s.handleSpaceGetRecord(e); err != nil {
		t.Fatalf("cross getRecord: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross OAuth status = %d, want 403", rec.Code)
	}

	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getRecord?space="+spaceURI+"&did="+bob.Did+"&collection=com.example.record&rkey=one", "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetRecord(e); err != nil {
		t.Fatalf("credential cross getRecord: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("credential cross status = %d, want 200", rec.Code)
	}

	otherSpace := testSpaceURI(t, bob.Did)
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getRecord?space="+otherSpace+"&did="+alice.Did+"&collection=com.example.record&rkey=one", "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetRecord(e); err != nil {
		t.Fatalf("mismatched credential: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched credential status = %d, want 403", rec.Code)
	}
}

func TestSpaceLatestCommitAndRepoCAR(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	spaceURI := testSpaceURI(t, alice.Did)
	batch := applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "one", map[string]any{"text": "hello"})
	ref, _ := space.ParseSpaceURI(spaceURI)

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getLatestCommit?space="+spaceURI+"&did="+alice.Did, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetLatestCommit(e); err != nil {
		t.Fatalf("latest commit: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("latest status = %d, want 200", rec.Code)
	}
	var latest ComAtprotoSpaceGetLatestCommitResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &latest); err != nil {
		t.Fatalf("decode latest: %v", err)
	}
	key, err := atcrypto.ParsePrivateBytesK256(alice.SigningKey)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("public test key: %v", err)
	}
	if !space.VerifyCommit(latest.Commit, space.CommitContext{Space: spaceURI, Author: alice.Did, Rev: batch.Rev}, pub.DIDKey()) {
		t.Fatal("latest commit did not verify against the account signing key")
	}

	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getRepo?space="+spaceURI+"&did="+alice.Did, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetRepo(e); err != nil {
		t.Fatalf("getRepo: %v", err)
	}
	if rec.Code != http.StatusOK || rec.Header().Get(echo.HeaderContentType) != "application/vnd.ipld.car" {
		t.Fatalf("getRepo response = %d/%q", rec.Code, rec.Header().Get(echo.HeaderContentType))
	}
	verified, err := space.VerifyRepoCAR(rec.Body.Bytes(), space.VerifyRepoParams{Space: spaceURI, Author: alice.Did, DIDKey: pub.DIDKey()})
	if err != nil {
		t.Fatalf("verify repo CAR: %v", err)
	}
	if len(verified.Records) != 1 || verified.Records[0].Collection != "com.example.record" {
		t.Fatalf("CAR records = %#v", verified.Records)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("hello")) {
		t.Fatal("CAR did not contain the canonical record value")
	}

	var repo models.SpaceRepo
	if err := s.db.First(t.Context(), &repo, "space = ? AND author = ?", ref.String(), alice.Did).Error; err != nil {
		t.Fatalf("stored space repo: %v", err)
	}
	if repo.Rev != batch.Rev {
		t.Fatalf("stored rev = %q, want %q", repo.Rev, batch.Rev)
	}
}

func TestSpaceListRepoOpsAtomicPaginationAndCurrentValues(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	spaceURI := testSpaceURI(t, alice.Did)
	if s.spaceRepoMan == nil {
		s.spaceRepoMan = NewSpaceRepoMan(s)
	}
	first, err := s.spaceRepoMan.Apply(t.Context(), spaceURI, alice.Did, []SpaceRepoOperation{
		{Type: SpaceRepoOpCreate, Collection: "com.example.record", Rkey: "one", Record: map[string]any{"text": "old"}},
		{Type: SpaceRepoOpCreate, Collection: "com.example.record", Rkey: "two", Record: map[string]any{"text": "two"}},
	})
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	second := applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "one", map[string]any{"text": "new"})

	target := "/xrpc/com.atproto.space.listRepoOps?space=" + spaceURI + "&did=" + alice.Did + "&limit=1"
	e, rec := newRequestContext(http.MethodGet, target, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceListRepoOps(e); err != nil {
		t.Fatalf("first ops page: %v", err)
	}
	var firstPage ComAtprotoSpaceListRepoOpsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &firstPage); err != nil {
		t.Fatalf("decode first ops page: %v", err)
	}
	if len(firstPage.Ops) != 2 || firstPage.Cursor == nil {
		t.Fatalf("first page ops=%d cursor=%v; atomic revision was split", len(firstPage.Ops), firstPage.Cursor)
	}
	if firstPage.Ops[0].Value != nil {
		t.Fatal("superseded operation unexpectedly included a current value")
	}
	if firstPage.Ops[1].Value == nil {
		t.Fatal("current operation did not include its value")
	}

	target += "&cursor=" + *firstPage.Cursor
	e, rec = newRequestContext(http.MethodGet, target, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceListRepoOps(e); err != nil {
		t.Fatalf("terminal ops page: %v", err)
	}
	var terminal ComAtprotoSpaceListRepoOpsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &terminal); err != nil {
		t.Fatalf("decode terminal ops page: %v", err)
	}
	if len(terminal.Ops) != 1 || terminal.Commit == nil || terminal.Cursor != nil {
		t.Fatalf("terminal page ops=%d commit=%v cursor=%v", len(terminal.Ops), terminal.Commit != nil, terminal.Cursor)
	}
	if terminal.Ops[0].Rev != second.Rev || terminal.Ops[0].Value == nil {
		t.Fatalf("terminal op = %#v, want current update at %q", terminal.Ops[0], second.Rev)
	}
	if first.Rev == second.Rev {
		t.Fatal("test batches unexpectedly shared a revision")
	}

	// An unknown/old since revision returns the retained window, not a made-up
	// HistoryUnavailable error.
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.listRepoOps?space="+spaceURI+"&did="+alice.Did+"&since=old-revision", "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceListRepoOps(e); err != nil {
		t.Fatalf("old since: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("old since status = %d", rec.Code)
	}
}

func TestSpaceRepoAvailabilityErrors(t *testing.T) {
	tests := []struct {
		name  string
		field string
		error string
	}{
		{"deactivated", "deactivated", "RepoDeactivated"},
		{"suspended", "suspended", "RepoSuspended"},
		{"takendown", "takendown", "RepoTakendown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t)
			alice := s.createTestAccount(t, "alice-"+test.name+".pds.test")
			spaceURI := testSpaceURI(t, alice.Did)
			applySpaceRecord(t, s, spaceURI, alice.Did, "com.example.record", "one", map[string]any{"text": "private"})
			if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", alice.Did).Update(test.field, true).Error; err != nil {
				t.Fatal(err)
			}
			e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getLatestCommit?space="+spaceURI+"&did="+alice.Did, "", nil)
			setSpaceCredential(e, spaceURI)
			if err := s.handleSpaceGetLatestCommit(e); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(test.error)) {
				t.Fatalf("%s response = %d %s", test.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSpaceRepoNotFoundError(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	spaceURI := testSpaceURI(t, alice.Did)
	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.space.getLatestCommit?space="+spaceURI+"&did="+alice.Did, "", nil)
	setSpaceCredential(e, spaceURI)
	if err := s.handleSpaceGetLatestCommit(e); err != nil {
		t.Fatalf("missing repo: %v", err)
	}
	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(`"RepoNotFound"`)) {
		t.Fatalf("missing repo response = %d %s", rec.Code, rec.Body.String())
	}
}
