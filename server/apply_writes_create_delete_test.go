package server

import (
	"context"
	"testing"
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
