package server

import (
	"context"
	"testing"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

const badRev = "3lmbbsbe4m2a" // 12 chars; not a valid TID

func TestIsValidRev(t *testing.T) {
	if isValidRev(badRev) {
		t.Fatalf("expected %q (12 chars) to be invalid", badRev)
	}
	good := syntax.NewTIDNow(0).String()
	if !isValidRev(good) {
		t.Fatalf("expected freshly minted TID %q to be valid", good)
	}
}

// setupBadRevRepo seeds a genesis repo, then corrupts only the DB rev column to
// a 12-char value (mirroring the historical data; the signed commit still holds
// a valid rev, which is fine — recommit re-mints from the commit's MST).
func setupBadRevRepo(t *testing.T, s *Server) string {
	t.Helper()
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
	if err := s.db.Exec(context.Background(), "UPDATE repos SET rev = ? WHERE did = ?", nil, badRev, acct.Did).Error; err != nil {
		t.Fatalf("corrupt rev: %v", err)
	}
	return acct.Did
}

func eventTypesFor(t *testing.T, s *Server, did string) []string {
	t.Helper()
	var types []string
	if err := s.db.Client().Raw("SELECT type FROM event_records WHERE did = ? ORDER BY seq", did).Scan(&types).Error; err != nil {
		t.Fatalf("query event_records: %v", err)
	}
	return types
}

func currentRev(t *testing.T, s *Server, did string) string {
	t.Helper()
	urepo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	return urepo.Repo.Rev
}

func TestRunRecommitMigrationDryRun(t *testing.T) {
	s := newTestServer(t)
	did := setupBadRevRepo(t, s)
	gdb := s.db.Client()

	results, err := RunRecommitMigration(context.Background(), gdb, RecommitOptions{
		Dids:   []string{did},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("RunRecommitMigration: %v", err)
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("unexpected results: %+v", results)
	}
	if !results[0].Recommitted {
		t.Fatal("dry-run should flag the bad-rev repo as needing recommit")
	}
	if got := currentRev(t, s, did); got != badRev {
		t.Fatalf("dry-run mutated rev: got %q, want %q", got, badRev)
	}
	if types := eventTypesFor(t, s, did); len(types) != 0 {
		t.Fatalf("dry-run emitted events: %v", types)
	}
}

func TestRunRecommitMigration(t *testing.T) {
	s := newTestServer(t)
	did := setupBadRevRepo(t, s)
	gdb := s.db.Client()

	results, err := RunRecommitMigration(context.Background(), gdb, RecommitOptions{
		Dids:   []string{did},
		DryRun: false,
	})
	if err != nil {
		t.Fatalf("RunRecommitMigration: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("result error: %v", r.Err)
	}
	if !r.Recommitted {
		t.Fatal("expected repo to be recommitted")
	}
	if !isValidRev(r.NewRev) {
		t.Fatalf("new rev %q is not a valid TID", r.NewRev)
	}
	if r.NewRev == badRev {
		t.Fatal("new rev should differ from the bad rev")
	}
	if r.NewHead == r.OldHead {
		t.Fatal("recommit should produce a new head cid")
	}

	if got := currentRev(t, s, did); !isValidRev(got) {
		t.Fatalf("stored rev %q is still invalid after migration", got)
	}

	types := eventTypesFor(t, s, did)
	for _, want := range []string{"sync", "identity", "account"} {
		if !contains(types, want) {
			t.Fatalf("missing %q event; got %v", want, types)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
