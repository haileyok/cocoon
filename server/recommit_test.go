package server

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
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

func TestRunRecommitMigrationVisibility(t *testing.T) {
	for _, state := range []struct {
		name        string
		deactivated bool
		takenDown   bool
	}{
		{name: "active"},
		{name: "deactivated", deactivated: true},
		{name: "taken-down", takenDown: true},
		{name: "both", deactivated: true, takenDown: true},
	} {
		for _, invalidRev := range []bool{false, true} {
			for _, dryRun := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/invalid=%t/dry=%t", state.name, invalidRev, dryRun), func(t *testing.T) {
					s := newTestServer(t)
					acct := s.createTestAccount(t, "alice.pds.test")
					s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
					updates := map[string]any{"deactivated": state.deactivated}
					if state.takenDown {
						updates["takedown_ref"] = "test-takedown"
					}
					if invalidRev {
						updates["rev"] = badRev
					}
					gdb := s.db.Client()
					if err := gdb.Model(&models.Repo{}).Where("did = ?", acct.Did).Updates(updates).Error; err != nil {
						t.Fatal(err)
					}
					before, err := s.getRepoActorByDid(context.Background(), acct.Did)
					if err != nil {
						t.Fatal(err)
					}
					var oldBlocks []models.Block
					if err := gdb.Order("cid").Find(&oldBlocks).Error; err != nil {
						t.Fatal(err)
					}
					// Existing events must remain unchanged, even when publication is skipped.
					p, err := NewDbPersister(gdb, 0)
					if err != nil {
						t.Fatal(err)
					}
					if err := p.Persist(context.Background(), &events.XRPCStreamEvent{
						RepoAccount: &atproto.SyncSubscribeRepos_Account{Did: acct.Did, Active: false},
					}); err != nil {
						t.Fatal(err)
					}
					var oldEvents []models.EventRecord
					if err := gdb.Order("seq").Find(&oldEvents).Error; err != nil {
						t.Fatal(err)
					}
					results, err := RunRecommitMigration(context.Background(), gdb, RecommitOptions{
						Dids: []string{acct.Did}, DryRun: dryRun,
					})
					if err != nil || len(results) != 1 {
						t.Fatalf("migration: results=%+v err=%v", results, err)
					}
					r := results[0]
					if r.Err != nil || r.Recommitted != invalidRev {
						t.Fatalf("unexpected result: %+v", r)
					}
					if r.Inactive != (state.deactivated || state.takenDown) {
						t.Fatalf("incorrect publication status: %+v", r)
					}
					after, err := s.getRepoActorByDid(context.Background(), acct.Did)
					if err != nil {
						t.Fatal(err)
					}
					oldHead, err := cid.Cast(before.Root)
					if err != nil {
						t.Fatal(err)
					}
					newHead, err := cid.Cast(after.Root)
					if err != nil {
						t.Fatal(err)
					}
					if r.OldRev != before.Rev || r.OldHead != oldHead.String() ||
						r.NewRev != after.Rev || r.NewHead != newHead.String() {
						t.Fatalf("result does not match persisted head/rev: %+v", r)
					}
					if invalidRev && !dryRun {
						if !isValidRev(after.Rev) || bytes.Equal(before.Root, after.Root) {
							t.Fatal("invalid revision was not repaired locally")
						}
						// Only the head and revision may change, never the account's visibility.
						after.Repo.Root, after.Repo.Rev = before.Root, before.Rev
					} else {
						var newBlocks []models.Block
						if err := gdb.Order("cid").Find(&newBlocks).Error; err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(oldBlocks, newBlocks) {
							t.Fatal("dry run or valid revision changed stored blocks")
						}
					}
					if !reflect.DeepEqual(before, after) {
						t.Fatal("migration changed unrelated repo/actor state")
					}
					var newEvents []models.EventRecord
					if err := gdb.Order("seq").Find(&newEvents).Error; err != nil {
						t.Fatal(err)
					}
					if dryRun || state.deactivated || state.takenDown {
						if !reflect.DeepEqual(oldEvents, newEvents) {
							t.Fatalf("inactive repo or dry run changed persisted events: %v", eventTypesFor(t, s, acct.Did))
						}
						return
					}
					if len(newEvents) != 4 || !reflect.DeepEqual(oldEvents[0], newEvents[0]) {
						t.Fatalf("active migration must preserve history and append exactly three events: %+v", newEvents)
					}
					var emitted []*events.XRPCStreamEvent
					if err := p.Playback(context.Background(), oldEvents[0].Seq, func(evt *events.XRPCStreamEvent) error {
						emitted = append(emitted, evt)
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					if len(emitted) != 3 || emitted[0].RepoSync == nil || emitted[1].RepoIdentity == nil || emitted[2].RepoAccount == nil {
						t.Fatalf("expected sync, identity, account: %+v", emitted)
					}
					if emitted[0].RepoSync.Did != acct.Did || emitted[0].RepoSync.Rev != r.NewRev ||
						emitted[1].RepoIdentity.Did != acct.Did || emitted[1].RepoIdentity.Handle == nil || *emitted[1].RepoIdentity.Handle != before.Handle ||
						emitted[2].RepoAccount.Did != acct.Did || !emitted[2].RepoAccount.Active {
						t.Fatal("active migration announced incorrect repo state")
					}
				})
			}
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
