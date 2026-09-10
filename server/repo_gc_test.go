package server

import (
	"context"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// gcCreateChurnedRepo seeds a repo with several records and churns it
// (update + delete). Since every applyWrites now deletes superseded blocks,
// dangling garbage is simulated by inserting unreachable rows directly into
// the blocks table (the state a pre-fix database is actually in).
func gcCreateChurnedRepo(t *testing.T, s *Server) string {
	t.Helper()
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
	did := acct.Did

	ops := make([]Op, 0, 4)
	for _, rk := range []string{"aaaa", "cccc", "eeee", "gggg"} {
		ops = append(ops, Op{
			Type:       OpTypeCreate,
			Collection: "app.bsky.feed.post",
			Rkey:       &rk,
			Record:     rmPostRecord("post " + rk),
		})
	}
	mustApply(t, s, did, ops...)

	mustApply(t, s, did,
		Op{Type: OpTypeUpdate, Collection: "app.bsky.feed.post", Rkey: strPtr("cccc"), Record: rmPostRecord("updated")},
		Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("gggg")},
	)

	return did
}

// gcInsertGarbageBlocks inserts n unreachable block rows for a did, mimicking
// the strata a pre-fix database accumulated (superseded MST nodes, deleted
// records, historical commits). Values are dag-cbor-shaped so the rows look
// like real data.
func gcInsertGarbageBlocks(t *testing.T, s *Server, did string, n int) []cid.Cid {
	t.Helper()
	out := make([]cid.Cid, 0, n)
	for i := 0; i < n; i++ {
		payload := []byte{0xA5, 0x01, byte(i), 0x02, byte(i + 1)}
		c := mkTestCid(t, payload)
		if err := s.db.Client().Exec(
			"INSERT INTO blocks (did, cid, rev, value) VALUES (?, ?, ?, ?)",
			did, c.Bytes(), "3lmbbsbe4m2a", payload,
		).Error; err != nil {
			t.Fatalf("insert garbage block: %v", err)
		}
		out = append(out, c)
	}
	return out
}

func mkTestCid(t *testing.T, b []byte) cid.Cid {
	t.Helper()
	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	c, err := pref.Sum(b)
	if err != nil {
		t.Fatalf("sum cid: %v", err)
	}
	return c
}

func TestRunRepoGcMigrationDryRun(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	did := gcCreateChurnedRepo(t, s)
	garbage := gcInsertGarbageBlocks(t, s, did, 3)

	before := countBlocks(t, s, did)

	results, err := RunRepoGcMigration(context.Background(), s.db.Client(), RepoGcOptions{
		Dids:   []string{did},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("RunRepoGcMigration: %v", err)
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].RemovedBlocks != 3 {
		t.Fatalf("dry-run should report 3 garbage blocks, got %d", results[0].RemovedBlocks)
	}
	if got := countBlocks(t, s, did); got != before {
		t.Fatalf("dry-run mutated blocks: before=%d after=%d", before, got)
	}
	for _, g := range garbage {
		if !blockExists(t, s, did, g) {
			t.Fatalf("dry-run deleted garbage block %s", g)
		}
	}
}

func TestRunRepoGcMigration(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	did := gcCreateChurnedRepo(t, s)
	garbage := gcInsertGarbageBlocks(t, s, did, 3)

	leaves := walkMstLeaves(t, s, did)
	if len(leaves) != 3 {
		t.Fatalf("expected 3 live records after churn, got %d", len(leaves))
	}

	results, err := RunRepoGcMigration(context.Background(), s.db.Client(), RepoGcOptions{
		Dids: []string{did},
	})
	if err != nil {
		t.Fatalf("RunRepoGcMigration: %v", err)
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].RemovedBlocks != 3 {
		t.Fatalf("expected 3 garbage blocks removed, got %d", results[0].RemovedBlocks)
	}

	// garbage must be gone
	for _, g := range garbage {
		if blockExists(t, s, did, g) {
			t.Fatalf("garbage block %s still present after gc", g)
		}
	}

	// every live record block must survive
	for path, c := range leaves {
		if !blockExists(t, s, did, c) {
			t.Fatalf("live record block %s for %s removed by gc", c, path)
		}
	}

	// the repo must still open and its leaves must still be reachable
	root := currentRoot(t, s, did)
	if _, err := openRepo(context.Background(), s.getBlockstore(did), root, did); err != nil {
		t.Fatalf("repo no longer opens after gc: %v", err)
	}
	if got := len(walkMstLeaves(t, s, did)); got != 3 {
		t.Fatalf("leaf count changed after gc: %d", got)
	}
}

func TestRunRepoGcMigrationNoGarbage(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	did := gcCreateChurnedRepo(t, s)

	results, err := RunRepoGcMigration(context.Background(), s.db.Client(), RepoGcOptions{
		Dids: []string{did},
	})
	if err != nil {
		t.Fatalf("RunRepoGcMigration: %v", err)
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].RemovedBlocks != 0 {
		t.Fatalf("expected 0 removals for a clean repo, got %d", results[0].RemovedBlocks)
	}
}

func TestRunRepoGcMigrationUnknownDid(t *testing.T) {
	s := newTestServer(t)

	results, err := RunRepoGcMigration(context.Background(), s.db.Client(), RepoGcOptions{
		Dids: []string{"did:plc:nonexistent0000000000000000"},
	})
	if err != nil {
		t.Fatalf("RunRepoGcMigration: %v", err)
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected an error result for an unknown did, got %+v", results)
	}
}

func TestRunRepoGcMigrationCorruptCidRowFails(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	did := gcCreateChurnedRepo(t, s)

	// insert a row with a cid that cannot be parsed: the migration must fail
	// the repo's pass instead of guessing a deletion key
	if err := s.db.Client().Exec(
		"INSERT INTO blocks (did, cid, rev, value) VALUES (?, ?, ?, ?)",
		did, []byte{0x00, 0x01, 0x02}, "3lmbbsbe4m2a", []byte{0xA5, 0x01},
	).Error; err != nil {
		t.Fatalf("insert corrupt block row: %v", err)
	}

	results, err := RunRepoGcMigration(context.Background(), s.db.Client(), RepoGcOptions{
		Dids: []string{did},
	})
	if err != nil {
		t.Fatalf("RunRepoGcMigration: %v", err)
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected an error result for the corrupt cid row, got %+v", results)
	}

	// nothing may have been deleted: the pass aborts before any deletion
	var n int64
	if err := s.db.Client().Table("blocks").Where("did = ?", did).Count(&n).Error; err != nil {
		t.Fatalf("count blocks: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected blocks to remain, got %d", n)
	}
}
