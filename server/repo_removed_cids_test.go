package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/events"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"github.com/multiformats/go-multihash"
)

// walkMstLeaves opens the repo at its current head and collects every leaf
// key -> CID pair in the MST.
func walkMstLeaves(t *testing.T, s *Server, did string) map[string]cid.Cid {
	t.Helper()
	urepo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	root, err := cid.Cast(urepo.Root)
	if err != nil {
		t.Fatalf("cast root: %v", err)
	}
	r, err := openRepo(context.Background(), s.getBlockstore(did), root, did)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	leaves := map[string]cid.Cid{}
	if err := r.MST.Walk(func(key []byte, val cid.Cid) error {
		leaves[string(key)] = val
		return nil
	}); err != nil {
		t.Fatalf("walk mst: %v", err)
	}
	return leaves
}

// currentRoot returns the repo's current head commit CID.
func currentRoot(t *testing.T, s *Server, did string) cid.Cid {
	t.Helper()
	urepo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	root, err := cid.Cast(urepo.Root)
	if err != nil {
		t.Fatalf("cast root: %v", err)
	}
	return root
}

// collectTreeStructuralCids walks the MST at root and returns the CIDs of
// every MST node block in the tree (not record blocks).
func collectTreeStructuralCids(t *testing.T, s *Server, did string, root cid.Cid) map[cid.Cid]struct{} {
	t.Helper()
	r, err := openRepo(context.Background(), s.getBlockstore(did), root, did)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	out := map[cid.Cid]struct{}{}
	var walk func(n *mst.Node)
	walk = func(n *mst.Node) {
		if n == nil {
			return
		}
		if n.CID != nil {
			out[*n.CID] = struct{}{}
		}
		for _, e := range n.Entries {
			if e.Child != nil {
				walk(e.Child)
			}
		}
	}
	walk(r.MST.Root)
	return out
}

// countBlocks returns the number of block rows for a did.
func countBlocks(t *testing.T, s *Server, did string) int64 {
	t.Helper()
	var n int64
	if err := s.db.Client().Table("blocks").Where("did = ?", did).Count(&n).Error; err != nil {
		t.Fatalf("count blocks: %v", err)
	}
	return n
}

// blockExists checks whether a block row exists in the DB for a did+cid.
func blockExists(t *testing.T, s *Server, did string, c cid.Cid) bool {
	t.Helper()
	var n int64
	if err := s.db.Client().Table("blocks").Where("did = ? AND cid = ?", did, c.Bytes()).Count(&n).Error; err != nil {
		t.Fatalf("count block rows: %v", err)
	}
	return n > 0
}

// blockstoreHas checks the blockstore API for a cid (fresh instance, so the
// in-memory inserts map is empty and the DB is consulted directly).
func blockstoreHas(t *testing.T, s *Server, did string, c cid.Cid) bool {
	t.Helper()
	bs := s.getBlockstore(did)
	_, err := bs.Get(context.Background(), c)
	return err == nil
}

func mustApply(t *testing.T, s *Server, did string, ops ...Op) {
	t.Helper()
	// fetch the repo fresh each time: applyWrites loads the MST from
	// urepo.Root, so a stale copy would rewind the tree to an older revision
	urepo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	if _, err := s.repoman.applyWrites(context.Background(), urepo.Repo, ops, nil); err != nil {
		t.Fatalf("applyWrites: %v", err)
	}
}

func rmPostRecord(text string) *MarshalableMap {
	mm := MarshalableMap{
		"$type":     "app.bsky.feed.post",
		"text":      text,
		"createdAt": "2024-01-01T00:00:00Z",
	}
	return &mm
}

func strPtr(v string) *string { return &v }

// TestApplyWritesRemovesSupersededRecordBlocks asserts that updating a record
// deletes the prior record version's block, and deleting a record deletes the
// record block entirely, matching the reference PDS behavior of deleting
// commit.removedCids.
func TestApplyWritesRemovesSupersededRecordBlocks(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeCreate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
		Record:     rmPostRecord("hello"),
	})

	v1 := walkMstLeaves(t, s, acct.Did)["app.bsky.feed.post/r1"]
	if v1 == cid.Undef {
		t.Fatal("record not in MST after create")
	}
	blocksAfterCreate := countBlocks(t, s, acct.Did)

	// update with different content
	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeUpdate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
		Record:     rmPostRecord("hello v2"),
	})

	if blockExists(t, s, acct.Did, v1) {
		t.Fatal("old record block still present in DB after update")
	}
	if blockstoreHas(t, s, acct.Did, v1) {
		t.Fatal("old record block still gettable via blockstore after update")
	}

	leaves := walkMstLeaves(t, s, acct.Did)
	v2 := leaves["app.bsky.feed.post/r1"]
	if v2 == cid.Undef || v2 == v1 {
		t.Fatalf("update did not produce a new record CID: v1=%s v2=%s", v1, v2)
	}
	if !blockExists(t, s, acct.Did, v2) {
		t.Fatal("new record block missing after update")
	}

	// an update writes a new record block and new MST path, and removes the
	// old record block and old MST path: the table must not grow.
	blocksAfterUpdate := countBlocks(t, s, acct.Did)
	if blocksAfterUpdate > blocksAfterCreate {
		t.Fatalf("block count grew after update: before=%d after=%d", blocksAfterCreate, blocksAfterUpdate)
	}

	// delete the record
	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeDelete,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
	})

	if _, ok := walkMstLeaves(t, s, acct.Did)["app.bsky.feed.post/r1"]; ok {
		t.Fatal("record still in MST after delete")
	}
	if blockExists(t, s, acct.Did, v2) {
		t.Fatal("deleted record block still present in DB after delete")
	}
	if blockstoreHas(t, s, acct.Did, v2) {
		t.Fatal("deleted record block still gettable via blockstore after delete")
	}
}

// TestApplyWritesRemovesSupersededMstNodes asserts that MST nodes superseded
// by a write are deleted, while MST nodes still linked from the new root are
// retained.
func TestApplyWritesRemovesSupersededMstNodes(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	// seed enough records that the MST has multiple levels, so a write to one
	// key only rewrites the path to that key and other subtrees stay shared
	rkeys := []string{
		"aaaa", "cccc", "eeee", "gggg", "iiii",
		"kkkk", "mmmm", "oooo", "qqqq", "ssss",
	}
	ops := make([]Op, 0, len(rkeys))
	for _, rk := range rkeys {
		ops = append(ops, Op{
			Type:       OpTypeCreate,
			Collection: "app.bsky.feed.post",
			Rkey:       &rk,
			Record:     rmPostRecord(fmt.Sprintf("post %s", rk)),
		})
	}
	mustApply(t, s, acct.Did, ops...)

	rootBefore := currentRoot(t, s, acct.Did)
	structuralBefore := collectTreeStructuralCids(t, s, acct.Did, rootBefore)

	// update one key
	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeUpdate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("kkkk"),
		Record:     rmPostRecord("updated"),
	})

	rootAfter := currentRoot(t, s, acct.Did)
	if rootAfter == rootBefore {
		t.Fatal("update did not change the root")
	}
	structuralAfter := collectTreeStructuralCids(t, s, acct.Did, rootAfter)

	// every node CID linked from both revisions must still be in the store
	for c := range structuralBefore {
		if _, linked := structuralAfter[c]; linked {
			if !blockstoreHas(t, s, acct.Did, c) {
				t.Fatalf("shared MST node %s deleted but still linked from current root", c)
			}
		}
	}

	// superseded MST nodes (in before, not in after) must be gone
	removed := 0
	for c := range structuralBefore {
		if _, linked := structuralAfter[c]; !linked {
			removed++
			if blockstoreHas(t, s, acct.Did, c) {
				t.Fatalf("superseded MST node %s still present after update", c)
			}
		}
	}
	if removed == 0 {
		t.Fatal("expected at least one superseded MST node to be removed")
	}

	// all leaves must still be reachable
	if n := len(walkMstLeaves(t, s, acct.Did)); n != len(rkeys) {
		t.Fatalf("leaf count changed after update: %d", n)
	}
}

// TestApplyWritesRemovesSupersededCommitBlocks asserts the previous commit
// block is deleted when a new commit is written, matching the reference PDS
// (DataDiff adds the previous commit CID to removedCids).
func TestApplyWritesRemovesSupersededCommitBlocks(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	genesisRoot, _ := s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	if !blockExists(t, s, acct.Did, genesisRoot) {
		t.Fatal("genesis commit block missing before write")
	}

	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeCreate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
		Record:     rmPostRecord("hello"),
	})

	if blockExists(t, s, acct.Did, genesisRoot) {
		t.Fatal("previous commit block still present after new commit")
	}

	// the current commit must still be there, and the repo must still open
	root := currentRoot(t, s, acct.Did)
	if !blockstoreHas(t, s, acct.Did, root) {
		t.Fatal("current commit block missing")
	}
	if _, err := openRepo(context.Background(), s.getBlockstore(acct.Did), root, acct.Did); err != nil {
		t.Fatalf("repo no longer opens from current root: %v", err)
	}
}

// TestApplyWritesNoopUpdateKeepsRecordBlock asserts that an update writing
// identical content does not delete the record block.
func TestApplyWritesNoopUpdateKeepsRecordBlock(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeCreate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
		Record:     rmPostRecord("hello"),
	})
	c1 := walkMstLeaves(t, s, acct.Did)["app.bsky.feed.post/r1"]

	// identical content -> same record CID -> nothing to remove
	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeUpdate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
		Record:     rmPostRecord("hello"),
	})

	c2 := walkMstLeaves(t, s, acct.Did)["app.bsky.feed.post/r1"]
	if c1 != c2 {
		t.Fatalf("identical update produced different record CID: %s vs %s", c1, c2)
	}
	if !blockExists(t, s, acct.Did, c1) {
		t.Fatal("record block removed by no-op update")
	}
}

// TestApplyWritesFirehoseAfterRemovals asserts #commit events still carry
// well-formed CARs (all referenced blocks present) once superseded blocks are
// being deleted.
func TestApplyWritesFirehoseAfterRemovals(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	ctx := context.Background()

	evts, cancel, err := s.evtman.Subscribe(ctx, "test", func(*events.XRPCStreamEvent) bool { return true }, nil)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()

	waitCommit := func() *atproto.SyncSubscribeRepos_Commit {
		t.Helper()
		select {
		case e := <-evts:
			if e.RepoCommit == nil {
				t.Fatalf("expected #commit event, got %+v", e)
			}
			return e.RepoCommit
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for firehose commit event")
			return nil
		}
	}

	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeCreate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
		Record:     rmPostRecord("hello"),
	})
	waitCommit()

	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeUpdate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
		Record:     rmPostRecord("hello v2"),
	})
	evt := waitCommit()

	// parse the event CAR and check every block it advertises can be read back
	// from the blockstore
	bs := s.getBlockstore(acct.Did)
	cr, err := car.NewCarReader(bytes.NewReader(evt.Blocks))
	if err != nil {
		t.Fatalf("parse event car: %v", err)
	}
	n := 0
	for {
		blk, err := cr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read car block: %v", err)
		}
		got, err := bs.Get(ctx, blk.Cid())
		if err != nil {
			t.Fatalf("event car advertises block %s which is not in the blockstore: %v", blk.Cid(), err)
		}
		if !bytes.Equal(got.RawData(), blk.RawData()) {
			t.Fatalf("block %s bytes differ between event car and blockstore", blk.Cid())
		}
		n++
	}
	if n == 0 {
		t.Fatal("event car contained no blocks")
	}

	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeDelete,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("r1"),
	})
	evt = waitCommit()

	// the delete event CAR embeds the deleted record block's bytes (op.Prev)
	// so consumers can apply the op without the blockstore; those bytes are
	// intentionally no longer in the store. Assert the CAR is well-formed and
	// self-contained, and that every non-record block (commit + MST nodes from
	// the write log) is still present.
	cr, err = car.NewCarReader(bytes.NewReader(evt.Blocks))
	if err != nil {
		t.Fatalf("parse delete event car: %v", err)
	}
	deletedPrev := evt.Ops[0].Prev
	nDeletedBlocks := 0
	for {
		blk, err := cr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read car block: %v", err)
		}
		if deletedPrev != nil && blk.Cid().String() == deletedPrev.String() {
			nDeletedBlocks++
			continue // embedded prev block: expected absent from store
		}
		if _, err := bs.Get(ctx, blk.Cid()); err != nil {
			t.Fatalf("delete event car advertises block %s which is not in the blockstore: %v", blk.Cid(), err)
		}
	}
	if nDeletedBlocks == 0 {
		t.Fatal("expected the deleted record block bytes to be embedded in the event CAR")
	}
}

// TestApplyWritesBatchCreateThenDeleteCleansBlock asserts that a batch which
// creates and then deletes the same rkey does not leave the (now unlinked)
// record block in storage.
func TestApplyWritesBatchCreateThenDeleteCleansBlock(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	did := acct.Did
	urepo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	blocksBefore := countBlocks(t, s, did)

	rkey := "3laaaaaaaaa2x"
	rec := rmPostRecord("transient")
	if _, err := s.repoman.applyWrites(context.Background(), urepo.Repo, []Op{
		{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: rec},
		{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: &rkey},
	}, nil); err != nil {
		t.Fatalf("applyWrites create+delete: %v", err)
	}

	// the tree is empty again, so every block from before except the new
	// commit must have been removed; nothing may linger
	blocksAfter := countBlocks(t, s, did)
	if blocksAfter > blocksBefore {
		t.Fatalf("create+delete batch left blocks behind: before=%d after=%d", blocksBefore, blocksAfter)
	}

	leaves := walkMstLeaves(t, s, did)
	if len(leaves) != 0 {
		t.Fatalf("expected empty MST after create+delete batch, got %d leaves", len(leaves))
	}
}

// TestApplyWritesBatchUpdateThenDeleteCleansBlock asserts that a batch which
// updates a record and then deletes it removes both the old and the new
// record blocks.
func TestApplyWritesBatchUpdateThenDeleteCleansBlock(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	did := acct.Did
	rkey := "r1"
	mustApply(t, s, did, Op{
		Type:       OpTypeCreate,
		Collection: "app.bsky.feed.post",
		Rkey:       &rkey,
		Record:     rmPostRecord("v1"),
	})
	v1 := walkMstLeaves(t, s, did)["app.bsky.feed.post/r1"]

	urepo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	if _, err := s.repoman.applyWrites(context.Background(), urepo.Repo, []Op{
		{Type: OpTypeUpdate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: rmPostRecord("v2")},
		{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: &rkey},
	}, nil); err != nil {
		t.Fatalf("applyWrites update+delete: %v", err)
	}

	if blockstoreHas(t, s, did, v1) {
		t.Fatal("old record block still present after update+delete batch")
	}
	if _, ok := walkMstLeaves(t, s, did)["app.bsky.feed.post/r1"]; ok {
		t.Fatal("record still in MST after update+delete batch")
	}
}

// TestComputeRemovedCids unit-tests the diff helper directly.
func TestComputeRemovedCids(t *testing.T) {
	// mkcid builds a valid CIDv1 (dag-cbor, sha2-256) from arbitrary bytes.
	mkcid := func(s string) cid.Cid {
		pref := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
		c, err := pref.Sum([]byte(s))
		if err != nil {
			t.Fatalf("sum: %v", err)
		}
		return c
	}

	// leaf returns the leaf CID a build() tree assigned to the given key.
	leaf := func(key string) cid.Cid { return mkcid("leaf-" + key) }

	build := func(keys ...string) *mst.Node {
		tree := mst.NewEmptyTree()
		for _, k := range keys {
			if _, err := tree.Insert([]byte(k), leaf(k)); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
		if _, err := tree.RootCID(); err != nil {
			t.Fatalf("root: %v", err)
		}
		return tree.Root
	}

	newRoot := mkcid("new-root")
	prevRoot := mkcid("prev-root")
	newBlock := mkcid("new-block")

	t.Run("identical trees remove nothing", func(t *testing.T) {
		n := build("app.bsky.feed.post/aaa")
		removed := computeRemovedCids(n, n, nil, nil, newRoot)
		if len(removed) != 0 {
			t.Fatalf("expected no removals, got %v", removed)
		}
	})

	t.Run("superseded node and prev commit removed", func(t *testing.T) {
		prev := build("app.bsky.feed.post/aaa", "app.bsky.feed.post/bbb")
		curr := build("app.bsky.feed.post/aaa", "app.bsky.feed.post/ccc")
		removed := computeRemovedCids(prev, curr, []cid.Cid{prevRoot}, nil, newRoot)
		set := map[cid.Cid]bool{}
		for _, c := range removed {
			set[c] = true
		}
		if !set[prevRoot] {
			t.Fatalf("prev commit not removed: %v", removed)
		}
		if !set[leaf("app.bsky.feed.post/bbb")] {
			t.Fatalf("bbb record block not removed: %v", removed)
		}
		// aaa's leaf (index 0) must be kept in both trees
		if set[leaf("app.bsky.feed.post/aaa")] {
			t.Fatalf("live leaf removed: %v", removed)
		}
	})

	t.Run("unlinked new block removed", func(t *testing.T) {
		n := build("app.bsky.feed.post/aaa")
		removed := computeRemovedCids(n, n, nil, []cid.Cid{newBlock}, newRoot)
		if len(removed) != 1 || removed[0] != newBlock {
			t.Fatalf("expected only the unlinked new block removed, got %v", removed)
		}
	})

	t.Run("new root always kept", func(t *testing.T) {
		prev := build("app.bsky.feed.post/aaa")
		curr := build("app.bsky.feed.post/aaa")
		removed := computeRemovedCids(prev, curr, []cid.Cid{newRoot}, []cid.Cid{newRoot}, newRoot)
		for _, c := range removed {
			if c == newRoot {
				t.Fatalf("new root removed: %v", removed)
			}
		}
	})
}

// TestApplyWritesRepoStillVerifies asserts the repo opens, the MST verifies,
// the commit signature verifies, and every record block is readable from the
// blockstore after superseded blocks have been removed.
func TestApplyWritesRepoStillVerifies(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	ctx := context.Background()

	var ops []Op
	rkeys := []string{"aaaa", "cccc", "eeee", "gggg", "iiii", "kkkk"}
	for _, rk := range rkeys {
		ops = append(ops, Op{
			Type:       OpTypeCreate,
			Collection: "app.bsky.feed.post",
			Rkey:       &rk,
			Record:     rmPostRecord(fmt.Sprintf("post %s", rk)),
		})
	}
	mustApply(t, s, acct.Did, ops...)

	// churn the tree so superseded blocks are actually created and removed
	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeUpdate,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("cccc"),
		Record:     rmPostRecord("updated"),
	})
	mustApply(t, s, acct.Did, Op{
		Type:       OpTypeDelete,
		Collection: "app.bsky.feed.post",
		Rkey:       strPtr("gggg"),
	})

	root := currentRoot(t, s, acct.Did)
	bs := s.getBlockstore(acct.Did)

	r, err := openRepo(ctx, bs, root, acct.Did)
	if err != nil {
		t.Fatalf("open repo from current root: %v", err)
	}

	// MST structural verification
	if err := r.MST.Verify(); err != nil {
		t.Fatalf("mst verify: %v", err)
	}

	// commit signature verification
	blk, err := bs.Get(ctx, root)
	if err != nil {
		t.Fatalf("get commit block: %v", err)
	}
	var commit atp.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(blk.RawData())); err != nil {
		t.Fatalf("unmarshal commit: %v", err)
	}
	priv, err := atcrypto.ParsePrivateBytesK256(acct.SigningKey)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if err := commit.VerifySignature(pub); err != nil {
		t.Fatalf("commit signature verification failed: %v", err)
	}
	mstRoot, err := r.MST.RootCID()
	if err != nil {
		t.Fatalf("mst root: %v", err)
	}
	if commit.Data != *mstRoot {
		t.Fatalf("commit data root %s does not match MST root %s", commit.Data, mstRoot)
	}

	// every leaf record block must still be readable
	leaves := walkMstLeaves(t, s, acct.Did)
	if len(leaves) != len(rkeys)-1 {
		t.Fatalf("unexpected leaf count: %d", len(leaves))
	}
	for path, c := range leaves {
		if _, err := bs.Get(ctx, c); err != nil {
			t.Fatalf("record block %s for %s missing: %v", c, path, err)
		}
	}
}
