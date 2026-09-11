package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
)

// TestReproRelayConsecutiveDeletes drives many consecutive single-record
// deletes (the production pattern: every delete emits an event, each verified
// exactly like the Bluesky relay does with VerifyCommitMessage), on a large
// randomly-keyed tree, until the tree is empty — covering subtree merges and
// root collapses.
func TestReproRelayConsecutiveDeletes(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
	did := acct.Did

	const n = 150
	clk := syntax.NewTIDClock(0)
	rkeys := make([]string, n)
	ops := make([]Op, 0, n)
	for i := 0; i < n; i++ {
		rkeys[i] = clk.Next().String()
		ops = append(ops, Op{
			Type:       OpTypeCreate,
			Collection: "app.bsky.feed.post",
			Rkey:       &rkeys[i],
			Record:     rmPostRecord(fmt.Sprintf("post %d", i)),
		})
	}
	mustApply(t, s, did, ops...)

	evts, cancel, err := s.evtman.Subscribe(context.Background(), "test", func(*events.XRPCStreamEvent) bool { return true }, nil)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()

	recv := func() *comatproto.SyncSubscribeRepos_Commit {
		t.Helper()
		select {
		case e := <-evts:
			if e.RepoCommit == nil {
				t.Fatalf("expected #commit, got %+v", e)
			}
			return e.RepoCommit
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for #commit event")
			return nil
		}
	}

	verify := func(evt *comatproto.SyncSubscribeRepos_Commit, rk string) {
		t.Helper()
		msg := &comatproto.SyncSubscribeRepos_Commit{
			Repo:     did,
			Rev:      evt.Rev,
			Since:    evt.Since,
			Commit:   evt.Commit,
			PrevData: evt.PrevData,
			Blocks:   evt.Blocks,
			Ops:      evt.Ops,
			Time:     evt.Time,
		}
		if _, err := repo.VerifyCommitMessage(context.Background(), msg); err != nil {
			t.Fatalf("relay verification failed for delete of %s (rev %s): %v", rk, evt.Rev, err)
		}
	}

	// delete every record one commit at a time, in shuffled key order, so
	// subtrees merge and the root collapses as the tree drains
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	// deterministic shuffle
	shuffled := make([]string, 0, n)
	for i := 0; i < n; i++ {
		shuffled = append(shuffled, rkeys[(i*37)%n])
	}

	seen := map[string]bool{}
	for _, rk := range shuffled {
		if seen[rk] {
			continue
		}
		seen[rk] = true
		mustApply(t, s, did, Op{
			Type:       OpTypeDelete,
			Collection: "app.bsky.feed.post",
			Rkey:       &rk,
		})
		evt := recv()
		verify(evt, rk)
	}
}
