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

// TestReproRelayDeleteFuzz drives single-record deletes across a variety of
// tree shapes (sizes, key distributions, collection prefixes), verifying each
// #commit event exactly like the Bluesky relay (repo.VerifyCommitMessage).
// It hunts for the root-trim case: a delete that collapses the root to a
// single clean child whose CID was never written in this commit.
func TestReproRelayDeleteFuzz(t *testing.T) {
	collections := []string{
		"app.bsky.feed.post",
		"app.bsky.graph.follow",
		"app.bsky.feed.like",
		"com.example.custom",
	}

	for _, n := range []int{3, 5, 8, 13, 21, 34, 55, 89, 144, 233} {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			s := newTestServer(t)
			s.evtman = newTestEvtman(t)
			s.repoman = NewRepoMan(s)
			acct := s.createTestAccount(t, "alice.pds.test")
			s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
			did := acct.Did

			// spread records across collections with TID rkeys; varying the
			// collection prefix varies MST heights and tree shapes
			clk := syntax.NewTIDClock(0)
			type keyRef struct {
				collection string
				rkey       string
			}
			var keys []keyRef
			ops := make([]Op, 0, n)
			for i := 0; i < n; i++ {
				kr := keyRef{collection: collections[i%len(collections)], rkey: clk.Next().String()}
				keys = append(keys, kr)
				ops = append(ops, Op{
					Type:       OpTypeCreate,
					Collection: kr.collection,
					Rkey:       &kr.rkey,
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

			// delete in an interleaved order (different collection round-robin)
			// so different subtree shapes are hit on the way down
			for i := 0; i < n; i++ {
				kr := keys[(i*7)%n]
				mustApply(t, s, did, Op{
					Type:       OpTypeDelete,
					Collection: kr.collection,
					Rkey:       &kr.rkey,
				})
				evt := recv()
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
					t.Fatalf("n=%d i=%d: relay verification failed for delete of %s/%s (rev %s): %v",
						n, i, kr.collection, kr.rkey, evt.Rev, err)
				}
			}
		})
	}
}
