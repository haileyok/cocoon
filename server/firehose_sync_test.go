package server

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/ipfs/go-cid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func newTestEvtman(t *testing.T) *events.EventManager {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "events.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open events db: %v", err)
	}
	p, err := NewDbPersister(gdb, time.Hour)
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}
	return events.NewEventManager(p)
}

// seedGenesisRepo commits an empty repo for did and records it as the head.
func (s *Server) seedGenesisRepo(t *testing.T, did string, signingKey []byte) (cid.Cid, string) {
	t.Helper()
	bs := s.getBlockstore(did)
	clk := syntax.NewTIDClock(0)
	r := &atp.Repo{
		DID:         syntax.DID(did),
		Clock:       clk,
		MST:         mst.NewEmptyTree(),
		RecordStore: bs,
	}
	root, rev, err := commitRepo(context.Background(), bs, r, signingKey)
	if err != nil {
		t.Fatalf("commit genesis: %v", err)
	}
	if err := s.UpdateRepo(context.Background(), did, root, rev); err != nil {
		t.Fatalf("update repo: %v", err)
	}
	return root, rev
}

func TestSubscribeReposMsgType(t *testing.T) {
	cases := []struct {
		evt  *events.XRPCStreamEvent
		want string
	}{
		{&events.XRPCStreamEvent{RepoCommit: &atproto.SyncSubscribeRepos_Commit{}}, "#commit"},
		{&events.XRPCStreamEvent{RepoSync: &atproto.SyncSubscribeRepos_Sync{}}, "#sync"},
		{&events.XRPCStreamEvent{RepoIdentity: &atproto.SyncSubscribeRepos_Identity{}}, "#identity"},
		{&events.XRPCStreamEvent{RepoAccount: &atproto.SyncSubscribeRepos_Account{}}, "#account"},
		{&events.XRPCStreamEvent{RepoInfo: &atproto.SyncSubscribeRepos_Info{}}, "#info"},
	}
	for _, c := range cases {
		mt, obj, ok := subscribeReposMsgType(c.evt)
		if !ok || mt != c.want {
			t.Fatalf("subscribeReposMsgType = (%q, ok=%v), want %q", mt, ok, c.want)
		}
		if obj == nil {
			t.Fatalf("obj is nil for %q", c.want)
		}
	}
	if _, _, ok := subscribeReposMsgType(&events.XRPCStreamEvent{}); ok {
		t.Fatal("expected ok=false for an empty event")
	}
}

// TestApplyWritesEmitsPrevData asserts the #commit firehose event advertises
// the previous commit's MST root as prevData.
func TestApplyWritesEmitsPrevData(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "alice.pds.test")
	root, _ := s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	ctx := context.Background()
	urepo, err := s.getRepoActorByDid(ctx, acct.Did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}

	evts, cancel, err := s.evtman.Subscribe(ctx, "test", func(*events.XRPCStreamEvent) bool { return true }, nil)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()

	rec := MarshalableMap{
		"$type":     "app.bsky.feed.post",
		"text":      "hello world",
		"createdAt": "2024-01-01T00:00:00Z",
	}
	if _, err := s.repoman.applyWrites(ctx, urepo.Repo, []Op{{
		Type:       OpTypeCreate,
		Collection: "app.bsky.feed.post",
		Record:     &rec,
	}}, nil); err != nil {
		t.Fatalf("applyWrites: %v", err)
	}

	wantPrev, err := readCommitData(ctx, s.getBlockstore(acct.Did), root)
	if err != nil {
		t.Fatalf("readCommitData: %v", err)
	}

	select {
	case evt := <-evts:
		if evt.RepoCommit == nil {
			t.Fatalf("expected a #commit event, got %+v", evt)
		}
		if evt.RepoCommit.PrevData == nil {
			t.Fatal("RepoCommit.PrevData is nil; want the previous commit's MST root")
		}
		if got := cid.Cid(*evt.RepoCommit.PrevData); got != wantPrev {
			t.Fatalf("prevData = %s, want %s", got, wantPrev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for #commit event")
	}
}

// TestActivateAccountEmitsRepoSync asserts account activation broadcasts a
// #sync event announcing the repo's current head.
func TestActivateAccountEmitsRepoSync(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	acct := s.createTestAccount(t, "bob.pds.test")
	_, rev := s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	ctx := context.Background()
	urepo, err := s.getRepoActorByDid(ctx, acct.Did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}

	evts, cancel, err := s.evtman.Subscribe(ctx, "test", func(*events.XRPCStreamEvent) bool { return true }, nil)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()

	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.activateAccount", "", nil)
	e.Set("repo", urepo)
	if err := s.handleServerActivateAccount(e); err != nil {
		t.Fatalf("handleServerActivateAccount: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case evt := <-evts:
			if evt.RepoSync == nil {
				continue
			}
			if evt.RepoSync.Did != acct.Did {
				t.Fatalf("sync did = %s, want %s", evt.RepoSync.Did, acct.Did)
			}
			if evt.RepoSync.Rev != rev {
				t.Fatalf("sync rev = %s, want %s", evt.RepoSync.Rev, rev)
			}
			if len(evt.RepoSync.Blocks) == 0 {
				t.Fatal("sync blocks are empty; want a CAR with the commit block")
			}
			return
		case <-deadline:
			t.Fatal("did not observe a #sync event after activation")
		}
	}
}
