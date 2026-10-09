package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// newTestEvtmanPersister builds an event manager over a fresh events database
// and returns the persister alongside it, for tests that need to inspect the
// retained seq range the manager prunes.
func newTestEvtmanPersister(t *testing.T) (*events.EventManager, *DbPersister) {
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
	return events.NewEventManager(p), p
}

func newTestEvtman(t *testing.T) *events.EventManager {
	t.Helper()
	m, _ := newTestEvtmanPersister(t)
	return m
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

	// capture the expected prevData before the write: the previous commit's
	// MST root. (The previous commit block itself is deleted once superseded,
	// matching the reference PDS, so it cannot be read back afterwards.)
	wantPrev, err := readCommitData(ctx, s.getBlockstore(acct.Did), root)
	if err != nil {
		t.Fatalf("readCommitData: %v", err)
	}

	rec := MarshalableMap{
		"$type":     "app.bsky.feed.post",
		"text":      "hello world",
		"createdAt": "2024-01-01T00:00:00Z",
	}
	if _, err := s.repoman.applyWrites(ctx, urepo.Repo, []Op{{
		Type:       OpTypeCreate,
		Collection: "app.bsky.feed.post",
		Record:     &rec,
	}}, nil, nil); err != nil {
		t.Fatalf("applyWrites: %v", err)
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
	attachStatusDID(t, s, acct, acct.Did, "valid")
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

func TestInactiveWritesStayLocalUntilActivation(t *testing.T) {
	s, account := endpointTestServer(t)
	s.repoman = NewRepoMan(s)
	manager, persister := newTestEvtmanPersister(t)
	s.evtman = manager
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	attachStatusDID(t, s, account, account.Did, "valid")
	if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Update("deactivated", true).Error; err != nil {
		t.Fatal(err)
	}
	session, err := s.createSession(context.Background(), &mustRepoActor(t, s, account.Did).Repo)
	if err != nil {
		t.Fatal(err)
	}
	request := func(nsid string, body any) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/xrpc/com.atproto."+nsid, bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+session.AccessToken)
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", nsid, w.Code, w.Body.String())
		}
		return w
	}
	readEvents := func() []*events.XRPCStreamEvent {
		t.Helper()
		var got []*events.XRPCStreamEvent
		if err := persister.Playback(context.Background(), 0, func(evt *events.XRPCStreamEvent) error {
			got = append(got, evt)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	write := ComAtprotoRepoPutRecordInput{Repo: account.Did, Collection: "app.bsky.feed.post", Rkey: "kept", Record: postRecord("draft")}
	request("repo.createRecord", write)
	write.Record = postRecord("staged")
	w := request("repo.putRecord", write)
	var saved ApplyWriteResult
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	request("repo.applyWrites", ComAtprotoRepoApplyWritesInput{Repo: account.Did, Writes: []ComAtprotoRepoApplyWritesItem{
		{Type: OpTypeCreate.String(), Collection: write.Collection, Rkey: "removed", Value: rmPostRecord("temporary")},
	}})
	request("repo.deleteRecord", ComAtprotoRepoDeleteRecordInput{Repo: account.Did, Collection: write.Collection, Rkey: "removed"})
	staged := mustRepoActor(t, s, account.Did)
	leaves := walkMstLeaves(t, s, account.Did)
	if staged.Active() || saved.Cid == nil || len(leaves) != 1 || leaves[write.Collection+"/kept"].String() != *saved.Cid {
		t.Fatal("inactive writes did not preserve the staged repository")
	}
	if got := readEvents(); len(got) != 0 {
		t.Fatalf("inactive writes published %d events", len(got))
	}
	request("server.activateAccount", map[string]any{})
	got := readEvents()
	if len(got) != 3 || got[0].RepoAccount == nil || !got[0].RepoAccount.Active || got[1].RepoIdentity == nil || got[2].RepoSync == nil {
		t.Fatalf("expected account, identity, sync after activation: %+v", got)
	}
	syncEvent := got[2].RepoSync
	if syncEvent.Did != account.Did || syncEvent.Rev != staged.Rev {
		t.Fatalf("activation did not announce staged revision: %+v", syncEvent)
	}
	cr, err := car.NewCarReader(bytes.NewReader(syncEvent.Blocks))
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.Header.Roots) != 1 || !bytes.Equal(cr.Header.Roots[0].Bytes(), staged.Root) {
		t.Fatal("activation announced the wrong head")
	}
	write.Record = postRecord("public")
	request("repo.putRecord", write)
	got = readEvents()
	if len(got) != 4 || got[3].RepoCommit == nil || got[3].RepoCommit.Rev != currentRev(t, s, account.Did) {
		t.Fatal("active write did not publish its commit")
	}
	request("server.deactivateAccount", map[string]any{})
	write.Record = postRecord("private again")
	request("repo.putRecord", write)
	got = readEvents()
	if len(got) != 5 || got[4].RepoAccount == nil || got[4].RepoAccount.Active {
		t.Fatal("writes after deactivation published an event")
	}
}
