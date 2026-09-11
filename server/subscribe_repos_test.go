package server

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/events"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
)

// Regression tests for the com.atproto.sync.subscribeRepos websocket handler
// (server/handle_sync_subscribe_repos.go) and the #commit op encoding
// (server/repo.go).

func handlerGoroutines() int {
	buf := make([]byte, 1<<22)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "(*Server).handleSyncSubscribeRepos(")
}

func gaugeRelaysConnected(t *testing.T) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	total := 0.0
	for _, mf := range mfs {
		if mf.GetName() != "cocoon_relays_connected" {
			continue
		}
		for _, m := range mf.GetMetric() {
			total += m.GetGauge().GetValue()
		}
	}
	return total
}

func counterTotal(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	total := 0.0
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

func newSubscribeTestServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	return s
}

// serveSubscribeRepos stands up a real HTTP server hosting the handler and
// returns a dialer for it.
func serveSubscribeRepos(t *testing.T, s *Server) func(ua string) *websocket.Conn {
	t.Helper()

	e := echo.New()
	e.GET("/xrpc/com.atproto.sync.subscribeRepos", s.handleSyncSubscribeRepos)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: e}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	url := "ws://" + ln.Addr().String() + "/xrpc/com.atproto.sync.subscribeRepos"
	return func(ua string) *websocket.Conn {
		t.Helper()
		hdr := http.Header{}
		hdr.Set("User-Agent", ua)
		c, _, err := websocket.DefaultDialer.Dial(url, hdr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return c
	}
}

func emitAccountEvent(s *Server) {
	s.evtman.AddEvent(context.Background(), &events.XRPCStreamEvent{
		RepoAccount: &comatproto.SyncSubscribeRepos_Account{
			Active: true,
			Did:    "did:plc:retire",
			Time:   time.Now().Format(time.RFC3339),
		},
	})
}

// awaitFirstEvent pumps events until the connected client receives one, proving
// the handler has registered its subscriber and is writing frames.
func awaitFirstEvent(t *testing.T, s *Server, c *websocket.Conn) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		emitAccountEvent(s)
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err := c.ReadMessage(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("client never received an event; harness broken")
		}
	}
}

// TestSubscribeReposRetiresSubscriberAfterDisconnect asserts the handler
// unwinds and releases everything it holds once the relay goes away:
//
//   - the event-manager subscription stops receiving broadcasts,
//   - the handler goroutine exits,
//   - cocoon_relays_connected is decremented back to zero.
//
// Regression test for a deadlock: the send loop ranged over the event channel,
// which is closed only by the deferred evtManCancel in that same goroutine, so
// cancelling the request context never unwound it.
func TestSubscribeReposRetiresSubscriberAfterDisconnect(t *testing.T) {
	s := newSubscribeTestServer(t)
	dial := serveSubscribeRepos(t, s)

	c := dial("relay/1.0")
	awaitFirstEvent(t, s, c)

	if got := gaugeRelaysConnected(t); got != 1 {
		t.Fatalf("connected: cocoon_relays_connected = %v, want 1", got)
	}

	// The relay goes away.
	_ = c.Close()

	// The handler must unwind on its own, without needing any further events
	// to be broadcast.
	deadline := time.Now().Add(10 * time.Second)
	for handlerGoroutines() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("handler goroutine never unwound after disconnect: %d still parked", handlerGoroutines())
		}
		time.Sleep(50 * time.Millisecond)
	}

	if got := gaugeRelaysConnected(t); got != 0 {
		t.Errorf("cocoon_relays_connected = %v, want 0 (gauge must not accumulate across reconnects)", got)
	}

	// And the retired subscription must not keep absorbing broadcasts.
	enqueuedBefore := counterTotal(t, "indigo_events_enqueued_for_broadcast_total")
	for i := 0; i < 500; i++ {
		emitAccountEvent(s)
	}
	time.Sleep(500 * time.Millisecond)
	enqueuedAfter := counterTotal(t, "indigo_events_enqueued_for_broadcast_total")

	if delta := enqueuedAfter - enqueuedBefore; delta != 0 {
		t.Errorf("retired subscriber still receiving broadcasts: %.0f events enqueued after disconnect (want 0)", delta)
	}
}

// TestSubscribeReposGaugeDoesNotAccumulateAcrossReconnects drives several
// connect/disconnect cycles — the pattern a flapping relay produces — and
// asserts the connection gauge returns to zero each time.
func TestSubscribeReposGaugeDoesNotAccumulateAcrossReconnects(t *testing.T) {
	s := newSubscribeTestServer(t)
	dial := serveSubscribeRepos(t, s)

	const cycles = 4
	for i := 0; i < cycles; i++ {
		c := dial("relay/1.0")
		awaitFirstEvent(t, s, c)

		if got := gaugeRelaysConnected(t); got != 1 {
			t.Fatalf("cycle %d connected: cocoon_relays_connected = %v, want 1", i+1, got)
		}

		_ = c.Close()

		deadline := time.Now().Add(10 * time.Second)
		for gaugeRelaysConnected(t) != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("cycle %d: gauge stuck at %v after disconnect, want 0", i+1, gaugeRelaysConnected(t))
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	if n := handlerGoroutines(); n != 0 {
		t.Errorf("%d handler goroutine(s) leaked across %d reconnect cycles", n, cycles)
	}
}

// TestCommitUpdateOpCarriesPrev asserts #commit frames advertise the superseded
// record CID for updates, as the lexicon requires, and that its absence no
// longer causes the relay's verifier to skip prevData/MST inversion.
func TestCommitUpdateOpCarriesPrev(t *testing.T) {
	s := newSubscribeTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

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

	recvCommit := func() *comatproto.SyncSubscribeRepos_Commit {
		t.Helper()
		for {
			select {
			case e := <-evts:
				if e.RepoCommit != nil {
					return e.RepoCommit
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for #commit")
			}
		}
	}

	rkey := "3laaaaaaaaa2x"
	rec := MarshalableMap{"$type": "app.bsky.feed.post", "text": "v1", "createdAt": "2024-01-01T00:00:00Z"}
	if _, err := s.repoman.applyWrites(ctx, urepo.Repo, []Op{{
		Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: &rec,
	}}, nil); err != nil {
		t.Fatalf("create: %v", err)
	}

	createEvt := recvCommit()
	if len(createEvt.Ops) != 1 {
		t.Fatalf("create event ops = %d, want 1", len(createEvt.Ops))
	}
	if got := createEvt.Ops[0]; got.Action != "create" {
		t.Fatalf("op action = %q, want %q", got.Action, "create")
	} else if got.Prev != nil {
		t.Errorf("create op must not carry prev, got %v", got.Prev)
	}
	createdCid := *createEvt.Ops[0].Cid

	urepo, err = s.getRepoActorByDid(ctx, acct.Did)
	if err != nil {
		t.Fatalf("reload repo: %v", err)
	}
	rec2 := MarshalableMap{"$type": "app.bsky.feed.post", "text": "v2", "createdAt": "2024-01-01T00:00:01Z"}
	if _, err := s.repoman.applyWrites(ctx, urepo.Repo, []Op{{
		Type: OpTypeUpdate, Collection: "app.bsky.feed.post", Rkey: &rkey, Record: &rec2,
	}}, nil); err != nil {
		t.Fatalf("update: %v", err)
	}
	updEvt := recvCommit()

	if len(updEvt.Ops) != 1 {
		t.Fatalf("update event ops = %d, want 1", len(updEvt.Ops))
	}
	op := updEvt.Ops[0]
	if op.Action != "update" {
		t.Fatalf("op action = %q, want %q", op.Action, "update")
	}
	if op.Prev == nil {
		t.Fatal("update op carries no prev CID; the lexicon requires it for updates")
	}
	if *op.Prev != createdCid {
		t.Errorf("update op prev = %v, want the superseded record CID %v", *op.Prev, createdCid)
	}
	if op.Cid == nil || *op.Cid == *op.Prev {
		t.Errorf("update op cid = %v, want a CID distinct from prev %v", op.Cid, *op.Prev)
	}

	// The relay's own verification path must now run the prevData/MST
	// inversion rather than bailing out on a legacy-shaped op.
	msg := &comatproto.SyncSubscribeRepos_Commit{
		Repo:     acct.Did,
		Rev:      updEvt.Rev,
		Since:    updEvt.Since,
		Commit:   updEvt.Commit,
		PrevData: updEvt.PrevData,
		Blocks:   updEvt.Blocks,
		Ops:      updEvt.Ops,
		Time:     updEvt.Time,
	}
	if _, err := repo.VerifyCommitMessage(ctx, msg); err != nil {
		t.Fatalf("relay-style verification of the update commit failed: %v", err)
	}
}
