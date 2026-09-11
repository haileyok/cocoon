package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
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
	evtman, persister := newTestEvtmanPersister(t)
	s.evtman = evtman
	// The handler consults the persister for the retained seq range, so tests
	// must wire the same instance the event manager writes through.
	s.evtpersister = persister
	s.repoman = NewRepoMan(s)
	return s
}

// startSubscribeReposServer stands up a real HTTP server hosting the handler and
// returns the websocket URL. Tests that need query parameters (a cursor) dial
// the returned URL directly.
func startSubscribeReposServer(t *testing.T, s *Server) string {
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

	return "ws://" + ln.Addr().String() + "/xrpc/com.atproto.sync.subscribeRepos"
}

// serveSubscribeRepos stands up a real HTTP server hosting the handler and
// returns a dialer for it.
func serveSubscribeRepos(t *testing.T, s *Server) func(ua string) *websocket.Conn {
	t.Helper()

	url := startSubscribeReposServer(t, s)
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

// dialSubscribeRepos connects to the handler, optionally naming a cursor.
func dialSubscribeRepos(t *testing.T, url string, cursor *int64) *websocket.Conn {
	t.Helper()
	if cursor != nil {
		url = fmt.Sprintf("%s?cursor=%d", url, *cursor)
	}
	hdr := http.Header{}
	hdr.Set("User-Agent", "relay/cursor-test")
	c, _, err := websocket.DefaultDialer.Dial(url, hdr)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	return c
}

// wsFrame is one decoded websocket frame: the CBOR event header plus the
// undecoded body bytes.
type wsFrame struct {
	header events.EventHeader
	body   []byte
}

// readWSFrame reads one frame and splits it into header and body.
func readWSFrame(t *testing.T, c *websocket.Conn) wsFrame {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read message: %v", err)
	}

	r := bytes.NewReader(data)
	var header events.EventHeader
	if err := header.UnmarshalCBOR(r); err != nil {
		t.Fatalf("decode event header: %v", err)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read frame body: %v", err)
	}

	return wsFrame{header: header, body: body}
}

func (f wsFrame) decodeError(t *testing.T) events.ErrorFrame {
	t.Helper()
	var ef events.ErrorFrame
	if err := ef.UnmarshalCBOR(bytes.NewReader(f.body)); err != nil {
		t.Fatalf("decode error frame: %v", err)
	}
	return ef
}

func (f wsFrame) decodeInfo(t *testing.T) comatproto.SyncSubscribeRepos_Info {
	t.Helper()
	var info comatproto.SyncSubscribeRepos_Info
	if err := info.UnmarshalCBOR(bytes.NewReader(f.body)); err != nil {
		t.Fatalf("decode info frame: %v", err)
	}
	return info
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

// wedgedPeer opens a websocket connection by hand, reads only the handshake
// response, and then stops reading forever without setting a deadline on its
// socket.
//
// This is the "stalled consumer" a reader error cannot detect: TCP stays
// healthy and open (the peer's receive window simply closes), so the server's
// read goroutine never errors, while the server's writes block once the socket
// buffers fill. A polling client from a library is unsuitable here — it sets
// read deadlines, and once it becomes unreachable its finalizer closes the
// socket, which the server observes as an ordinary disconnect instead.
//
// The returned conn must be kept reachable (runtime.KeepAlive) for the duration
// of the test, or the finalizer will close it.
func wedgedPeer(t *testing.T, addr string) net.Conn {
	t.Helper()

	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/xrpc/com.atproto.sync.subscribeRepos", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("User-Agent", "relay/wedged-peer")

	if err := req.Write(nc); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	// Read just the handshake response, then never read again.
	_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	if _, err := nc.Read(buf); err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	_ = nc.SetReadDeadline(time.Time{})

	return nc
}

// TestSubscribeReposWriteDeadlineUnwindsOnWedgedPeer covers the failure a reader
// error cannot detect: a relay that stays connected but stops reading. The
// socket buffers fill, the synchronous frame write blocks, and no read error
// fires — so only a write deadline can unpin the handler.
//
// Regression test for a handler that stayed blocked inside the write path
// forever, never reaching its deferred evtManCancel/conn.Close.
func TestSubscribeReposWriteDeadlineUnwindsOnWedgedPeer(t *testing.T) {
	defer func(prev time.Duration) { wsWriteTimeout = prev }(wsWriteTimeout)
	wsWriteTimeout = 1 * time.Second

	s := newSubscribeTestServer(t)

	e := echo.New()
	e.GET("/xrpc/com.atproto.sync.subscribeRepos", s.handleSyncSubscribeRepos)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: e}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	nc := wedgedPeer(t, ln.Addr().String())
	defer func() {
		runtime.KeepAlive(nc)
		_ = nc.Close()
	}()

	// Wait for the server to register the subscriber. The peer is not reading,
	// so we cannot wait on a received event.
	deadline := time.Now().Add(10 * time.Second)
	for handlerGoroutines() == 0 {
		emitAccountEvent(s)
		if time.Now().After(deadline) {
			t.Fatal("handler never registered a subscriber")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Flood payloads large enough to fill the socket buffers and block the
	// server's write. The handler must unpin itself via the write deadline.
	big := strings.Repeat("x", 256*1024)
	unpinBy := time.Now().Add(30 * time.Second)
	for i := 0; i < 20000; i++ {
		s.evtman.AddEvent(context.Background(), &events.XRPCStreamEvent{
			RepoAccount: &comatproto.SyncSubscribeRepos_Account{
				Active: true,
				Did:    "did:plc:wedged",
				Status: &big,
				Time:   time.Now().Format(time.RFC3339),
			},
		})

		if handlerGoroutines() == 0 {
			break
		}
		if time.Now().After(unpinBy) {
			t.Fatalf("handler still pinned by a non-reading peer: a blocked write must not outlive the write deadline")
		}
	}

	if got := gaugeRelaysConnected(t); got != 0 {
		t.Errorf("cocoon_relays_connected = %v, want 0 after the wedged peer forced a teardown", got)
	}
}

// TestSubscribeReposPingsAnIdleStream asserts the handler keeps a silent stream
// observably alive on its own schedule. An idle PDS emits nothing, and a
// websocket carrying no traffic in either direction is dropped by middleboxes —
// and read as a dead host by a consumer whose liveness check only resets on a
// pong. Without server-initiated pings, a quiet cocoon is indistinguishable
// from a down one.
func TestSubscribeReposPingsAnIdleStream(t *testing.T) {
	defer func(prev time.Duration) { wsPingInterval = prev }(wsPingInterval)
	wsPingInterval = 200 * time.Millisecond

	s := newSubscribeTestServer(t)
	dial := serveSubscribeRepos(t, s)

	c := dial("relay/idle-ping")
	defer c.Close()

	// Record pings as they arrive. A read timeout is fatal on a gorilla client
	// (a second read panics), so this blocks on one read while control frames
	// are dispatched to the handler.
	var pings atomic.Int32
	c.SetPingHandler(func(string) error {
		pings.Add(1)
		return nil
	})

	// No events are emitted at all: the ping must arrive on its own.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, _ = c.ReadMessage()

	if got := pings.Load(); got == 0 {
		t.Fatal("idle stream received no ping; a silent connection would be dropped upstream")
	}
}

// TestSubscribeReposClosesGracefully asserts the handler sends a websocket close
// frame before tearing the connection down.
//
// A bare TCP close carries no close code, so the peer surfaces it as
// "close 1006 (abnormal closure): unexpected EOF" — the same shape as a crash.
// A routine teardown must look like a normal going-away instead.
//
// The teardown here is server-initiated: the client handshakes and then never
// answers a ping, so the handler reaps it. That path exists only because the
// read deadline is enforced, and the close frame exists only because the
// teardown announces itself.
func TestSubscribeReposClosesGracefully(t *testing.T) {
	defer func(pi, pt time.Duration) {
		wsPingInterval, wsPongTimeout = pi, pt
	}(wsPingInterval, wsPongTimeout)
	wsPingInterval = 150 * time.Millisecond
	wsPongTimeout = 500 * time.Millisecond

	s := newSubscribeTestServer(t)
	dial := serveSubscribeRepos(t, s)

	c := dial("relay/graceful-close")
	defer c.Close()

	awaitFirstEvent(t, s, c)

	// Stay silent: read frames, but never answer the server's pings.
	c.SetPingHandler(func(string) error { return nil })

	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		mt, _, err := c.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway) {
				return // close frame arrived — correct
			}
			t.Fatalf("connection dropped without a close frame (relay would log 1006): %v", err)
		}
		if mt == websocket.CloseMessage {
			return
		}
	}
}

// TestSubscribeReposDetectsSilentPeer asserts a half-open connection is
// reaped. A peer that vanishes without a FIN produces no read error of its own,
// so only an unanswered ping — and the resulting read-deadline expiry — reveals
// that it is gone. Without this the handler sits on a dead socket, holding its
// event-manager subscription open indefinitely.
func TestSubscribeReposDetectsSilentPeer(t *testing.T) {
	defer func(pi, pt time.Duration) {
		wsPingInterval, wsPongTimeout = pi, pt
	}(wsPingInterval, wsPongTimeout)
	wsPingInterval = 150 * time.Millisecond
	wsPongTimeout = 500 * time.Millisecond

	s := newSubscribeTestServer(t)

	e := echo.New()
	e.GET("/xrpc/com.atproto.sync.subscribeRepos", s.handleSyncSubscribeRepos)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: e}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Handshake, then go silent: never answer a ping, never send anything.
	nc := wedgedPeer(t, ln.Addr().String())
	defer func() {
		runtime.KeepAlive(nc)
		_ = nc.Close()
	}()

	deadline := time.Now().Add(10 * time.Second)
	for handlerGoroutines() == 0 {
		emitAccountEvent(s)
		if time.Now().After(deadline) {
			t.Fatal("handler never registered a subscriber")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The silent peer must be reaped once its pongs stop arriving, with no
	// in-band signal of any kind to prompt it.
	reaped := time.Now().Add(15 * time.Second)
	for handlerGoroutines() != 0 {
		if time.Now().After(reaped) {
			t.Fatal("handler never reaped a silent peer: an unanswered ping must expire the read deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if got := gaugeRelaysConnected(t); got != 0 {
		t.Errorf("cocoon_relays_connected = %v, want 0 after a silent peer was reaped", got)
	}
}

// seedEvents writes n events through the persister and returns their seqs.
func seedEvents(t *testing.T, s *Server, n int) (oldest, newest int64) {
	t.Helper()
	for i := 0; i < n; i++ {
		emitAccountEvent(s)
	}
	o, nn, ok, err := s.evtpersister.EventSeqRange(context.Background())
	if err != nil {
		t.Fatalf("event seq range: %v", err)
	}
	if !ok {
		t.Fatal("no events retained after seeding")
	}
	return o, nn
}

// TestSubscribeReposSignalsOutdatedCursor asserts a cursor behind the retained
// window is reported with an #info frame naming OutdatedCursor, before any
// event is served.
//
// Without it, playback silently starts at the oldest retained event: the
// consumer is never told that the events it asked for were pruned, so a gap in
// its view of the repo is indistinguishable from "nothing happened". The
// reference PDS emits exactly this frame for exactly this case.
func TestSubscribeReposSignalsOutdatedCursor(t *testing.T) {
	s := newSubscribeTestServer(t)
	oldest, _ := seedEvents(t, s, 5)

	url := startSubscribeReposServer(t, s)
	stale := oldest - 100
	c := dialSubscribeRepos(t, url, &stale)
	defer c.Close()

	f := readWSFrame(t, c)
	if f.header.Op != events.EvtKindMessage || f.header.MsgType != "#info" {
		t.Fatalf("frame = {op:%d t:%q}, want an #info message frame", f.header.Op, f.header.MsgType)
	}
	info := f.decodeInfo(t)
	if info.Name != "OutdatedCursor" {
		t.Errorf("#info name = %q, want OutdatedCursor", info.Name)
	}
	// The lexicon makes the message optional, but the reference sends one and a
	// consumer logs it verbatim, so a silent notice would be a regression in the
	// operator's ability to tell why their cursor was rejected.
	if info.Message == nil || *info.Message == "" {
		t.Error("#info frame carries no message")
	}
}

// TestSubscribeReposDoesNotSignalOutdatedCursorWithinWindow asserts the notice
// is not sent to a consumer whose next event is still retained. A false
// OutdatedCursor tells a consumer it lost events when it did not.
//
// The boundary is the interesting part: a cursor of oldest-1 needs oldest,
// which we still hold, so it is fully served and must stay quiet.
func TestSubscribeReposDoesNotSignalOutdatedCursorWithinWindow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		offset   int64 // added to oldest to form the cursor
		wantInfo bool
	}{
		{"exactly_at_oldest", 0, false},
		{"one_below_oldest_still_served", -1, false},
		{"two_below_oldest_first_gap", -2, true},
		{"far_below_oldest", -50, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSubscribeTestServer(t)
			oldest, _ := seedEvents(t, s, 5)

			url := startSubscribeReposServer(t, s)
			cursor := oldest + tc.offset
			c := dialSubscribeRepos(t, url, &cursor)
			defer c.Close()

			// The stream is live regardless: the sentinel, when present, is the
			// first frame. Give the handler a moment to write it if it will.
			gotInfo := false
			for i := 0; i < 5; i++ {
				emitAccountEvent(s)
				if err := c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
					t.Fatalf("set deadline: %v", err)
				}
				_, data, err := c.ReadMessage()
				if err != nil {
					break
				}
				// Don't consume the stream further; a single frame is enough to
				// tell whether a sentinel was emitted first.
				r := bytes.NewReader(data)
				var header events.EventHeader
				if err := header.UnmarshalCBOR(r); err != nil {
					t.Fatalf("decode header: %v", err)
				}
				if header.Op == events.EvtKindMessage && header.MsgType == "#info" {
					gotInfo = true
				}
				break
			}

			if gotInfo != tc.wantInfo {
				t.Errorf("cursor=%d (oldest=%d): OutdatedCursor sent = %v, want %v",
					cursor, oldest, gotInfo, tc.wantInfo)
			}
		})
	}
}

// TestSubscribeReposSignalsFutureCursor asserts a cursor ahead of every event we
// have is refused with a FutureCursor error frame, and that the connection is
// then closed rather than left open on a stream that can never produce an event
// above that seq.
//
// This is the case that silently hangs a consumer: nothing above the cursor can
// ever be sent, so without a refusal the consumer waits forever. The relay
// treats FutureCursor as "drop the connection and reset this host to idle",
// which is the recovery path. (cmd/relay/relay/slurper.go)
func TestSubscribeReposSignalsFutureCursor(t *testing.T) {
	s := newSubscribeTestServer(t)
	_, newest := seedEvents(t, s, 3)

	url := startSubscribeReposServer(t, s)
	ahead := newest + 1_000_000
	c := dialSubscribeRepos(t, url, &ahead)
	defer c.Close()

	f := readWSFrame(t, c)
	if f.header.Op != events.EvtKindErrorFrame {
		t.Fatalf("frame op = %d, want %d (error frame)", f.header.Op, events.EvtKindErrorFrame)
	}
	ef := f.decodeError(t)
	if ef.Error != "FutureCursor" {
		t.Errorf("error frame name = %q, want FutureCursor", ef.Error)
	}

	// The handler must not keep the stream open: there is nothing it could ever
	// send. The close frame proves the teardown is deliberate.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := c.SetReadDeadline(deadline); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		_, _, err := c.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseGoingAway) &&
				!websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				t.Fatalf("stream ended without a deliberate close: %v", err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("future cursor: handler left the connection open")
		}
	}
}

// TestSubscribeReposCursorAtNewestIsServed asserts the ordinary caught-up case
// stays silent. The relay sits here most of the time — its cursor equals the
// newest seq — so warning on it would spam every healthy reconnect.
func TestSubscribeReposCursorAtNewestIsServed(t *testing.T) {
	s := newSubscribeTestServer(t)
	_, newest := seedEvents(t, s, 4)

	url := startSubscribeReposServer(t, s)
	c := dialSubscribeRepos(t, url, &newest)
	defer c.Close()

	// Push a fresh event; the consumer must receive stream content, not a
	// cursor notice.
	emitAccountEvent(s)

	f := readWSFrame(t, c)
	if f.header.Op == events.EvtKindErrorFrame {
		t.Fatalf("caught-up consumer was refused: %+v", f.decodeError(t))
	}
	if f.header.Op == events.EvtKindMessage && f.header.MsgType == "#info" {
		if info := f.decodeInfo(t); info.Name == "OutdatedCursor" {
			t.Fatal("caught-up consumer was sent OutdatedCursor; its next event was retained")
		}
	}
}

// TestSubscribeReposNoCursorIsSilent asserts a fresh consumer with no cursor
// gets no notice: it is asking for "from now on", and it has lost nothing.
func TestSubscribeReposNoCursorIsSilent(t *testing.T) {
	s := newSubscribeTestServer(t)
	seedEvents(t, s, 3)

	url := startSubscribeReposServer(t, s)
	c := dialSubscribeRepos(t, url, nil)
	defer c.Close()

	emitAccountEvent(s)

	f := readWSFrame(t, c)
	if f.header.Op == events.EvtKindErrorFrame {
		t.Fatalf("cursorless consumer was refused: %+v", f.decodeError(t))
	}
	if f.header.Op == events.EvtKindMessage && f.header.MsgType == "#info" {
		if info := f.decodeInfo(t); info.Name == "OutdatedCursor" {
			t.Fatal("cursorless consumer was sent OutdatedCursor; it has no cursor to be behind")
		}
	}
}

// TestSubscribeReposEmptyStoreServesNoCursorNotice asserts a host with no
// retained events does not claim the cursor is outdated. On a fresh store every
// cursor is "ahead" of nothing, and reporting a failure the consumer cannot act
// on would make an empty PDS look broken.
func TestSubscribeReposEmptyStoreServesNoCursorNotice(t *testing.T) {
	s := newSubscribeTestServer(t)

	url := startSubscribeReposServer(t, s)
	cursor := int64(1)
	c := dialSubscribeRepos(t, url, &cursor)
	defer c.Close()

	emitAccountEvent(s)

	f := readWSFrame(t, c)
	if f.header.Op == events.EvtKindErrorFrame {
		t.Fatalf("first-ever consumer was refused on an empty store: %+v", f.decodeError(t))
	}
}

// TestEventSeqRangeReportsRetainedBounds covers the query directly: an empty
// store reports ok=false, and a populated one reports the true floor and
// ceiling so the handler's comparison is against real retained bounds.
func TestEventSeqRangeReportsRetainedBounds(t *testing.T) {
	s := newSubscribeTestServer(t)
	ctx := context.Background()

	if _, _, ok, err := s.evtpersister.EventSeqRange(ctx); err != nil {
		t.Fatalf("empty store: %v", err)
	} else if ok {
		t.Fatal("empty store reported a retained range")
	}

	oldest, newest := seedEvents(t, s, 3)
	if oldest >= newest {
		t.Fatalf("range = [%d,%d], want oldest < newest", oldest, newest)
	}

	gotOldest, gotNewest, ok, err := s.evtpersister.EventSeqRange(ctx)
	if err != nil {
		t.Fatalf("populated store: %v", err)
	}
	if !ok {
		t.Fatal("populated store reported no retained range")
	}
	if gotOldest != oldest || gotNewest != newest {
		t.Errorf("range = [%d,%d], want [%d,%d]", gotOldest, gotNewest, oldest, newest)
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
