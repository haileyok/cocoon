package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bluesky-social/gttp"
	"github.com/haileyok/cocoon/identity"
	"github.com/labstack/echo/v4"
	"golang.org/x/net/dns/dnsmessage"
)

func proxyTestHTTPClient(t *testing.T, upstream *httptest.Server) *http.Client {
	t.Helper()
	tlsConfig := upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "example.com"
	client := newProxyHTTPClient(
		gttp.WithTLSConfig(tlsConfig),
		gttp.WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
			// Check before mapping public addresses to the loopback test server.
			if err := newProxyDialer().ControlContext(ctx, network, address, nil); err != nil {
				return nil, err
			}
			if address != "203.0.113.10:443" && address != "203.0.113.10:8443" && address != "203.0.113.11:443" {
				return nil, fmt.Errorf("unexpected dial: %s", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		}),
	)
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestProxyBlocksPrivateDestinations(t *testing.T) {
	var connections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"value":{"$type":"app.bsky.feed.generator","did":"did:web:generator.test"}}`)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	for _, method := range []string{"app.bsky.feed.getTimeline", "app.bsky.feed.getFeed"} {
		for _, initialized := range []bool{false, true} {
			for _, host := range []string{"127.0.0.1", "localhost"} {
				t.Run(fmt.Sprintf("%s/initialized=%t/%s", method, initialized, host), func(t *testing.T) {
					s := newTestServer(t)
					if initialized {
						s.proxyHTTPClient = defaultProxyHTTPClient
					}
					cache := identity.NewMemCache(10)
					if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
						Id: "did:web:appview.test", Service: []identity.DidDocService{{Id: "#view", ServiceEndpoint: strings.Replace(upstream.URL, "127.0.0.1", host, 1)}},
					}); err != nil {
						t.Fatal(err)
					}
					s.passport = identity.NewPassport(nil, cache)
					s.config.FallbackProxy = "did:web:appview.test#view"
					e, _ := newRequestContext("GET", "/xrpc/"+method+"?feed=at://did:web:owner.test/app.bsky.feed.generator/test", "", nil)
					e.Set("credentialKind", credentialLegacyAccess)
					if method == "app.bsky.feed.getFeed" {
						_ = s.handleProxyBskyFeedGetFeed(e)
					} else if err := s.handleProxy(e); !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
						t.Errorf("expected IP-policy rejection, got %v", err)
					}
				})
			}
		}
	}
	if connections.Load() != 0 {
		t.Fatalf("private service received %d connections", connections.Load())
	}
}

func TestProxyDialUsesCheckedAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  [][4]byte
	}{
		{"public", [][4]byte{{203, 0, 113, 10}}},
		{"public then private", [][4]byte{{203, 0, 113, 10}, {10, 0, 0, 1}}},
		{"private then public", [][4]byte{{10, 0, 0, 1}, {203, 0, 113, 10}}},
		{"private only", [][4]byte{{10, 0, 0, 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { dns.Close() })
			go func() {
				buf := make([]byte, 4096)
				for {
					n, addr, err := dns.ReadFrom(buf)
					if err != nil {
						return
					}
					var message dnsmessage.Message
					if message.Unpack(buf[:n]) != nil {
						continue
					}
					message.Header.Response = true
					message.Header.RecursionAvailable = true
					for _, q := range message.Questions {
						if q.Type != dnsmessage.TypeA {
							continue
						}
						for _, ip := range tc.ips {
							message.Answers = append(message.Answers, dnsmessage.Resource{
								Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
								Body:   &dnsmessage.AResource{A: ip},
							})
						}
					}
					response, err := message.Pack()
					if err == nil {
						_, _ = dns.WriteTo(response, addr)
					}
				}
			}()
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
			}}
			dialed := make(chan string, 4)
			stopped := errors.New("test stopped before connecting")
			dialer := newProxyDialer()
			dialer.Resolver = resolver
			check := dialer.ControlContext
			dialer.ControlContext = func(ctx context.Context, network, address string, conn syscall.RawConn) error {
				if err := check(ctx, network, address, conn); err != nil {
					return err
				}
				// Returning here prevents an actual connection to the public IP.
				dialed <- address
				return stopped
			}
			client := newProxyHTTPClient(gttp.WithDialContext(dialer.DialContext))
			t.Cleanup(client.CloseIdleConnections)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", "https://appview.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Do(req)
			if tc.name == "private only" {
				if !errors.Is(err, gttp.ErrBlockedByIPPolicy) || len(dialed) != 0 {
					t.Fatalf("private DNS answer reached connect: calls=%d error=%v", len(dialed), err)
				}
			} else {
				// All attempts fail deliberately. Go returns the first address's
				// error, which may be the blocked sibling in a mixed answer.
				if (!errors.Is(err, stopped) && !errors.Is(err, gttp.ErrBlockedByIPPolicy)) || len(dialed) != 1 {
					t.Fatalf("public DNS answer: calls=%d error=%v", len(dialed), err)
				}
				if address := <-dialed; address != "203.0.113.10:443" {
					t.Fatalf("dial must use checked IP, not resolve again: %s", address)
				}
			}
		})
	}
}

func TestProxyAddressPolicy(t *testing.T) {
	for _, tc := range []struct {
		address string
		blocked bool
	}{
		{"127.0.0.1:443", true},
		{"[::1]:443", true},
		{"[::ffff:127.0.0.1]:443", true},
		{"10.0.0.1:443", true},
		{"172.16.0.1:443", true},
		{"172.31.255.255:443", true},
		{"192.168.1.1:443", true},
		{"[fd00::1]:443", true},
		{"169.254.169.254:443", true},
		{"[fe80::1%eth0]:443", true},
		{"224.0.0.1:443", true},
		{"[ff02::1]:443", true},
		{"0.1.2.3:443", true},
		{"0.0.0.0:443", true},
		{"[::]:443", true},
		{"[::%lo]:443", true},
		{"255.255.255.255:443", true},
		{"100.64.0.1:443", true},
		{"100.127.255.255:443", true},
		{"[64:ff9b::a00:1]:443", true},
		{"[64:ff9b:1::a00:1]:443", true},
		{"[64:ff9b::a00:1%lo]:443", true},
		{"[64:ff9b:1::a00:1%lo]:443", true},
		{"unresolved.test:443", true},
		{"203.0.113.10:443", false},
		{"[::ffff:203.0.113.10]:443", false},
		{"[2606:4700:4700::1111]:443", false},
		{"172.15.255.255:443", false},
		{"172.32.0.0:443", false},
		{"100.63.255.255:443", false},
		{"100.128.0.0:443", false},
		{"[64:ff9b:2::1]:443", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			err := newProxyDialer().ControlContext(t.Context(), "tcp", tc.address, nil)
			if tc.blocked && !errors.Is(err, gttp.ErrBlockedByIPPolicy) || !tc.blocked && err != nil {
				t.Fatalf("address %s: error=%v, want blocked=%t", tc.address, err, tc.blocked)
			}
		})
	}
}

func TestProxyBlocksZonedUnspecifiedAddress(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	var connections atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			conn.Close()
		}
	}()
	client := newProxyHTTPClient()
	t.Cleanup(client.CloseIdleConnections)
	// Linux routes the unspecified address to loopback. A zone must not
	// hide that address from the policy check before the socket connects.
	resp, err := client.Get(fmt.Sprintf("https://[::%%25lo]:%d/", listener.Addr().(*net.TCPAddr).Port))
	if resp != nil {
		resp.Body.Close()
	}
	listener.Close()
	<-done
	if !errors.Is(err, gttp.ErrBlockedByIPPolicy) || connections.Load() != 0 {
		t.Fatalf("zoned unspecified address: connections=%d error=%v", connections.Load(), err)
	}
}

func TestProxyDialTimeoutIncludesDNS(t *testing.T) {
	// Each UDP answer requests TCP fallback; both answers are delayed. DNS
	// retries alone take longer than the connection-establishment budget.
	testCtx := t.Context()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var size uint16
			if binary.Read(server, binary.BigEndian, &size) != nil {
				return
			}
			request := make([]byte, size)
			if _, err := io.ReadFull(server, request); err != nil {
				return
			}
			var message dnsmessage.Message
			if message.Unpack(request) != nil {
				return
			}
			timer := time.NewTimer(3 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return
			case <-testCtx.Done():
				return
			}
			message.Header.Response = true
			message.Header.RecursionAvailable = true
			message.Header.Truncated = network == "udp"
			if network == "tcp" {
				message.Header.RCode = dnsmessage.RCodeServerFailure
			}
			response, err := message.Pack()
			if err != nil {
				return
			}
			_, _ = server.Write(binary.BigEndian.AppendUint16(nil, uint16(len(response))))
			_, _ = server.Write(response)
		}()
		return client, nil
	}}
	dialer := newProxyDialer()
	dialer.Resolver = resolver
	client := newProxyHTTPClient(gttp.WithDialContext(dialer.DialContext))
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(testCtx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://slow-dns.test./", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = client.Do(req)
	elapsed := time.Since(start)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || ctx.Err() != nil || elapsed < 9*time.Second || elapsed > 11*time.Second {
		t.Fatalf("DNS must share the ten-second dial budget: elapsed=%s error=%v request context=%v", elapsed, err, ctx.Err())
	}
}

func TestProxyRedirectGuards(t *testing.T) {
	// A proxy would resolve the destination itself, bypassing the local IP guard.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	for _, tc := range []struct {
		name, target, last string
		wantErr            error
	}{
		{"same origin", "/next", "/last", nil},
		{"default port", "https://203.0.113.10:443/next", "https://203.0.113.10/last", nil},
		{"other host", "https://203.0.113.11/next", "/last", nil},
		{"other port", "https://203.0.113.10:8443/next", "/last", nil},
		{"return to original", "https://203.0.113.10:8443/next", "https://203.0.113.10/last", nil},
		{"return to explicit default port", "https://203.0.113.10:8443/next", "https://203.0.113.10:443/last", nil},
		{"private", "https://127.0.0.1/next", "", gttp.ErrBlockedByIPPolicy},
		{"downgrade", "http://203.0.113.10/next", "", gttp.ErrSchemeDowngrade},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 3)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("Authorization")
				switch r.URL.Path {
				case "/start":
					http.Redirect(w, r, tc.target, http.StatusFound)
				case "/next":
					http.Redirect(w, r, tc.last, http.StatusFound)
				default:
					io.WriteString(w, "ok")
				}
			}))
			t.Cleanup(upstream.Close)
			client := proxyTestHTTPClient(t, upstream)
			req, err := http.NewRequest("GET", "https://203.0.113.10/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer service-token")
			resp, err := client.Do(req)
			if tc.wantErr != nil {
				if resp != nil {
					resp.Body.Close()
				}
				if !errors.Is(err, tc.wantErr) || len(seen) != 1 {
					t.Fatalf("redirect: requests=%d error=%v, want %v", len(seen), err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != "ok" || len(seen) != 3 {
				t.Fatalf("redirect chain: requests=%d body=%q error=%v", len(seen), body, err)
			}
			for i := 0; i < 3; i++ {
				want := ""
				if i == 0 || tc.name == "same origin" || tc.name == "default port" {
					want = "Bearer service-token"
				}
				if got := <-seen; got != want {
					t.Errorf("hop %d authorization = %q, want %q", i, got, want)
				}
			}
		})
	}
}

// TestProxyHTTPClientHasTimeouts guards the client the proxy paths use. The bug
// this prevents: with no response-header timeout, an upstream connection that
// goes silent without a RST/FIN is only noticed when the kernel gives up on its
// retransmissions (roughly 15 minutes at the default tcp_retries2=15), and every
// request multiplexed onto that connection hangs for that long and then fails at
// the same instant.
func TestProxyHTTPClientHasTimeouts(t *testing.T) {
	c := newProxyHTTPClient()

	if c.Timeout != 2*time.Minute {
		t.Errorf("client timeout = %v, want 2 minutes", c.Timeout)
	}

	for _, stage := range []string{"headers", "body"} {
		t.Run(stage, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage == "body" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			t.Cleanup(upstream.Close)
			client := proxyTestHTTPClient(t, upstream)
			if stage == "body" {
				client.Timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", "https://203.0.113.10/stall", nil)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			resp, err := client.Do(req)
			if stage == "body" {
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				_, err = io.ReadAll(resp.Body)
			}
			if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				t.Fatalf("expected client timeout during %s, got %v (context: %v)", stage, err, ctx.Err())
			}
			if stage == "headers" && time.Since(start) < 20*time.Second {
				t.Fatal("header timeout shortened below 20 seconds")
			}
		})
	}
}

// TestProxyCancelsUpstreamOnClientDisconnect proves the inbound request context
// reaches the upstream call. Without it, a client that gives up (a page reload
// mid-request) leaves the upstream request running until its connection is
// torn down, holding a connection slot for minutes.
func TestProxyCancelsUpstreamOnClientDisconnect(t *testing.T) {
	const aud = "did:web:appview.test#view"
	const method = "app.bsky.feed.getTimeline"

	received := make(chan struct{})
	upstreamCancelled := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(received)
		<-r.Context().Done()
		close(upstreamCancelled)
	}))
	t.Cleanup(upstream.Close)

	s := newTestServer(t)
	s.proxyHTTPClient = proxyTestHTTPClient(t, upstream)

	attachOauthProvider(t, s)
	account := s.createTestAccount(t, "proxy.pds.test")

	cache := identity.NewMemCache(10)
	if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
		Id:      "did:web:appview.test",
		Service: []identity.DidDocService{{Id: "#view", ServiceEndpoint: "https://203.0.113.10"}},
	}); err != nil {
		t.Fatal(err)
	}
	s.passport = identity.NewPassport(upstream.Client(), cache)
	s.config.FallbackProxy = aud

	s.echo = echo.New()
	s.echo.Validator = newTestValidator()
	s.addRoutes()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := httptest.NewRequest(http.MethodGet, "/xrpc/"+method+"?limit=1", nil).WithContext(ctx)
	r.Header.Set("atproto-proxy", aud)
	setProxyTestOAuth(t, s, r, account.Did, "rpc:"+method+"?aud=did%3Aweb%3Aappview.test%23view")

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.echo.ServeHTTP(httptest.NewRecorder(), r)
	}()

	select {
	case <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never received the proxied request")
	}

	// The client goes away while the upstream is still working.
	cancel()

	select {
	case <-upstreamCancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream request was not cancelled when the client disconnected; the inbound context is not propagated")
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy handler did not return after the client disconnected")
	}
}

// blackholeRelay forwards TCP connections to target until blackhole is called.
// From then on the connections that already exist swallow every byte in both
// directions without closing, the way a dropped flow behaves: no RST, no FIN,
// no response. Connections accepted later are forwarded normally.
type blackholeRelay struct {
	listener net.Listener
	target   string
	mu       sync.Mutex
	conns    []*atomic.Bool
	accepted atomic.Int32
}

func newBlackholeRelay(t *testing.T, target string) *blackholeRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &blackholeRelay{listener: listener, target: target}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			r.accepted.Add(1)
			server, err := net.Dial("tcp", target)
			if err != nil {
				client.Close()
				continue
			}
			dead := new(atomic.Bool)
			r.mu.Lock()
			r.conns = append(r.conns, dead)
			r.mu.Unlock()
			t.Cleanup(func() { client.Close(); server.Close() })
			pipe := func(dst, src net.Conn) {
				buf := make([]byte, 32<<10)
				for {
					n, err := src.Read(buf)
					if err != nil {
						return
					}
					if dead.Load() {
						continue
					}
					if _, err := dst.Write(buf[:n]); err != nil {
						return
					}
				}
			}
			go pipe(server, client)
			go pipe(client, server)
		}
	}()
	return r
}

func (r *blackholeRelay) blackhole() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, dead := range r.conns {
		dead.Store(true)
	}
}

// TestProxyDropsDeadHTTP2Connection reproduces the cocoon.hailey.at outage of
// 2026-11-21: the HTTP/2 connection to the appview went silent, and because a
// client kept polling, the connection never sat idle long enough to be closed.
// Every request rode the dead connection and failed after the 20s header
// timeout, for minutes. HTTP/2 PING health checks must notice the dead
// connection and close it, so that requests move to a new connection.
func TestProxyDropsDeadHTTP2Connection(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	relay := newBlackholeRelay(t, upstream.Listener.Addr().String())

	tlsConfig := upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "example.com"
	client := newProxyHTTPClient(
		gttp.WithTLSConfig(tlsConfig),
		gttp.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, relay.listener.Addr().String())
		}),
	)
	t.Cleanup(client.CloseIdleConnections)

	get := func(timeout time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(t.Context(), timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", "https://203.0.113.10/xrpc/app.bsky.notification.getUnreadCount", nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("upstream spoke %s, want HTTP/2", resp.Proto)
		}
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	if body, err := get(5 * time.Second); err != nil || body != "ok" {
		t.Fatalf("first request: body=%q err=%v", body, err)
	}
	relay.blackhole()
	start := time.Now()

	// Poll like a client checking for notifications. Each poll keeps the
	// connection from going idle, which is what kept the dead connection in
	// the pool in production.
	const budget = 20 * time.Second
	for time.Since(start) < budget {
		if body, err := get(budget); err == nil && body == "ok" {
			if relay.accepted.Load() < 2 {
				t.Fatal("request succeeded without a new connection")
			}
			t.Logf("recovered on a new connection after %s", time.Since(start).Round(time.Millisecond))
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no request succeeded within %s of the connection going dead; the proxy kept using it", budget)
}
