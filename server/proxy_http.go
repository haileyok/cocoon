package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/bluesky-social/gttp"
)

const (
	// proxyDialTimeout bounds connection establishment with an upstream
	// service (appview, chat service, feed generator).
	proxyDialTimeout = 10 * time.Second

	// proxyResponseHeaderTimeout bounds the wait for the upstream's response
	// headers. This is the timeout that keeps a half-open connection from
	// pinning requests: when a flow is dropped without a RST or FIN, the
	// kernel only gives up after its retransmission budget, which is roughly
	// 15 minutes at the default tcp_retries2=15. Every request multiplexed
	// onto that connection hangs for that long and then fails at once.
	proxyResponseHeaderTimeout = 20 * time.Second

	// proxyRequestTimeout is a backstop for the whole exchange, including
	// reading the response body. Proxied payloads are JSON API responses, so
	// minutes rather than seconds are generous enough to never fire in
	// practice.
	proxyRequestTimeout = 2 * time.Minute

	// proxyTLSHandshakeTimeout bounds the TLS handshake with an upstream.
	proxyTLSHandshakeTimeout = 10 * time.Second

	// proxyIdleConnTimeout is how long a keep-alive connection to an upstream
	// may sit idle before it is closed. A shorter window than the kernel's
	// keepalive (tcp_keepalive_time defaults to two hours) means dead
	// connections are dropped by us rather than discovered by accident.
	proxyIdleConnTimeout = 90 * time.Second

	// proxyHTTP2ReadIdleTimeout and proxyHTTP2PingTimeout are the HTTP/2
	// health check: when nothing has been read from a connection for
	// proxyHTTP2ReadIdleTimeout, the transport sends a PING and closes the
	// connection if no answer arrives within proxyHTTP2PingTimeout. Neither
	// the response-header timeout nor the idle timeout replaces this. A
	// header timeout fails the one request but leaves its connection in the
	// pool, and a client polling more often than proxyIdleConnTimeout keeps a
	// dead connection from ever going idle. With the check off, that is how
	// every app.bsky request on cocoon.hailey.at failed for minutes at a time
	// on 2026-11-21.
	proxyHTTP2ReadIdleTimeout = 10 * time.Second
	proxyHTTP2PingTimeout     = 5 * time.Second

	// proxyMaxIdleConnsPerHost is the per-upstream keep-alive pool. The
	// default of 2 makes a burst of client requests open and close
	// connections constantly.
	proxyMaxIdleConnsPerHost = 32
)

// newProxyHTTPClient builds the client used for requests cocoon forwards to
// another service on a client's behalf.
//
// It deliberately does not use http.DefaultClient: that carries no
// response-header timeout, so an upstream connection that goes silent hangs
// whatever is queued on it until the kernel aborts the socket. Requests are
// also sent with the inbound request context, so a client that disconnects
// cancels the upstream call instead of leaving it running.
func newProxyHTTPClient(opts ...gttp.Option) *http.Client {
	dialer := newProxyDialer()
	client := gttp.New(append([]gttp.Option{
		gttp.WithDialContext(dialer.DialContext),
		// The dialer's socket check covers initial and redirected connections.
		// Disable gttp's separate DNS preflight so DNS shares the dial budget.
		gttp.WithAllowPrivateRedirects(),
		gttp.WithNoProxy(),
		gttp.WithTimeout(proxyRequestTimeout),
		gttp.WithTLSHandshakeTimeout(proxyTLSHandshakeTimeout),
		gttp.WithResponseHeaderTimeout(proxyResponseHeaderTimeout),
		gttp.WithExpectContinueTimeout(time.Second),
		gttp.WithIdleConnTimeout(proxyIdleConnTimeout),
		gttp.WithMaxIdleConns(100),
		gttp.WithMaxIdleConnsPerHost(proxyMaxIdleConnsPerHost),
		gttp.WithMaxConnsPerHost(0),
		gttp.WithRedirectPolicy(10),
		// Preserve streaming bytes and the existing timeout/retry policy.
		gttp.WithNoRetries(),
		gttp.WithDisableCompression(),
		gttp.WithIdleTimeout(0),
		gttp.WithHTTP2ReadIdleTimeout(proxyHTTP2ReadIdleTimeout),
		gttp.WithHTTP2PingTimeout(proxyHTTP2PingTimeout),
	}, opts...)...)
	origin := func(u *url.URL) [3]string {
		scheme, port := strings.ToLower(u.Scheme), u.Port()
		if port == "" {
			switch scheme {
			case "https":
				port = "443"
			case "http":
				port = "80"
			}
		}
		return [3]string{scheme, strings.ToLower(u.Hostname()), port}
	}
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := checkRedirect(req, via); err != nil {
			return err
		}
		// Go copies the original headers again on each hop. Once the chain
		// crosses an origin, do not restore its service token on later hops.
		for _, previous := range via {
			if origin(previous.URL) != origin(req.URL) {
				req.Header.Del("Authorization")
				break
			}
		}
		return nil
	}
	return client
}

func newProxyDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   proxyDialTimeout,
		KeepAlive: 30 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			// ControlContext sees the resolved address immediately before connect.
			// Go owns DNS, the shared deadline and IPv4/IPv6 fallback; every
			// attempted address is checked, including mixed public/private answers.
			destination, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %s", gttp.ErrBlockedByIPPolicy, address)
			}
			// Zones select an interface; they must not change address classification.
			ip := destination.Addr().WithZone("").Unmap()
			blocked := ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsMulticast() || ip.IsUnspecified()
			if ip.Is4() {
				v4 := ip.As4()
				blocked = blocked || v4[0] == 0 || v4 == [4]byte{255, 255, 255, 255} ||
					(v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127)
			} else {
				// NAT64 can translate an apparently public IPv6 destination to a
				// private IPv4 address. Keep both translation ranges blocked.
				blocked = blocked || netip.MustParsePrefix("64:ff9b::/96").Contains(ip) ||
					netip.MustParsePrefix("64:ff9b:1::/48").Contains(ip)
			}
			if blocked {
				return fmt.Errorf("%w: %s", gttp.ErrBlockedByIPPolicy, address)
			}
			return nil
		},
	}
}

// defaultProxyHTTPClient is the process-wide proxy client. Server.proxyHTTPClient
// defaults to it so that neither proxy path can fall back to
// http.DefaultClient.
var defaultProxyHTTPClient = newProxyHTTPClient()
