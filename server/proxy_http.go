package server

import (
	"net"
	"net/http"
	"time"
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
func newProxyHTTPClient() *http.Client {
	return &http.Client{
		Timeout: proxyRequestTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   proxyDialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   proxyMaxIdleConnsPerHost,
			IdleConnTimeout:       proxyIdleConnTimeout,
			TLSHandshakeTimeout:   proxyTLSHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: proxyResponseHeaderTimeout,
		},
	}
}

// defaultProxyHTTPClient is the process-wide proxy client. Server.proxyHTTPClient
// defaults to it so that neither proxy path can fall back to
// http.DefaultClient.
var defaultProxyHTTPClient = newProxyHTTPClient()
