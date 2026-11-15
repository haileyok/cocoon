package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/haileyok/cocoon/identity"
	"github.com/labstack/echo/v4"
)

// TestProxyHTTPClientHasTimeouts guards the client the proxy paths use. The bug
// this prevents: with no response-header timeout, an upstream connection that
// goes silent without a RST/FIN is only noticed when the kernel gives up on its
// retransmissions (roughly 15 minutes at the default tcp_retries2=15), and every
// request multiplexed onto that connection hangs for that long and then fails at
// the same instant.
func TestProxyHTTPClientHasTimeouts(t *testing.T) {
	c := newProxyHTTPClient()

	if c.Timeout != proxyRequestTimeout {
		t.Errorf("client timeout = %v, want %v", c.Timeout, proxyRequestTimeout)
	}

	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.Transport)
	}

	if tr.ResponseHeaderTimeout <= 0 {
		t.Error("transport has no ResponseHeaderTimeout, so a half-open upstream connection pins requests")
	}

	if tr.TLSHandshakeTimeout <= 0 {
		t.Error("transport has no TLSHandshakeTimeout")
	}

	if tr.IdleConnTimeout <= 0 {
		t.Error("transport has no IdleConnTimeout")
	}

	if tr.MaxIdleConnsPerHost < proxyMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want at least %d", tr.MaxIdleConnsPerHost, proxyMaxIdleConnsPerHost)
	}

	if defaultProxyHTTPClient == nil {
		t.Error("defaultProxyHTTPClient is nil, so the proxy would fall back to http.DefaultClient")
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
	// Keep production timeouts, but trust the test server's certificate.
	proxyClient := *defaultProxyHTTPClient
	tr := defaultProxyHTTPClient.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = upstream.Client().Transport.(*http.Transport).TLSClientConfig
	proxyClient.Transport = tr
	s.proxyHTTPClient = &proxyClient

	attachOauthProvider(t, s)
	account := s.createTestAccount(t, "proxy.pds.test")

	cache := identity.NewMemCache(10)
	if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
		Id:      "did:web:appview.test",
		Service: []identity.DidDocService{{Id: "#view", ServiceEndpoint: upstream.URL}},
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
