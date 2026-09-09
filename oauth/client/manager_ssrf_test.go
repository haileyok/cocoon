package client

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/haileyok/cocoon/internal/helpers"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/bluesky-social/gttp"
)

// The OAuth client manager fetches request-controlled URLs (client_id and
// jwks_uri) when a client registers. These fetches must not reach loopback,
// private, link-local, or CGNAT addresses, and responses must be size-capped.
// The production client is helpers.NewSafeFetchClient(); these tests pin its
// behavior through the Manager.

// newRecordingServer starts a loopback HTTP server that counts every request
// it receives and serves syntactically valid OAuth client metadata.
func newRecordingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{
			"client_id": "https://client.example",
			"client_name": "Test Client",
			"client_uri": "https://client.example",
			"redirect_uris": ["https://client.example/callback"],
			"scope": "atproto",
			"token_endpoint_auth_method": "none",
			"jwks_uri": "https://client.example/jwks.json"
		}`))
	}))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &hits
}

func newSafeManager() *Manager {
	return NewManager(ManagerArgs{Cli: helpers.NewSafeFetchClient()})
}

// A loopback client_id must be rejected by the SSRF filter before any request
// is issued — not by a later metadata-validation error.
func TestClientMetadataFetchBlocksLoopbackBeforeRequest(t *testing.T) {
	srv, hits := newRecordingServer(t)
	m := newSafeManager()

	_, err := m.GetClient(context.Background(), srv.URL)
	if err == nil {
		t.Fatalf("fetch of loopback client_id %s unexpectedly succeeded", srv.URL)
	}
	if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
		t.Fatalf("expected gttp.ErrBlockedByIPPolicy, got: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("loopback server received %d requests; SSRF filter should block before dialing", got)
	}
}

// A private-range client_id must fail fast with the IP-policy sentinel.
func TestClientMetadataFetchBlocksPrivateIP(t *testing.T) {
	m := newSafeManager()

	_, err := m.GetClient(context.Background(), "http://10.255.255.1:1/.well-known/oauth-authorization-server")
	if err == nil {
		t.Fatal("fetch of private-range client_id unexpectedly succeeded")
	}
	if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
		t.Fatalf("expected gttp.ErrBlockedByIPPolicy, got: %v", err)
	}
}

// A remote client whose jwks_uri points at a loopback service must not have
// that JWKS fetched.
func TestClientJwksFetchBlocksLoopbackBeforeRequest(t *testing.T) {
	srv, hits := newRecordingServer(t)
	m := newSafeManager()

	_, err := m.getClientJwks(context.Background(), "https://remote-client.example", srv.URL+"/jwks.json")
	if err == nil {
		t.Fatalf("jwks fetch to loopback %s unexpectedly succeeded", srv.URL)
	}
	if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
		t.Fatalf("expected gttp.ErrBlockedByIPPolicy, got: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("loopback server received %d requests; SSRF filter should block before dialing", got)
	}
}
