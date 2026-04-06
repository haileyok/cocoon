// Package testpds provides a helper for spinning up an ephemeral Cocoon PDS
// instance in tests. The server runs in-process with an in-memory SQLite
// database and auto-generated keys, so no external dependencies are needed.
package testpds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/plc"
	"github.com/haileyok/cocoon/server"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/prometheus/client_golang/prometheus"
)

// httpClientTimeout bounds outbound HTTP requests made by the server (e.g.
// handle resolution via .well-known). Tests use a tight timeout so unresolvable
// handles fail fast instead of triggering the retry/backoff loop in the default
// RobustHTTPClient.
const httpClientTimeout = 1 * time.Second

// TestPDS holds the state of a running test PDS instance.
type TestPDS struct {
	// URL is the base HTTP URL of the running server (e.g. "http://localhost:12345").
	URL string

	// AdminPassword is the admin password for the test instance.
	AdminPassword string

	// DID is the server's DID.
	DID string

	// FakePLC is the fake PLC client used when no PLCUrl is configured.
	// Nil when using a real PLC directory.
	FakePLC *plc.FakePLC
}

// Options configures a test PDS. All fields are optional.
type Options struct {
	// PLCUrl points the server at a real PLC directory at the given URL. If
	// empty (the default), an in-memory FakePLC is used instead — account
	// creation works without any external dependencies, but DIDs are not
	// resolvable from outside the test process.
	PLCUrl string

	// RequireInvite controls whether the server requires invite codes for
	// account creation. Defaults to false.
	RequireInvite bool

	// Relays is the list of relay URLs to notify on new commits.
	// Defaults to empty (no relay notifications).
	Relays []string

	// AdminPassword overrides the admin password. Defaults to "test-admin".
	AdminPassword string
}

// Start launches a new ephemeral PDS and registers cleanup with t.Cleanup.
// The server is ready to accept requests when Start returns.
func Start(t *testing.T, opts *Options) *TestPDS {
	t.Helper()

	if opts == nil {
		opts = &Options{}
	}
	if opts.AdminPassword == "" {
		opts.AdminPassword = "test-admin"
	}

	port := freePort(t)
	hostname := fmt.Sprintf("localhost:%d", port)

	rotKeyBytes := generateRotationKey(t)
	jwkBytes := generateJWK(t)
	sessionSecret, err := helpers.RandomHex(32)
	if err != nil {
		t.Fatalf("testpds: generate session secret: %v", err)
	}

	dir := t.TempDir()

	// Use FakePLC by default for fully isolated tests. If PLCUrl is set,
	// use the real PLC client pointing at that URL instead.
	var plcClient plc.PLCClient
	if opts.PLCUrl == "" {
		fake, err := plc.NewFakePLC(&plc.FakePLCArgs{
			RotationKey: rotKeyBytes,
			PdsHostname: hostname,
		})
		if err != nil {
			t.Fatalf("testpds: create fake plc: %v", err)
		}
		plcClient = fake
	}

	s, err := server.New(&server.Args{
		Addr:                 fmt.Sprintf(":%d", port),
		DbName:               dir + "/test.db",
		DbType:               "sqlite",
		Did:                  fmt.Sprintf("did:web:%s", hostname),
		Hostname:             hostname,
		RotationKeyBytes:     rotKeyBytes,
		JwkBytes:             jwkBytes,
		NonceSecret:          helpers.RandomBytes(32),
		PLCUrl:               opts.PLCUrl,
		PLCClient:            plcClient,
		HTTPClient:           &http.Client{Timeout: httpClientTimeout},
		ContactEmail:         "test@test.com",
		AdminPassword:        opts.AdminPassword,
		SessionSecret:        sessionSecret,
		RequireInvite:        opts.RequireInvite,
		Relays:               opts.Relays,
		PrometheusRegisterer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatalf("testpds: server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(ctx)
	}()

	baseURL := fmt.Sprintf("http://%s", hostname)
	waitForHealthy(t, baseURL+"/xrpc/_health", errCh)

	t.Cleanup(func() {
		cancel()
		// Give Serve a moment to finish its graceful shutdown.
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
		}
	})

	var fakePLC *plc.FakePLC
	if f, ok := plcClient.(*plc.FakePLC); ok {
		fakePLC = f
	}

	return &TestPDS{
		URL:           baseURL,
		AdminPassword: opts.AdminPassword,
		DID:           fmt.Sprintf("did:web:%s", hostname),
		FakePLC:       fakePLC,
	}
}

// Client returns an unauthenticated xrpc.Client pointed at this PDS.
func (p *TestPDS) Client() *xrpc.Client {
	return &xrpc.Client{Host: p.URL}
}

// ClientWithAuth returns an xrpc.Client with the given auth info set.
func (p *TestPDS) ClientWithAuth(auth *xrpc.AuthInfo) *xrpc.Client {
	return &xrpc.Client{Host: p.URL, Auth: auth}
}

// MustCreateAccount creates a test account and returns an authenticated
// xrpc.Client. Fails the test on error.
func (p *TestPDS) MustCreateAccount(t *testing.T, handle, email, password string) *xrpc.Client {
	t.Helper()

	ctx := context.Background()
	client := p.Client()

	out, err := atproto.ServerCreateAccount(ctx, client, &atproto.ServerCreateAccount_Input{
		Handle:   handle,
		Email:    &email,
		Password: &password,
	})
	if err != nil {
		t.Fatalf("testpds: create account %s: %v", handle, err)
	}

	return p.ClientWithAuth(&xrpc.AuthInfo{
		AccessJwt:  out.AccessJwt,
		RefreshJwt: out.RefreshJwt,
		Did:        out.Did,
		Handle:     out.Handle,
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testpds: listen for free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func generateRotationKey(t *testing.T) []byte {
	t.Helper()
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("testpds: generate rotation key: %v", err)
	}
	return key.Bytes()
}

func generateJWK(t *testing.T) []byte {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testpds: generate ecdsa key: %v", err)
	}
	key, err := jwk.FromRaw(privKey)
	if err != nil {
		t.Fatalf("testpds: jwk from raw: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, fmt.Sprintf("%d", time.Now().UnixNano())); err != nil {
		t.Fatalf("testpds: set key id: %v", err)
	}
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("testpds: marshal jwk: %v", err)
	}
	return b
}

func waitForHealthy(t *testing.T, url string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("testpds: server exited during startup: %v", err)
		default:
		}

		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("testpds: server did not become healthy within 10s at %s", url)
}
