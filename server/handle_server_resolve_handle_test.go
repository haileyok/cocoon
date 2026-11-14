package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/identity"
)

// staticTXTResolver stands in for DNS so handle resolution in these tests never
// touches the network.
type staticTXTResolver struct {
	recs []string
	err  error
}

func (r staticTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.recs, r.err
}

// staticTransport answers every request with a canned status/body.
type staticTransport struct {
	status int
	body   string
	err    error
}

func (t staticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.err != nil {
		return nil, t.err
	}
	return &http.Response{
		StatusCode: t.status,
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// newHandleResolutionServer wires a server whose passport resolves handles from
// the given TXT answer and well-known response instead of the network.
func newHandleResolutionServer(t *testing.T, resolver identity.TXTResolver, known staticTransport) *Server {
	t.Helper()

	s := newTestServer(t)
	s.passport = identity.NewPassport(
		&http.Client{Transport: known},
		identity.NewMemCache(100),
		identity.WithTXTResolver(resolver),
	)
	return s
}

func TestResolveHandleUnresolvableHandleIsClientError(t *testing.T) {
	// A handle nothing claims is the caller's mistake: the reference PDS answers
	// 400 InvalidRequest, and a 500 makes clients retry a call that can never
	// succeed.
	s := newHandleResolutionServer(t,
		staticTXTResolver{recs: nil},
		staticTransport{status: 404, body: "not found"},
	)

	ctx, w := newRequestContext("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=nobody.example.com", "", nil)
	if err := s.handleResolveHandle(ctx); err != nil {
		t.Fatalf("handleResolveHandle returned error: %v", err)
	}

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (body %q)", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, "Unable to resolve handle") {
		t.Fatalf("body = %q, want an \"Unable to resolve handle\" error", got)
	}
}

func TestResolveHandleWebsiteWithoutDIDIsClientError(t *testing.T) {
	// Plenty of domains answer every path with a page (an SPA, a default nginx
	// response). That is a definitive "no DID here", not a server fault.
	s := newHandleResolutionServer(t,
		staticTXTResolver{recs: []string{"v=spf1 -all"}},
		staticTransport{status: 200, body: "<html>hello</html>"},
	)

	ctx, w := newRequestContext("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=nobody.example.com", "", nil)
	if err := s.handleResolveHandle(ctx); err != nil {
		t.Fatalf("handleResolveHandle returned error: %v", err)
	}

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (body %q)", w.Code, w.Body.String())
	}
}

func TestResolveHandleResolutionFailureIsServerError(t *testing.T) {
	// DNS broke, so whether the handle exists is unknown: keep the 5xx (and the
	// error log) rather than telling the client the handle is gone.
	s := newHandleResolutionServer(t,
		staticTXTResolver{err: &net.DNSError{Err: "server misbehaving", Name: "_atproto.nobody.example.com"}},
		staticTransport{status: 500, body: "boom"},
	)

	ctx, w := newRequestContext("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=nobody.example.com", "", nil)
	if err := s.handleResolveHandle(ctx); err != nil {
		t.Fatalf("handleResolveHandle returned error: %v", err)
	}

	if w.Code != 500 {
		t.Fatalf("status = %d, want 500 (body %q)", w.Code, w.Body.String())
	}
}

func TestResolveHandleSucceeds(t *testing.T) {
	const did = "did:plc:z72i7hdynmk6r22z27h6tvur"

	t.Run("from TXT", func(t *testing.T) {
		s := newHandleResolutionServer(t,
			staticTXTResolver{recs: []string{"did=" + did}},
			staticTransport{status: 500, err: errors.New("well-known must not be consulted")},
		)

		ctx, w := newRequestContext("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=bsky.app", "", nil)
		if err := s.handleResolveHandle(ctx); err != nil {
			t.Fatalf("handleResolveHandle returned error: %v", err)
		}

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200 (body %q)", w.Code, w.Body.String())
		}
		if got := w.Body.String(); !strings.Contains(got, did) {
			t.Fatalf("body = %q, want it to contain %q", got, did)
		}
	})

	t.Run("from well-known", func(t *testing.T) {
		s := newHandleResolutionServer(t,
			staticTXTResolver{recs: nil},
			staticTransport{status: 200, body: did + "\n"},
		)

		ctx, w := newRequestContext("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=nobody.example.com", "", nil)
		if err := s.handleResolveHandle(ctx); err != nil {
			t.Fatalf("handleResolveHandle returned error: %v", err)
		}

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200 (body %q)", w.Code, w.Body.String())
		}
		if got := w.Body.String(); !strings.Contains(got, did) {
			t.Fatalf("body = %q, want it to contain %q", got, did)
		}
	})
}
