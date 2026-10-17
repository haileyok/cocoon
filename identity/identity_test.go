package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bluesky-social/gttp"
	"github.com/haileyok/cocoon/internal/helpers"
)

func TestNormalizePlcURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty uses default", in: "", want: DefaultPlcURL},
		{name: "whitespace uses default", in: "   ", want: DefaultPlcURL},
		{name: "https kept", in: "https://plc.example.com", want: "https://plc.example.com"},
		{name: "http allowed for local testing", in: "http://localhost:2582", want: "http://localhost:2582"},
		{name: "trailing slash trimmed", in: "http://localhost:2582/", want: "http://localhost:2582"},
		{name: "path prefix kept", in: "https://example.com/plc/", want: "https://example.com/plc"},
		{name: "missing scheme rejected", in: "localhost:2582", wantErr: true},
		{name: "non-http scheme rejected", in: "ftp://plc.example.com", wantErr: true},
		{name: "missing host rejected", in: "https://", wantErr: true},
		{name: "query rejected", in: "https://plc.example.com?x=1", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePlcURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizePlcURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDidToDocUrlUsesPlcURL(t *testing.T) {
	got, err := DidToDocUrl("http://localhost:2582", "did:plc:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://localhost:2582/did:plc:abc123"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	got, err = DidToDocUrl("", "did:plc:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://plc.directory/did:plc:abc123"; got != want {
		t.Fatalf("empty plc url: got %q, want %q", got, want)
	}

	// did:web resolution never touches the PLC directory.
	got, err = DidToDocUrl("http://localhost:2582", "did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://example.com/.well-known/did.json"; got != want {
		t.Fatalf("did:web: got %q, want %q", got, want)
	}
}

// fakePlc serves a minimal PLC directory and records requested paths.
func fakePlc(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/did:plc:abc123":
			json.NewEncoder(w).Encode(DidDoc{Id: "did:plc:abc123"})
		case "/did:plc:abc123/data":
			json.NewEncoder(w).Encode(DidData{Did: "did:plc:abc123"})
		case "/did:plc:abc123/log/audit":
			json.NewEncoder(w).Encode(DidAuditLog{{Did: "did:plc:abc123"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func TestFetchHelpersUseConfiguredPlcURL(t *testing.T) {
	srv, paths := fakePlc(t)
	ctx := context.Background()

	doc, err := FetchDidDoc(ctx, srv.Client(), srv.URL, "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDidDoc: %v", err)
	}
	if doc.Id != "did:plc:abc123" {
		t.Fatalf("unexpected doc id %q", doc.Id)
	}

	data, err := FetchDidData(ctx, srv.Client(), srv.URL, "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDidData: %v", err)
	}
	if data.Did != "did:plc:abc123" {
		t.Fatalf("unexpected data did %q", data.Did)
	}

	log, err := FetchDidAuditLog(ctx, srv.Client(), srv.URL, "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDidAuditLog: %v", err)
	}
	if len(log) != 1 || log[0].Did != "did:plc:abc123" {
		t.Fatalf("unexpected audit log %+v", log)
	}

	want := []string{"/did:plc:abc123", "/did:plc:abc123/data", "/did:plc:abc123/log/audit"}
	if len(*paths) != len(want) {
		t.Fatalf("paths = %v, want %v", *paths, want)
	}
	for i := range want {
		if (*paths)[i] != want[i] {
			t.Fatalf("paths = %v, want %v", *paths, want)
		}
	}
}

func TestPassportUsesConfiguredPlcURL(t *testing.T) {
	srv, paths := fakePlc(t)

	p := NewPassport(nil, NewMemCache(10), WithPlcURL(srv.URL))
	doc, err := p.FetchDoc(context.Background(), "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDoc: %v", err)
	}
	if doc.Id != "did:plc:abc123" {
		t.Fatalf("unexpected doc id %q", doc.Id)
	}
	if len(*paths) != 1 || (*paths)[0] != "/did:plc:abc123" {
		t.Fatalf("fake PLC was not queried as expected: %v", *paths)
	}
}

func TestPassportBlocksPrivateWebFetches(t *testing.T) {
	var connections atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(DidDoc{Id: "did:web:localhost"})
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	p := NewPassport(nil, NewMemCache(10), WithPlcURL(srv.URL))
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1", "10.0.0.1", "169.254.169.254"} {
		t.Run(host, func(t *testing.T) {
			host = net.JoinHostPort(host, port)
			_, err := p.FetchDoc(context.Background(), "did:web:"+host)
			if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
				t.Fatalf("DID fetch: want IP-policy rejection, got %v", err)
			}
			_, err = ResolveHandleFromWellKnown(context.Background(), p.h, host)
			if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
				t.Fatalf("handle fetch: want IP-policy rejection, got %v", err)
			}
		})
	}
	if connections.Load() != 0 {
		t.Fatalf("private web server received %d connections", connections.Load())
	}
}

func TestPassportPublicWebFetches(t *testing.T) {
	for _, mode := range []string{"document", "redirect", "private-redirect", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			const did = "did:web:203.0.113.10"
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/atproto-did" {
					fmt.Fprint(w, did)
					return
				}
				switch mode {
				case "redirect":
					if r.URL.Path != "/document" {
						http.Redirect(w, r, "/document", http.StatusFound)
						return
					}
				case "private-redirect":
					http.Redirect(w, r, "https://127.0.0.1/document", http.StatusFound)
					return
				case "oversized":
					fmt.Fprint(w, `{"id":"`+did+`"}`+strings.Repeat(" ", helpers.SafeFetchClientMaxBodyBytes))
					return
				}
				json.NewEncoder(w).Encode(DidDoc{Id: did})
			}))
			defer srv.Close()
			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())
			client := gttp.New(
				gttp.WithStrictSSRFProtection(), gttp.WithNoProxy(), gttp.WithNoRetries(),
				gttp.WithMaxResponseBodyBytes(helpers.SafeFetchClientMaxBodyBytes),
				gttp.WithTimeout(time.Second),
				gttp.WithTLSConfig(&tls.Config{RootCAs: roots, ServerName: "example.com"}),
				gttp.WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
					// gttp must approve the logical public address before this test-only dial.
					if address != "203.0.113.10:443" {
						return nil, fmt.Errorf("unexpected dial: %s", address)
					}
					return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
				}),
			)
			defer client.CloseIdleConnections()
			p := NewPassport(client, NewMemCache(10))
			doc, err := p.FetchDoc(context.Background(), did)
			switch mode {
			case "private-redirect":
				if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
					t.Fatalf("want IP-policy rejection, got %v", err)
				}
			case "oversized":
				if !errors.Is(err, gttp.ErrResponseTooLarge) {
					t.Fatalf("want response size rejection, got %v", err)
				}
			default:
				if err != nil || doc.Id != did {
					t.Fatalf("document: %+v, error: %v", doc, err)
				}
				resolved, err := ResolveHandleFromWellKnown(context.Background(), client, "203.0.113.10")
				if err != nil || resolved != did {
					t.Fatalf("handle: %q, error: %v", resolved, err)
				}
			}
		})
	}
}

func TestPassportPlcFetchLimits(t *testing.T) {
	for _, mode := range []string{"redirect", "oversized", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var redirected atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
				json.NewEncoder(w).Encode(DidDoc{Id: "did:plc:abc123"})
			}))
			defer target.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusFound)
				case "oversized":
					json.NewEncoder(w).Encode(DidDoc{Id: strings.Repeat("x", helpers.SafeFetchClientMaxBodyBytes+1)})
				case "cancel":
					<-r.Context().Done()
				}
			}))
			defer srv.Close()
			p := NewPassport(nil, NewMemCache(10), WithPlcURL(srv.URL))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := p.FetchDoc(ctx, "did:plc:abc123")
			if err == nil {
				t.Fatal("expected fetch rejection")
			}
			if mode == "oversized" && !errors.Is(err, gttp.ErrResponseTooLarge) {
				t.Fatalf("want response size rejection, got %v", err)
			}
			if mode == "cancel" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("want deadline error, got %v", err)
			}
			if redirected.Load() != 0 {
				t.Fatalf("PLC redirect reached another server: %d requests", redirected.Load())
			}
		})
	}
}
