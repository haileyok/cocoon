package scopes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"golang.org/x/net/dns/dnsmessage"
)

func basePLCURL(t *testing.T, r *IndigoResolver) string {
	t.Helper()
	cache, ok := r.dir.(*identity.CacheDirectory)
	if !ok {
		t.Fatalf("expected *identity.CacheDirectory, got %T", r.dir)
	}
	base, ok := cache.Inner.(*identity.BaseDirectory)
	if !ok {
		t.Fatalf("expected *identity.BaseDirectory inner, got %T", cache.Inner)
	}
	return base.PLCURL
}

func TestNewIndigoResolverWithPLCURL(t *testing.T) {
	r := NewIndigoResolverWithPLCURL("http://localhost:2582")
	if got := basePLCURL(t, r); got != "http://localhost:2582" {
		t.Fatalf("PLCURL = %q, want %q", got, "http://localhost:2582")
	}
}

func TestNewIndigoResolverWithPLCURLEmptyUsesDefault(t *testing.T) {
	r := NewIndigoResolverWithPLCURL("")
	if got := basePLCURL(t, r); got != identity.DefaultPLCURL {
		t.Fatalf("PLCURL = %q, want %q", got, identity.DefaultPLCURL)
	}
}

// All DNS and HTTP traffic stays on disposable local servers.
func lexiconTestDNS(t *testing.T, did string) *net.Resolver {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if msg.Unpack(buf[:n]) != nil {
				continue
			}
			msg.Header.Response = true
			msg.Header.RecursionAvailable = true
			for _, q := range msg.Questions {
				h := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET}
				if q.Type == dnsmessage.TypeTXT && strings.HasPrefix(q.Name.String(), "_lexicon.") {
					msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.TXTResource{TXT: []string{"did=" + did}}})
				} else if q.Type == dnsmessage.TypeA {
					ip := [4]byte{127, 0, 0, 1}
					if q.Name.String() == "public.example.com." {
						ip = [4]byte{203, 0, 113, 10}
					}
					msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: ip}})
				}
			}
			packet, err := msg.Pack()
			if err == nil {
				_, _ = conn.WriteTo(packet, addr)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, conn.LocalAddr().String())
	}}
}

func TestLexiconResolutionBlocksPrivateDestinations(t *testing.T) {
	const did = "did:plc:abcdefghijklmnopqrstuvwx"
	dns := lexiconTestDNS(t, did)
	for _, kind := range []string{"permission-set", "space", "space permissions"} {
		for _, host := range []string{"127.0.0.1", "localhost", "pds.example.com"} {
			t.Run(kind+"/"+host, func(t *testing.T) {
				var hits atomic.Int32
				pds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					fmt.Fprintf(w, `{"value":{"lexicon":1,"id":"com.example.lexicon","defs":{"main":{"type":%q,"title":"Example","key":"tid","collections":["com.example.record"],"permissions":[]}}}}`, kind)
				}))
				defer pds.Close()
				_, port, _ := net.SplitHostPort(pds.Listener.Addr().String())
				plc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"id":%q,"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":%q}]}`, did, "http://"+net.JoinHostPort(host, port))
				}))
				defer plc.Close()
				r := NewIndigoResolverWithPLCURL(plc.URL)
				r.dns.Resolver = net.Resolver{PreferGo: true, Dial: dns.Dial}
				var err error
				if kind == "space" {
					_, err = r.ResolveSpaceCollections(t.Context(), "com.example.lexicon")
				} else if kind == "space permissions" {
					_, err = r.ResolveSpacePermissions(t.Context(), "com.example.lexicon")
				} else {
					_, err = r.ResolvePermissionSet(t.Context(), "com.example.lexicon")
				}
				if err == nil || !strings.Contains(err.Error(), "lexicon fetch requires HTTPS") || hits.Load() != 0 {
					t.Fatalf("private record fetch: error=%v, requests=%d", err, hits.Load())
				}
			})
		}
	}
}

func TestLexiconResolutionBlocksPrivateDIDWeb(t *testing.T) {
	dns := lexiconTestDNS(t, "did:web:lexicon.example.com")
	r := NewIndigoResolver()
	r.dns.Resolver = net.Resolver{PreferGo: true, Dial: dns.Dial}
	base := r.dir.(*identity.CacheDirectory).Inner.(*identity.BaseDirectory)
	// Check constructor wiring before adding the test-only DNS resolver.
	if response, err := base.HTTPClient.Get("https://127.0.0.1/.well-known/did.json"); err == nil {
		response.Body.Close()
		t.Fatal("default identity client accepted a private endpoint")
	} else if !strings.Contains(err.Error(), "lexicon fetch requires HTTPS") {
		t.Fatalf("default identity client lacks URL policy: %v", err)
	}
	base.HTTPClient = *newLexiconHTTPClient("", gttp.WithNoRedirects(), gttp.WithResolver(dns))
	_, err := r.ResolvePermissionSet(t.Context(), "com.example.lexicon")
	if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
		t.Fatalf("private DID-web fetch: %v", err)
	}
}

func TestLexiconResolutionCancelsDNS(t *testing.T) {
	r := NewIndigoResolver()
	started := make(chan struct{}, 1)
	r.dns.Resolver = net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, err := r.ResolvePermissionSet(ctx, "com.example.lexicon")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want DNS cancellation, got %v", err)
	}
}

func TestLexiconSuppliedDirectoryPrivatePDS(t *testing.T) {
	const did = "did:plc:abcdefghijklmnopqrstuvwx"
	dns := lexiconTestDNS(t, did)
	for _, endpoint := range []string{"https://private.example.com", "https://127.0.0.1", "https://[::%25lo]", "https://[64:ff9b::7f00:1%25lo]", "https://public.example.com:8443"} {
		t.Run(endpoint, func(t *testing.T) {
			dir := identity.NewMockDirectory()
			dir.Insert(identity.Identity{DID: syntax.DID(did), Services: map[string]identity.ServiceEndpoint{
				"atproto_pds": {Type: "AtprotoPersonalDataServer", URL: endpoint},
			}})
			r := NewIndigoResolverWithDirectory(dir)
			r.dns.Resolver = net.Resolver{PreferGo: true, Dial: dns.Dial}
			// Keep the production guard; only route DNS to the disposable test server.
			r.httpClient = newLexiconHTTPClient("", gttp.WithResolver(dns), gttp.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
				t.Error("unsafe destination reached the dialer")
				return nil, fmt.Errorf("unexpected dial")
			}))
			_, err := r.ResolvePermissionSet(t.Context(), "com.example.lexicon")
			if endpoint == "https://private.example.com" {
				if !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
					t.Fatalf("want private DNS rejection, got %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "lexicon fetch requires HTTPS") {
				t.Fatalf("want URL policy rejection, got %v", err)
			}
		})
	}
}

func TestLexiconResolutionPublicFetch(t *testing.T) {
	for _, mode := range []string{"permission-set", "space", "DID-web", "DID-web redirect", "public redirect", "private redirect", "HTTP redirect", "IP redirect", "port redirect", "oversized", "at limit", "over limit", "space at limit", "space over limit", "API error", "non-JSON error", "cancel body", "deadline body", "unsigned JSON", "P256", "partial", "space permissions", "space forged signature", "space permissions forged signature", "forged signature", "tampered commit", "wrong DID", "wrong path", "tampered record CID", "wrong ID", "wrong type", "wrong version", "missing defs", "missing commit", "missing MST", "missing record", "multiple roots", "bad prefix", "negative prefix"} {
		t.Run(mode, func(t *testing.T) {
			did := "did:plc:abcdefghijklmnopqrstuvwx"
			if strings.HasPrefix(mode, "DID-web") {
				did = "did:web:public.example.com"
			}
			dns := lexiconTestDNS(t, did)
			kind := "permission-set"
			if strings.HasPrefix(mode, "space") && !strings.HasPrefix(mode, "space permissions") {
				kind = "space"
			}
			fixtureMode := mode
			if strings.HasSuffix(mode, "forged signature") {
				fixtureMode = "forged signature"
			}
			proof, publicKey := lexiconProofFixture(t, kind, fixtureMode)
			if strings.HasSuffix(mode, "limit") {
				size := 2 << 20
				if strings.Contains(mode, "over limit") {
					size++
				}
				proof = lexiconProofAtSize(t, proof, size)
			}
			var requests atomic.Int32
			started := make(chan struct{}, 1)
			pds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests.Add(1)
				if req.URL.Path == "/.well-known/did.json" {
					if mode == "DID-web redirect" {
						http.Redirect(w, req, "/other-did.json", http.StatusFound)
					} else {
						fmt.Fprintf(w, `{"id":%q,"verificationMethod":[{"id":"#atproto","type":"Multikey","controller":%q,"publicKeyMultibase":%q}],"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://public.example.com"}]}`, did, did, publicKey)
					}
					return
				}
				if req.URL.Path != "/record" {
					if req.URL.Path != "/xrpc/com.atproto.sync.getRecord" || req.URL.Query().Get("did") != did || req.URL.Query().Get("collection") != "com.atproto.lexicon.schema" || req.URL.Query().Get("rkey") != "com.example.lexicon" {
						t.Errorf("wrong record request: %s", req.URL)
					}
					switch mode {
					case "public redirect":
						http.Redirect(w, req, "/record", http.StatusFound)
						return
					case "private redirect":
						http.Redirect(w, req, "https://private.example.com/record", http.StatusFound)
						return
					case "HTTP redirect":
						http.Redirect(w, req, "http://public.example.com/record", http.StatusFound)
						return
					case "IP redirect":
						http.Redirect(w, req, "https://203.0.113.10/record", http.StatusFound)
						return
					case "port redirect":
						http.Redirect(w, req, "https://public.example.com:8443/record", http.StatusFound)
						return
					case "API error":
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, `{"error":"Forbidden","message":"not available"}`)
						return
					case "non-JSON error":
						http.Error(w, "unavailable", http.StatusServiceUnavailable)
						return
					}
				}
				if mode == "cancel body" || mode == "deadline body" {
					fmt.Fprint(w, `{"value":`)
					w.(http.Flusher).Flush()
					started <- struct{}{}
					<-req.Context().Done()
					return
				}
				if mode == "oversized" {
					fmt.Fprintf(w, `{"padding":%q,`, strings.Repeat("x", helpers.SafeFetchClientMaxBodyBytes))
					return
				}
				if mode == "unsigned JSON" {
					fmt.Fprint(w, `{"value":{"lexicon":1,"id":"com.example.lexicon","defs":{"main":{"type":"permission-set","permissions":[]}}}}`)
					return
				}
				w.Header().Set("Content-Type", "application/vnd.ipld.car")
				_, _ = w.Write(proof)
			}))
			defer pds.Close()
			plc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				fmt.Fprintf(w, `{"id":%q,"verificationMethod":[{"id":"#atproto","type":"Multikey","controller":%q,"publicKeyMultibase":%q}],"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://public.example.com"}]}`, did, did, publicKey)
			}))
			defer plc.Close()
			r := NewIndigoResolverWithPLCURL(plc.URL)
			r.dns.Resolver = net.Resolver{PreferGo: true, Dial: dns.Dial}
			r.SetLocalLexiconReader(func(_ context.Context, authority syntax.DID, nsid syntax.NSID) ([]byte, bool, error) {
				if authority.String() != did || nsid != "com.example.lexicon" {
					t.Fatalf("wrong local lookup before remote fallback: %s/%s", authority, nsid)
				}
				return nil, false, nil
			})
			roots := x509.NewCertPool()
			roots.AddCert(pds.Certificate())
			opts := []gttp.Option{
				gttp.WithResolver(dns),
				gttp.WithTLSConfig(&tls.Config{RootCAs: roots, ServerName: "example.com"}),
				gttp.WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
					// Only the policy-approved logical public address reaches this dial.
					if address != "203.0.113.10:443" {
						t.Errorf("unexpected dial: %s", address)
						return nil, fmt.Errorf("unexpected dial: %s", address)
					}
					return (&net.Dialer{}).DialContext(ctx, network, pds.Listener.Addr().String())
				}),
			}
			r.httpClient = newLexiconHTTPClient("", opts...)
			if strings.HasPrefix(mode, "DID-web") {
				base := r.dir.(*identity.CacheDirectory).Inner.(*identity.BaseDirectory)
				base.HTTPClient = *newLexiconHTTPClient("", append(opts, gttp.WithNoRedirects())...)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancel body" {
				go func() {
					select {
					case <-started:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			if mode == "deadline body" {
				r.httpClient.Timeout = 100 * time.Millisecond
			}
			if mode == "space permissions forged signature" || mode == "space forged signature" {
				var err error
				if mode == "space permissions forged signature" {
					_, err = r.ResolveSpacePermissions(ctx, "com.example.lexicon")
				} else {
					_, err = r.ResolveSpaceCollections(ctx, "com.example.lexicon")
				}
				if err == nil || !strings.Contains(err.Error(), "commit signature") || requests.Load() != 1 {
					t.Fatalf("forged space proof: requests=%d error=%v", requests.Load(), err)
				}
				return
			}
			if mode == "space permissions" {
				perms, err := r.ResolveSpacePermissions(ctx, "com.example.lexicon")
				if err != nil || len(perms) != 1 || perms[0].Type != "com.example.group" {
					t.Fatalf("space permissions=%v, error=%v", perms, err)
				}
				return
			}
			if strings.HasPrefix(mode, "space") {
				cols, err := r.ResolveSpaceCollections(ctx, "com.example.lexicon")
				if mode == "space over limit" {
					if !errors.Is(err, gttp.ErrResponseTooLarge) {
						t.Fatalf("want size rejection, got collections=%v, error=%v", cols, err)
					}
					return
				}
				if err != nil || len(cols) != 1 || cols[0] != "com.example.record" {
					t.Fatalf("collections=%v, error=%v", cols, err)
				}
				return
			}
			ps, err := r.ResolvePermissionSet(ctx, "com.example.lexicon")
			switch mode {
			case "permission-set", "public redirect", "DID-web", "at limit", "P256", "partial":
				if err != nil || len(ps.Permissions) != 2 || ps.Permissions[0].Resource != "repo" || ps.Permissions[0].Action[0] != "create" {
					t.Fatalf("permission-set=%+v, error=%v", ps, err)
				}
				before := requests.Load()
				if _, err := r.ResolvePermissionSet(ctx, "com.example.lexicon"); err != nil || requests.Load() != before {
					t.Fatalf("cache did not preserve result: %v", err)
				}
			case "oversized", "over limit":
				if !errors.Is(err, gttp.ErrResponseTooLarge) {
					t.Fatalf("want size rejection, got %v", err)
				}
			case "cancel body":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("want cancellation, got %v", err)
				}
			case "deadline body":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("want deadline, got %v", err)
				}
			case "API error", "non-JSON error":
				var apiErr *atclient.APIError
				if !errors.As(err, &apiErr) {
					t.Fatalf("want API error, got %v", err)
				}
				if mode == "API error" {
					if apiErr.StatusCode != http.StatusForbidden || apiErr.Name != "Forbidden" || apiErr.Message != "not available" {
						t.Fatalf("lost API error details: %+v", apiErr)
					}
				} else if apiErr.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("lost HTTP status: %+v", apiErr)
				}
			default:
				if err == nil || requests.Load() != 1 {
					t.Fatalf("unsafe response: error=%v, requests=%d", err, requests.Load())
				}
				before := requests.Load()
				if _, cachedErr := r.ResolvePermissionSet(ctx, "com.example.lexicon"); cachedErr == nil || requests.Load() != before {
					t.Fatalf("negative cache did not preserve rejection: %v", cachedErr)
				}
			}
		})
	}
}

func TestLexiconConfiguredPLC(t *testing.T) {
	const did = "did:plc:abcdefghijklmnopqrstuvwx"
	for _, mode := range []string{"document", "redirect", "oversized", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				redirected.Add(1)
				fmt.Fprintf(w, `{"id":%q}`, did)
			}))
			defer target.Close()
			started := make(chan struct{})
			plc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path != "/directory/"+did {
					t.Errorf("trusted PLC exception reached unexpected path %q", req.URL.Path)
				}
				switch mode {
				case "redirect":
					http.Redirect(w, req, target.URL, http.StatusFound)
				case "oversized":
					fmt.Fprintf(w, `{"id":%q,"padding":%q}`, did, strings.Repeat("x", helpers.SafeFetchClientMaxBodyBytes))
				case "cancel":
					close(started)
					<-req.Context().Done()
				default:
					fmt.Fprintf(w, `{"id":%q}`, did)
				}
			}))
			defer plc.Close()
			r := NewIndigoResolverWithPLCURL(plc.URL + "/directory/")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancel" {
				go func() {
					select {
					case <-started:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			ident, err := r.dir.LookupDID(ctx, syntax.DID(did))
			switch mode {
			case "document":
				if err != nil || ident.DID.String() != did {
					t.Fatalf("configured PLC: identity=%v, error=%v", ident, err)
				}
				base := r.dir.(*identity.CacheDirectory).Inner.(*identity.BaseDirectory)
				for _, path := range []string{"/.well-known/did.json", "/directory/did:plc:abc%2F..%2Fsecret", "/directory/" + did + "?other=path"} {
					if resp, err := base.HTTPClient.Get(plc.URL + path); err == nil {
						resp.Body.Close()
						t.Fatalf("PLC exception accepted unrelated path %s", path)
					}
				}
			case "oversized":
				if !errors.Is(err, gttp.ErrResponseTooLarge) {
					t.Fatalf("want size rejection, got %v", err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("want cancellation, got %v", err)
				}
			case "redirect":
				if err == nil || redirected.Load() != 0 {
					t.Fatalf("PLC redirect: error=%v, requests=%d", err, redirected.Load())
				}
			}
		})
	}
}
