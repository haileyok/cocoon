package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestProxyRPCPermissions(t *testing.T) {
	const aud = "did:web:appview.test#view"
	const timeline = "app.bsky.feed.getTimeline"
	const feed = "app.bsky.feed.getFeed"
	const skeleton = "app.bsky.feed.getFeedSkeleton"
	rpc := func(method, audience string) string { return "rpc:" + method + "?aud=" + url.QueryEscape(audience) }
	for _, tc := range []struct {
		name, method, nsid, scope, header string
		legacy                            bool
		want                              int
	}{
		{"no RPC grant", "GET", timeline, "atproto", aud, false, 403},
		{"matching GET", "GET", timeline, rpc(timeline, aud), aud, false, 200},
		{"fallback audience", "GET", timeline, rpc(timeline, aud), "", false, 200},
		{"different service", "GET", timeline, rpc(timeline, aud), "did:web:appview.test#other", false, 403},
		{"different DID", "GET", timeline, rpc(timeline, "did:web:other.test#view"), aud, false, 403},
		{"bare DID is not service audience", "GET", timeline, rpc(timeline, "did:web:appview.test"), aud, false, 403},
		{"different method", "GET", timeline, rpc(skeleton, aud), aud, false, 403},
		{"POST denied", "POST", "chat.bsky.convo.sendMessage", "atproto", aud, false, 403},
		{"POST permitted", "POST", "chat.bsky.convo.sendMessage", "transition:chat.bsky", aud, false, 200},
		{"legacy", "GET", timeline, "", aud, true, 200},
		{"feed needs both methods", "GET", feed, rpc(feed, aud), aud, false, 403},
		{"skeleton alone is insufficient", "GET", feed, rpc(skeleton, aud), aud, false, 403},
		{"feed permitted", "GET", feed, rpc(feed, aud) + " " + rpc(skeleton, aud), aud, false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			type forwarded struct{ method, path, query, body, auth string }
			seen := make(chan forwarded, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/xrpc/com.atproto.repo.getRecord" {
					io.WriteString(w, `{"uri":"at://did:web:owner.test/app.bsky.feed.generator/test","cid":"bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku","value":{"$type":"app.bsky.feed.generator","did":"did:web:generator.test","displayName":"Test","createdAt":"2026-09-09T00:00:00Z"}}`)
					return
				}
				body, _ := io.ReadAll(r.Body)
				seen <- forwarded{r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Header.Get("Authorization")}
				io.WriteString(w, `{"ok":true}`)
			}))
			t.Cleanup(upstream.Close)
			s := newTestServer(t)
			s.proxyHTTPClient = upstream.Client()
			attachOauthProvider(t, s)
			account := s.createTestAccount(t, "proxy.pds.test")
			cache := identity.NewMemCache(10)
			if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
				Id: "did:web:appview.test", Service: []identity.DidDocService{
					{Id: "#view", ServiceEndpoint: upstream.URL}, {Id: "#other", ServiceEndpoint: upstream.URL},
				},
			}); err != nil {
				t.Fatal(err)
			}
			s.passport = identity.NewPassport(upstream.Client(), cache)
			s.config.FallbackProxy = aud
			s.echo = echo.New()
			s.echo.Validator = newTestValidator()
			s.addRoutes()
			query := "limit=3"
			if tc.nsid == feed {
				query = url.Values{"feed": {"at://did:web:owner.test/app.bsky.feed.generator/test"}}.Encode()
			}
			target := "/xrpc/" + tc.nsid + "?" + query
			body := ""
			if tc.method == "POST" {
				body = `{"text":"test"}`
			}
			r := httptest.NewRequest(tc.method, target, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("atproto-proxy", tc.header)
			if tc.legacy {
				repo, err := s.getRepoActorByDid(context.Background(), account.Did)
				if err != nil {
					t.Fatal(err)
				}
				session, err := s.createSession(context.Background(), &repo.Repo)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			} else {
				setProxyTestOAuth(t, s, r, account.Did, tc.scope)
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == 403 {
				assertInsufficientScope(t, w.Code, w.Body.Bytes())
				if calls.Load() != 0 {
					t.Fatalf("denied request made %d upstream calls", calls.Load())
				}
				return
			}
			wantCalls := int32(1)
			if tc.nsid == feed {
				wantCalls = 2
			}
			if calls.Load() != wantCalls || len(seen) != 1 {
				t.Fatalf("unexpected upstream calls: %d", calls.Load())
			}
			got := <-seen
			if got.method != tc.method || got.path != "/xrpc/"+tc.nsid || got.query != query || got.body != body || w.Body.String() != `{"ok":true}` {
				t.Fatal("proxy changed the request or response payload")
			}
			token, _, err := new(jwt.Parser).ParseUnverified(strings.TrimPrefix(got.auth, "Bearer "), jwt.MapClaims{})
			if err != nil {
				t.Fatal(err)
			}
			claims := token.Claims.(jwt.MapClaims)
			wantAud, wantLxm := "did:web:appview.test", tc.nsid
			if tc.nsid == feed {
				wantAud, wantLxm = "did:web:generator.test", skeleton
			}
			if claims["iss"] != account.Did || claims["aud"] != wantAud || claims["lxm"] != wantLxm {
				t.Fatal("incorrect service-auth claims")
			}
		})
	}
}

func setProxyTestOAuth(t *testing.T, s *Server, r *http.Request, did, scope string) {
	t.Helper()
	access := "proxy-test-access"
	proof := newTestDpopProof(t, s, r.Method, "https://"+testHostname+r.URL.String(), &access)
	parsed, _, err := new(jwt.Parser).ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(parsed.Header["jwk"])
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.ParseKey(keyJSON)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	grant := provider.OauthToken{
		Token: access, Sub: did, ClientId: "http://localhost", RefreshToken: "proxy-test-refresh",
		ExpiresAt: time.Now().Add(time.Hour), Parameters: provider.ParRequest{Scope: scope, DpopJkt: &jkt},
	}
	if err := s.db.Create(context.Background(), &grant, nil).Error; err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "DPoP "+access)
	r.Header.Set("DPoP", proof)
}
