package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/identity"
	"github.com/labstack/echo/v4"
)

// A failed or unusable feed generator lookup must produce an error response
// rather than crashing the handler.
func TestProxyGetFeedGeneratorLookupFailure(t *testing.T) {
	const aud = "did:web:appview.test#view"
	const feed = "app.bsky.feed.getFeed"
	const skeleton = "app.bsky.feed.getFeedSkeleton"
	scope := "rpc:" + feed + "?aud=" + url.QueryEscape(aud) + " rpc:" + skeleton + "?aud=" + url.QueryEscape(aud)

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		want    int
	}{
		{"upstream server error", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":"InternalServerError"}`)
		}, 500},
		{"record not found", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"RecordNotFound","message":"Could not locate record"}`)
		}, 400},
		{"record is not a feed generator", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"uri":"at://did:web:owner.test/app.bsky.feed.generator/test","cid":"bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku","value":{"$type":"app.bsky.feed.post","text":"hi","createdAt":"2026-09-09T00:00:00Z"}}`)
		}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(tc.handler)
			t.Cleanup(upstream.Close)

			s := newTestServer(t)
			s.proxyHTTPClient = upstream.Client()
			attachOauthProvider(t, s)
			account := s.createTestAccount(t, "feed.pds.test")
			cache := identity.NewMemCache(10)
			if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
				Id: "did:web:appview.test", Service: []identity.DidDocService{
					{Id: "#view", ServiceEndpoint: upstream.URL},
				},
			}); err != nil {
				t.Fatal(err)
			}
			s.passport = identity.NewPassport(upstream.Client(), cache)
			s.config.FallbackProxy = aud
			s.echo = echo.New()
			s.echo.Validator = newTestValidator()
			s.addRoutes()

			target := "/xrpc/" + feed + "?" + url.Values{"feed": {"at://did:web:owner.test/app.bsky.feed.generator/test"}}.Encode()
			r := httptest.NewRequest("GET", target, strings.NewReader(""))
			r.Header.Set("atproto-proxy", aud)
			setProxyTestOAuth(t, s, r, account.Did, scope)
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
