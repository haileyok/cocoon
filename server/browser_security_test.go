package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSameOriginRequest(t *testing.T) {
	s := newTestServer(t) // Hostname pds.test, so https://pds.test is also accepted.
	for _, tc := range []struct {
		name, target, origin, referer string
		want                          bool
	}{
		{"same origin", "https://pds.example/account", "https://pds.example", "", true},
		{"foreign scheme", "https://pds.example/account", "http://pds.example", "", false},
		{"same site subdomain", "https://pds.example/account", "https://evil.pds.example", "", false},
		{"foreign port", "https://pds.example/account", "https://pds.example:444", "", false},
		{"default port", "https://pds.example/account", "https://pds.example:443", "", true},
		{"host case", "https://pds.example/account", "https://PDS.EXAMPLE", "", true},
		{"http dev", "http://localhost:8080/account", "http://localhost:8080", "", true},
		{"ipv6", "http://[::1]:8080/account", "http://[::1]:8080", "", true},
		{"null", "https://pds.example/account", "null", "https://pds.example/account", false},
		{"missing", "https://pds.example/account", "", "", false},
		{"referer fallback", "https://pds.example/account", "", "https://pds.example/account?request_uri=abc", true},
		{"foreign referer scheme", "https://pds.example/account", "", "http://pds.example/account", false},
		{"foreign referer site", "https://pds.example/account", "", "https://evil.pds.example/account", false},
		{"origin takes precedence", "https://pds.example/account", "https://evil.example", "https://pds.example/account", false},
		{"userinfo", "https://pds.example/account", "https://evil@pds.example", "", false},
		{"origin path", "https://pds.example/account", "https://pds.example/path", "", false},
		{"origin query", "https://pds.example/account", "https://pds.example?x=y", "", false},
		{"origin fragment", "https://pds.example/account", "https://pds.example#x", "", false},
		{"scheme relative", "https://pds.example/account", "//pds.example", "", false},
		{"multiple origins", "https://pds.example/account", "https://pds.example https://evil.example", "", false},
		// Behind a proxy that rewrites Host or doesn't forward the scheme, the
		// PDS's own public origin still matches; nothing else does.
		{"configured origin via proxy", "http://127.0.0.1:2583/oauth/authorize", "https://pds.test", "", true},
		{"configured origin referer via proxy", "http://127.0.0.1:2583/oauth/authorize", "", "https://pds.test/oauth/authorize?x=y", true},
		{"configured host over http", "http://127.0.0.1:2583/oauth/authorize", "http://pds.test", "", false},
		{"configured host other port", "http://127.0.0.1:2583/oauth/authorize", "https://pds.test:8443", "", false},
		{"configured sibling via proxy", "http://127.0.0.1:2583/oauth/authorize", "https://evil.pds.test", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newRequestContext("POST", tc.target, "", map[string]string{"Origin": tc.origin, "Referer": tc.referer})
			if tc.origin == "" {
				e.Request().Header.Del("Origin")
			}
			if tc.referer == "" {
				e.Request().Header.Del("Referer")
			}
			if got := s.isSameOriginRequest(e); got != tc.want {
				t.Fatalf("same origin = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSameOriginRejectsAmbiguousHeaders(t *testing.T) {
	s := newTestServer(t)
	for _, headers := range []http.Header{
		{"Origin": {"https://pds.test", "https://evil.test"}},
		{"Origin": {""}, "Referer": {"https://pds.test/account"}},
		{"Referer": {"https://pds.test/account", "https://evil.test/"}},
	} {
		e, _ := newRequestContext("POST", "https://pds.test/account", "", nil)
		e.Request().Header = headers
		if s.isSameOriginRequest(e) {
			t.Fatalf("accepted ambiguous headers: %v", headers)
		}
	}
}

func TestSameOriginBehindTLSProxy(t *testing.T) {
	s := newTestServer(t)
	s.config.Hostname = "pds.example" // Only the forwarded scheme can make https://pds.test match.
	e, _ := newRequestContext("POST", "http://pds.test/account", "", map[string]string{
		"Origin": "https://pds.test", "X-Forwarded-Proto": "https",
	})
	// Echo trusts forwarding headers only from a trusted proxy peer.
	e.Request().RemoteAddr = "127.0.0.1:1234"
	if !s.isSameOriginRequest(e) {
		t.Fatal("legitimate TLS-terminated request was rejected")
	}
	e.Request().Header.Set("Origin", "http://pds.test")
	if s.isSameOriginRequest(e) {
		t.Fatal("foreign scheme accepted behind TLS proxy")
	}
	e.Request().Header.Set("Origin", "https://pds.test")
	e.Request().RemoteAddr = "203.0.113.7:1234"
	if s.isSameOriginRequest(e) {
		t.Fatal("forwarded scheme trusted from a public peer")
	}
}

func TestAuthorizeRequiresSameOriginBeforeChangingRequest(t *testing.T) {
	s, _, cookie := manageServer(t) // Real routes, cookie store and production renderer.
	for _, decision := range []string{"accept", "reject"} {
		for _, tc := range []struct{ name, origin, referer string }{
			{"cross site", "https://attacker.test", ""},
			{"same site sibling", "https://evil.pds.test", ""},
			{"foreign scheme", "http://pds.test", ""},
			{"null origin", "null", "https://pds.test/oauth/authorize"},
			{"missing provenance", "", ""},
			{"foreign referer", "", "https://evil.pds.test/"},
		} {
			t.Run(decision+"/"+tc.name, func(t *testing.T) {
				id := oauth.GenerateRequestId()
				insertAuthRequest(t, s, id)
				form := url.Values{"request_uri": {oauth.EncodeRequestUri(id)}, "accept_or_reject": {decision}}
				r := httptest.NewRequest(http.MethodPost, "https://pds.test/oauth/authorize", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if tc.origin != "" {
					r.Header.Set("Origin", tc.origin)
				}
				if tc.referer != "" {
					r.Header.Set("Referer", tc.referer)
				}
				r.AddCookie(cookie) // SameSite is a browser policy, not a server-side check.
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, r)
				if w.Code != http.StatusForbidden {
					t.Errorf("status = %d, want 403", w.Code)
				}
				var stored provider.OauthAuthorizationRequest
				if err := s.db.First(context.Background(), &stored, "request_id = ?", id).Error; err != nil {
					t.Fatalf("unauthorized request was deleted: %v", err)
				}
				if stored.Code != nil || stored.Sub != nil || stored.Accepted != nil {
					t.Fatal("unauthorized request issued a code or changed consent")
				}
			})
		}
	}
}

func TestAuthorizeAllowsSameOriginRefererFallback(t *testing.T) {
	s, acct, cookie := manageServer(t)
	insertAuthRequest(t, s, "referer-fallback")
	form := url.Values{"request_uri": {oauth.EncodeRequestUri("referer-fallback")}, "accept_or_reject": {"accept"}}
	r := httptest.NewRequest("POST", "https://pds.test/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "https://pds.test/oauth/authorize?client_id=http%3A%2F%2Flocalhost")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("fallback: %d %s", w.Code, w.Body.String())
	}
	var stored provider.OauthAuthorizationRequest
	if err := s.db.First(context.Background(), &stored, "request_id = ?", "referer-fallback").Error; err != nil {
		t.Fatal(err)
	}
	if stored.Code == nil || stored.Sub == nil || *stored.Sub != acct.Did {
		t.Fatal("legitimate fallback did not issue a code for the signed-in account")
	}
}

// A proxy that connects from a public address, or doesn't set
// X-Forwarded-Proto, leaves the backend seeing plain http on an internal host.
// Consent from the PDS's own https pages must keep working there.
func TestAuthorizeAcceptsConfiguredOriginBehindProxy(t *testing.T) {
	s, acct, cookie := manageServer(t)
	insertAuthRequest(t, s, "behind-proxy")
	form := url.Values{"request_uri": {oauth.EncodeRequestUri("behind-proxy")}, "accept_or_reject": {"accept"}}
	r := httptest.NewRequest("POST", "http://10.0.0.5:2583/oauth/authorize", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.7:4321"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://"+testHostname)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "https://app.example/callback?") {
		t.Fatalf("consent behind proxy: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	var stored provider.OauthAuthorizationRequest
	if err := s.db.First(context.Background(), &stored, "request_id = ?", "behind-proxy").Error; err != nil {
		t.Fatal(err)
	}
	if stored.Code == nil || stored.Sub == nil || *stored.Sub != acct.Did {
		t.Fatal("consent behind proxy did not issue a code for the signed-in account")
	}
}

func TestAccountActionsRejectForeignScheme(t *testing.T) {
	s, acct, cookie := manageServer(t)
	token := insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "http://localhost"})
	for _, path := range []string{"/account/switch", "/account/revoke"} {
		form := url.Values{"did": {acct.Did}, "id": {itoa(token.ID)}}
		r := httptest.NewRequest("POST", "https://pds.test"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://pds.test")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code != 403 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("%s: status=%d; must not save a switched session", path, w.Code)
		}
	}
	if err := s.db.First(context.Background(), &provider.OauthToken{}, "id = ?", token.ID).Error; err != nil {
		t.Fatalf("foreign scheme revoked token: %v", err)
	}
}

func TestBrowserSecurityHeadersOnProductionRoutes(t *testing.T) {
	s, _ := recoveryServer(t)
	s.loadTemplates()
	s.echo.Use(browserSecurityHeaders)
	for _, directive := range []string{
		"default-src 'none'", "script-src 'none'", "style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:", "base-uri 'none'", "frame-ancestors 'none'",
	} {
		if !strings.Contains(browserContentSecurityPolicy, directive) {
			t.Errorf("missing browser policy: %s", directive)
		}
	}
	if strings.Contains(browserContentSecurityPolicy, "form-action") {
		t.Fatal("a form-action restriction needs browser tests for cross-origin OAuth callbacks")
	}
	for _, path := range []string{
		"/account", "/account/signin", "/account/signin/verify", "/account/signout",
		"/account/2fa", "/account/2fa/totp", "/account/2fa/yubikey", "/account/not-found", "/oauth/authorize",
	} {
		w := browserDo(s, nil, "GET", path, nil)
		for name, want := range map[string]string{
			"Content-Security-Policy": browserContentSecurityPolicy,
			"X-Frame-Options":         "DENY", "X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "same-origin", "Cache-Control": "no-store",
		} {
			if got := w.Header().Get(name); got != want {
				t.Errorf("%s %s = %q, want %q", path, name, got, want)
			}
		}
	}
	// The real rendered pages, not an alternate renderer, retain their styles.
	w := browserDo(s, nil, "GET", "/account/signin", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `/static/style.css`) {
		t.Fatal("production signin template did not render")
	}
	w = browserDo(s, nil, "POST", "/oauth/authorize", url.Values{})
	if w.Code != 403 || w.Header().Get("Content-Security-Policy") != browserContentSecurityPolicy {
		t.Fatal("CSRF denial lost browser security headers")
	}
}

func TestBrowserSecurityDoesNotChangeProtocolCORS(t *testing.T) {
	s, _ := recoveryServer(t)
	s.echo.Use(browserSecurityHeaders)
	s.echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"}, AllowHeaders: []string{"*"}, AllowMethods: []string{"*"}, AllowCredentials: true,
	}))
	for _, path := range []string{"/oauth/token", "/oauth/par", "/oauth/revoke", "/oauth/jwks", "/xrpc/com.atproto.server.describeServer", "/accounts"} {
		r := httptest.NewRequest("OPTIONS", path, nil)
		r.Header.Set("Origin", "https://app.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s CORS changed: %d %v", path, w.Code, w.Header())
		}
		for _, name := range []string{"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "Cache-Control"} {
			if w.Header().Get(name) != "" {
				t.Errorf("browser header %s leaked onto %s", name, path)
			}
		}
	}
}

// newServerFromArgs builds a Server through New, with the middleware stack and
// session store production uses, then adds routes and migrates like Serve.
func newServerFromArgs(t *testing.T, version string) *Server {
	t.Helper()
	serverDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// New writes nonce.secret to the working directory, and dev builds load
	// templates from ./server/templates.
	if err := os.Symlink(serverDir, filepath.Join(dir, "server")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	rotationKey, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("rotation.key", rotationKey.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateJwk, err := jwk.FromRaw(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateJwk.Set(jwk.KeyIDKey, "test"); err != nil {
		t.Fatal(err)
	}
	jwkBytes, err := json.Marshal(privateJwk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("jwk.key", jwkBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// New registers Echo's Prometheus collectors, which panic if registered twice.
	registerer := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	t.Cleanup(func() { prometheus.DefaultRegisterer = registerer })

	s, err := New(&Args{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Addr:             "127.0.0.1:0",
		DbName:           filepath.Join(dir, "test.db"),
		Version:          version,
		Did:              testDid,
		Hostname:         testHostname,
		RotationKeyPath:  "rotation.key",
		JwkPath:          "jwk.key",
		ContactEmail:     "admin@pds.test",
		AdminPassword:    "admin-test-password",
		SessionSecret:    "browser-cookie-test-signing-key-32",
		SessionCookieKey: "session",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := s.db.Client().DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	s.addRoutes()
	return s
}

// Every save of the browser session must keep HttpOnly, SameSite=Lax and
// (outside dev builds) Secure, including saves that only carry flash messages
// and re-saves of an already signed-in session.
func TestNewKeepsBrowserSessionCookieFlags(t *testing.T) {
	for _, tc := range []struct {
		version string
		secure  bool
	}{{"dev", false}, {"test-release", true}} {
		t.Run(tc.version, func(t *testing.T) {
			s := newServerFromArgs(t, tc.version)
			acct := s.createTestAccount(t, "cookie-policy.pds.test")

			var cookie *http.Cookie
			request := func(method, path string, form url.Values, status int) string {
				t.Helper()
				var body io.Reader
				if form != nil {
					body = strings.NewReader(form.Encode())
				}
				r := httptest.NewRequest(method, "https://"+testHostname+path, body)
				r.Header.Set("Origin", "https://"+testHostname)
				if form != nil {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, r)
				if w.Code != status {
					t.Fatalf("%s %s: status=%d, want %d", method, path, w.Code, status)
				}
				if w.Header().Get("Content-Security-Policy") != browserContentSecurityPolicy || w.Header().Get("X-Frame-Options") != "DENY" {
					t.Errorf("%s %s: browser security headers not wired in New", method, path)
				}
				found := false
				for _, c := range w.Result().Cookies() {
					if c.Name != "session" {
						continue
					}
					found = true
					cookie = c
					if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != tc.secure || c.Path != "/" || c.Domain != "" {
						t.Errorf("%s %s: cookie HttpOnly=%t SameSite=%v Secure=%t Path=%q Domain=%q; want true, Lax, %t, /, host-only",
							method, path, c.HttpOnly, c.SameSite, c.Secure, c.Path, c.Domain, tc.secure)
					}
					if c.MaxAge != int(AccountSessionMaxAge.Seconds()) {
						t.Errorf("%s %s: cookie MaxAge=%d, want %d", method, path, c.MaxAge, int(AccountSessionMaxAge.Seconds()))
					}
				}
				if !found {
					t.Fatalf("%s %s did not save the session", method, path)
				}
				return w.Body.String()
			}

			request("GET", "/account/signin", nil, 200)
			request("POST", "/account/signin", url.Values{"username": {acct.Handle}, "password": {"wrong-password"}}, 303)
			if body := request("GET", "/account/signin", nil, 200); !strings.Contains(body, "Handle or password is incorrect.") {
				t.Fatal("sign-in error flash was not rendered")
			}
			request("POST", "/account/signin", url.Values{"username": {acct.Handle}, "password": {acct.Password}}, 303)
			if body := request("GET", "/account", nil, 200); !strings.Contains(body, acct.Handle) {
				t.Fatal("account page did not accept the signed-in cookie")
			}
			request("POST", "/account/revoke", url.Values{"id": {"999999"}}, 303)
			if body := request("GET", "/account", nil, 200); !strings.Contains(body, "That session was already signed out.") {
				t.Fatal("signed-in flash was not rendered")
			}
			request("GET", "/account/signin?add=1", nil, 200)

			// Protocol endpoints keep their own response policy.
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, httptest.NewRequest("GET", "/xrpc/com.atproto.server.describeServer", nil))
			if w.Code != 200 || w.Header().Get("Content-Security-Policy") != "" || w.Header().Get("X-Frame-Options") != "" {
				t.Errorf("describeServer: status=%d CSP=%q XFO=%q", w.Code, w.Header().Get("Content-Security-Policy"), w.Header().Get("X-Frame-Options"))
			}
		})
	}
}
