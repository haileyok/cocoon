package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

// authKeyDashboardServer builds a server with the account-session middleware
// wired, like the browser dashboard uses, and an account with two sign-in
// keys.
func authKeyDashboardServer(t *testing.T) (*Server, *testAccount, []string) {
	t.Helper()
	s := newTestServer(t)
	s.echo = echo.New()
	s.echo.Validator = newTestValidator()
	s.addRoutes()
	s.loadTemplates()
	s.echo.Use(session.Middleware(sessions.NewCookieStore([]byte("auth-key-test-cookie-signing-key-32"))))

	acct := s.createTestAccount(t, "keys.pds.test")

	var didKeys []string
	for i := 0; i < 2; i++ {
		k, err := atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			t.Fatalf("generate sign-in key: %v", err)
		}
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatalf("derive public sign-in key: %v", err)
		}
		didKeys = append(didKeys, pub.DIDKey())
		if err := s.db.Create(context.Background(), &models.AuthKey{
			Did:       acct.Did,
			DidKey:    pub.DIDKey(),
			CreatedAt: time.Now(),
		}, nil).Error; err != nil {
			t.Fatalf("insert auth key: %v", err)
		}
	}
	return s, acct, didKeys
}

// authKeyDashboardRequest performs a same-origin request with the account's
// browser session cookie.
func authKeyDashboardRequest(t *testing.T, s *Server, acct *testAccount, method, path, form string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(form))
	r.Host = testHostname
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://"+testHostname)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

// browserSessionCookie signs in through the dashboard's password form and
// returns the session cookie.
func browserSessionCookie(t *testing.T, s *Server, acct *testAccount) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {acct.Handle}, "password": {acct.Password}}
	r := httptest.NewRequest(http.MethodPost, "/account/signin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("dashboard sign in failed: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == s.config.SessionCookieKey {
			return c
		}
	}
	t.Fatal("no session cookie after dashboard sign in")
	return nil
}

// The account dashboard lists the account's sign-in keys with a revoke button;
// revoking stops the key signing in and revokes its OAuth sessions.
func TestAccountDashboardAuthKeys(t *testing.T) {
	t.Run("lists sign-in keys", func(t *testing.T) {
		s, acct, didKeys := authKeyDashboardServer(t)
		cookie := browserSessionCookie(t, s, acct)

		r := httptest.NewRequest(http.MethodGet, "/account", nil)
		r.Host = testHostname
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://"+testHostname)
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("account page: %d %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		for _, dk := range didKeys {
			if !strings.Contains(body, dk) {
				t.Errorf("account page should list sign-in key %s", dk)
			}
		}
	})

	t.Run("revoke key", func(t *testing.T) {
		s, acct, didKeys := authKeyDashboardServer(t)
		cookie := browserSessionCookie(t, s, acct)

		form := url.Values{"did_key": {didKeys[0]}}
		r := httptest.NewRequest(http.MethodPost, "/account/auth-keys/revoke", strings.NewReader(form.Encode()))
		r.Host = testHostname
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://"+testHostname)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code/100 != 2 && w.Code/100 != 3 {
			t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
		}

		var revoked models.AuthKey
		if err := s.db.Raw(context.Background(), "SELECT * FROM auth_keys WHERE did = ? AND did_key = ?", nil, acct.Did, didKeys[0]).Scan(&revoked).Error; err != nil {
			t.Fatalf("query key: %v", err)
		}
		if revoked.RevokedAt == nil {
			t.Error("key should be revoked")
		}

		var other models.AuthKey
		if err := s.db.Raw(context.Background(), "SELECT * FROM auth_keys WHERE did = ? AND did_key = ?", nil, acct.Did, didKeys[1]).Scan(&other).Error; err != nil {
			t.Fatalf("query key: %v", err)
		}
		if other.RevokedAt != nil {
			t.Error("other key must stay active")
		}
	})
}
