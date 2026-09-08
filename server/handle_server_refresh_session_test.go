package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const refreshSessionPath = "/xrpc/com.atproto.server.refreshSession"

func TestRefreshSessionRejectsOAuthGrant(t *testing.T) {
	s, session := setupRefreshTest(t)
	attachOauthProvider(t, s)
	proof := newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+refreshSessionPath, &session.AccessToken)
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
	var legacy models.Token
	if err := s.db.Client().Where("token = ?", session.AccessToken).First(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	// OAuth resource authentication uses the token row and matching DPoP key.
	grant := provider.OauthToken{
		Token: session.AccessToken, Sub: legacy.Did, ClientId: "http://localhost",
		RefreshToken: "oauth-refresh-test", ExpiresAt: time.Now().Add(time.Hour),
		Parameters: provider.ParRequest{Scope: "atproto", DpopJkt: &jkt},
	}
	if err := s.db.Create(context.Background(), &grant, nil).Error; err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, refreshSessionPath, nil)
	r.Header.Set("Authorization", "DPoP "+grant.Token)
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("expected OAuth rejection, got %d", w.Code)
	}
	var count int64
	if err := s.db.Client().Model(&models.RefreshToken{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("unexpected legacy credentials: %d", count)
	}
}

func refreshRequest(s *Server, authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, refreshSessionPath, nil)
	r.Header.Set("Authorization", authorization)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

func setupRefreshTest(t *testing.T) (*Server, *Session) {
	t.Helper()
	s := newTestServer(t)
	account := s.createTestAccount(t, "refresh.pds.test")
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.createSession(context.Background(), &repo.Repo)
	if err != nil {
		t.Fatal(err)
	}
	s.echo = echo.New()
	s.echo.Validator = newTestValidator()
	s.addRoutes()
	return s, session
}

func TestRefreshSessionRejectsOtherCredentials(t *testing.T) {
	s, session := setupRefreshTest(t)
	for _, auth := range []string{"", "Bearer " + session.AccessToken, "DPoP " + session.AccessToken} {
		// No OAuth provider is installed: refresh must reject DPoP before
		// entering OAuth authentication, irrespective of the token/proof.
		w := refreshRequest(s, auth)
		if w.Code < 400 || w.Code >= 500 {
			t.Fatalf("expected client error, got %d", w.Code)
		}
	}
	if w := refreshRequest(s, "Bearer "+session.RefreshToken); w.Code != 200 {
		t.Fatalf("valid refresh: %d %s", w.Code, w.Body.String())
	}
}

func TestRefreshSessionRotationAndReplay(t *testing.T) {
	s, session := setupRefreshTest(t)
	w := refreshRequest(s, "Bearer "+session.RefreshToken)
	if w.Code != 200 {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	var next ComAtprotoServerRefreshSessionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if next.AccessJwt == "" || next.RefreshJwt == "" || next.RefreshJwt == session.RefreshToken {
		t.Fatal("missing or unchanged replacement credentials")
	}
	if w := refreshRequest(s, "Bearer "+session.RefreshToken); w.Code < 400 {
		t.Fatal("consumed refresh token accepted")
	}
	for _, tc := range []struct {
		token string
		want  int
	}{{session.AccessToken, 400}, {next.AccessJwt, 200}} {
		r := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.server.getSession", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if (tc.want == 200 && w.Code != 200) || (tc.want == 400 && w.Code < 400) {
			t.Fatalf("access token status: %d", w.Code)
		}
	}
	if w := refreshRequest(s, "Bearer "+next.RefreshJwt); w.Code != 200 {
		t.Fatalf("next refresh: %d", w.Code)
	}
}

func TestRefreshSessionConcurrentConsumption(t *testing.T) {
	s, session := setupRefreshTest(t)
	pool, err := s.db.Client().DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	// Synchronize after authentication so both requests reach the handler
	// with a token that existed when middleware validated it.
	var ready sync.WaitGroup
	ready.Add(2)
	s.echo.POST(refreshSessionPath, s.handleRefreshSession, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware,
		func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				ready.Done()
				ready.Wait()
				return next(c)
			}
		})
	results := make(chan int, 2)
	for range 2 {
		go func() { results <- refreshRequest(s, "Bearer "+session.RefreshToken).Code }()
	}
	a, b := <-results, <-results
	if !((a == 200 && b >= 400) || (b == 200 && a >= 400)) {
		t.Fatalf("expected one success, got %d and %d", a, b)
	}
	var count int64
	if err := s.db.Client().Model(&models.RefreshToken{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected one refresh token, got %d", count)
	}
}

func TestRefreshSessionRollback(t *testing.T) {
	s, session := setupRefreshTest(t)
	if err := s.db.Client().Exec(`CREATE TRIGGER reject_refresh BEFORE INSERT ON refresh_tokens BEGIN SELECT RAISE(ABORT, 'test failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if w := refreshRequest(s, "Bearer "+session.RefreshToken); w.Code < 400 {
		t.Fatal("expected insertion failure")
	}
	for _, table := range []string{"tokens", "refresh_tokens"} {
		var count int64
		if err := s.db.Client().Table(table).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s: expected original row only, got %d", table, count)
		}
	}
	if err := s.db.Client().Exec("DROP TRIGGER reject_refresh").Error; err != nil {
		t.Fatal(err)
	}
	if w := refreshRequest(s, "Bearer "+session.RefreshToken); w.Code != 200 {
		t.Fatalf("original credential not restored: %d", w.Code)
	}
}
