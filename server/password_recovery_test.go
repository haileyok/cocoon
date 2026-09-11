package server

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func recoveryServer(t *testing.T) (*Server, *testAccount) {
	t.Helper()
	s, account := endpointTestServer(t)
	s.echo.Use(session.Middleware(sessions.NewCookieStore([]byte("recovery-test-cookie-signing-key-32"))))
	return s, account
}

func recoveryRequest(s *Server, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

func requestRecoveryCode(t *testing.T, s *Server, account *testAccount) string {
	t.Helper()
	w := recoveryRequest(s, "POST", "/xrpc/com.atproto.server.requestPasswordReset", `{"email":"`+account.Email+`"}`)
	if w.Code != 200 {
		t.Fatalf("request reset: %d %s", w.Code, w.Body.String())
	}
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil || repo.PasswordResetCode == nil {
		t.Fatalf("missing reset code: %v", err)
	}
	if len(*repo.PasswordResetCode) < 26 {
		t.Fatal("reset code is too short for unauthenticated recovery")
	}
	return *repo.PasswordResetCode
}

func resetWithCode(s *Server, code string) *httptest.ResponseRecorder {
	return recoveryRequest(s, "POST", "/xrpc/com.atproto.server.resetPassword", `{"token":"`+code+`","password":"new-recovery-password"}`)
}

func browserSignin(t *testing.T, s *Server, account *testAccount, password string) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {account.Handle}, "password": {password}}
	r := httptest.NewRequest("POST", "/account/signin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatalf("sign in: %d %s", w.Code, w.Header().Get("Location"))
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == s.config.SessionCookieKey {
			return cookie
		}
	}
	t.Fatal("missing browser cookie")
	return nil
}

func TestPasswordRecoveryRevokesSessions(t *testing.T) {
	s, account := recoveryServer(t)
	ctx := context.Background()
	repo, err := s.getRepoActorByDid(ctx, account.Did)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := s.createSession(ctx, &repo.Repo)
	if err != nil {
		t.Fatal(err)
	}
	cookie := browserSignin(t, s, account, account.Password)
	oauthRequest := httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
	setProxyTestOAuth(t, s, oauthRequest, account.Did, "atproto")
	code := "pending-authorization-code"
	if err := s.db.Create(ctx, &provider.OauthAuthorizationRequest{RequestId: "pending", Sub: &account.Did, Code: &code}, nil).Error; err != nil {
		t.Fatal(err)
	}

	other := s.createTestAccount(t, "other-recovery.pds.test")
	otherRepo, err := s.getRepoActorByDid(ctx, other.Did)
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := s.createSession(ctx, &otherRepo.Repo)
	if err != nil {
		t.Fatal(err)
	}

	resetCode := requestRecoveryCode(t, s, account)
	w := resetWithCode(s, resetCode)
	if w.Code != 200 {
		t.Fatalf("logged-out reset: %d %s", w.Code, w.Body.String())
	}
	updated, err := s.getRepoActorByDid(ctx, account.Did)
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.Password), []byte("new-recovery-password")) != nil || updated.PasswordResetCode != nil || updated.PasswordResetCodeExpiresAt != nil {
		t.Fatal("password/challenge not updated")
	}
	for _, tc := range []struct{ path, token string }{
		{"/xrpc/com.atproto.server.getSession", legacy.AccessToken},
		{"/xrpc/com.atproto.server.refreshSession", legacy.RefreshToken},
	} {
		method := "GET"
		if strings.HasSuffix(tc.path, "refreshSession") {
			method = "POST"
		}
		r := httptest.NewRequest(method, tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code/100 != 4 {
			t.Fatalf("old legacy credential: %d", w.Code)
		}
	}
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, oauthRequest)
	if w.Code/100 != 4 {
		t.Fatalf("old OAuth access: %d", w.Code)
	}
	for _, table := range []string{"oauth_tokens", "oauth_authorization_requests"} {
		var count int64
		if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM "+table+" WHERE sub = ?", nil, account.Did).Scan(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained credentials", table)
		}
	}
	r := httptest.NewRequest("GET", "/account", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/account/signin" {
		t.Fatalf("old browser session: %d", w.Code)
	}
	w = resetWithCode(s, resetCode)
	if w.Code/100 != 4 {
		t.Fatalf("replayed reset: %d", w.Code)
	}
	r = httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
	r.Header.Set("Authorization", "Bearer "+otherSession.AccessToken)
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("other account revoked: %d", w.Code)
	}

	body, _ := json.Marshal(map[string]string{"identifier": account.Handle, "password": "new-recovery-password"})
	w = recoveryRequest(s, "POST", "/xrpc/com.atproto.server.createSession", string(body))
	if w.Code != 200 {
		t.Fatalf("new password login: %d %s", w.Code, w.Body.String())
	}
	newCookie := browserSignin(t, s, account, "new-recovery-password")
	s.echo.GET("/test/session", func(e echo.Context) error {
		repo, _, err := s.getSessionRepoOrErr(e)
		if err != nil {
			return e.NoContent(401)
		}
		return e.String(200, repo.Repo.Did)
	})
	r = httptest.NewRequest("GET", "/test/session", nil)
	r.AddCookie(newCookie)
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != account.Did {
		t.Fatal("new browser session rejected")
	}
}

func TestPasswordRecoveryRejectsInvalidChallenge(t *testing.T) {
	for _, mode := range []string{"wrong", "expired", "missing-expiry"} {
		t.Run(mode, func(t *testing.T) {
			s, account := recoveryServer(t)
			code := requestRecoveryCode(t, s, account)
			switch mode {
			case "wrong":
				code = "wrong-code"
			case "expired":
				if err := s.db.Exec(context.Background(), "UPDATE repos SET password_reset_code_expires_at = ? WHERE did = ?", nil, time.Now().Add(-time.Minute), account.Did).Error; err != nil {
					t.Fatal(err)
				}
			case "missing-expiry":
				if err := s.db.Exec(context.Background(), "UPDATE repos SET password_reset_code_expires_at = NULL WHERE did = ?", nil, account.Did).Error; err != nil {
					t.Fatal(err)
				}
			}
			w := resetWithCode(s, code)
			if w.Code/100 != 4 {
				t.Fatalf("invalid reset: %d", w.Code)
			}
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			if bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(account.Password)) != nil || repo.PasswordResetCode == nil {
				t.Fatal("invalid reset changed account")
			}
		})
	}
}

func TestPasswordRecoveryConcurrentRedemption(t *testing.T) {
	s, account := recoveryServer(t)
	code := requestRecoveryCode(t, s, account)
	pool, err := s.db.Client().DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	var reads atomic.Int32
	ready := make(chan struct{})
	if err := s.db.Client().Callback().Query().After("gorm:query").Register("reset-barrier", func(tx *gorm.DB) {
		if tx.Statement.Table == "repos" {
			if reads.Add(1) == 2 {
				close(ready)
			}
			<-ready
		}
	}); err != nil {
		t.Fatal(err)
	}
	results := make(chan int, 2)
	for range 2 {
		go func() { results <- resetWithCode(s, code).Code }()
	}
	one, two := <-results, <-results
	if err := s.db.Client().Callback().Query().Remove("reset-barrier"); err != nil {
		t.Fatal(err)
	}
	if !((one == 200 && two/100 == 4) || (two == 200 && one/100 == 4)) {
		t.Fatalf("concurrent reset responses: %d, %d", one, two)
	}
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	if repo.SessionVersion != 1 {
		t.Fatalf("session version = %d, want 1", repo.SessionVersion)
	}
}

func TestPasswordRecoveryRollback(t *testing.T) {
	s, account := recoveryServer(t)
	ctx := context.Background()
	code := requestRecoveryCode(t, s, account)
	before, err := s.getRepoActorByDid(ctx, account.Did)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := s.createSession(ctx, &before.Repo)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
	setProxyTestOAuth(t, s, r, account.Did, "atproto")
	if err := s.db.Exec(ctx, `CREATE TRIGGER fail_revocation BEFORE DELETE ON oauth_tokens BEGIN SELECT RAISE(ABORT, 'test revocation failure'); END`, nil).Error; err != nil {
		t.Fatal(err)
	}
	w := resetWithCode(s, code)
	if w.Code != 500 {
		t.Fatalf("failed reset: %d", w.Code)
	}
	after, err := s.getRepoActorByDid(ctx, account.Did)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed reset changed account")
	}
	for _, token := range []string{legacy.AccessToken, legacy.RefreshToken} {
		var count int64
		table := "tokens"
		if token == legacy.RefreshToken {
			table = "refresh_tokens"
		}
		if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM "+table+" WHERE token = ?", nil, token).Scan(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatal("failed reset deleted legacy credential")
		}
	}
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("failed reset revoked OAuth session")
	}
	if err := s.db.Exec(ctx, "DROP TRIGGER fail_revocation", nil).Error; err != nil {
		t.Fatal(err)
	}
	if w := resetWithCode(s, code); w.Code != 200 {
		t.Fatalf("retry after rollback: %d", w.Code)
	}
}

func TestPasswordRecoveryRejectsLateCredentials(t *testing.T) {
	for _, current := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale", true: "current"}[current], func(t *testing.T) {
			s, account := recoveryServer(t)
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			if w := resetWithCode(s, requestRecoveryCode(t, s, account)); w.Code != 200 {
				t.Fatalf("reset: %d", w.Code)
			}
			if current {
				repo, err = s.getRepoActorByDid(context.Background(), account.Did)
				if err != nil {
					t.Fatal(err)
				}
			}
			legacy, err := s.createSession(context.Background(), &repo.Repo)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct{ method, nsid, token string }{
				{"GET", "getSession", legacy.AccessToken}, {"POST", "refreshSession", legacy.RefreshToken},
			} {
				r := httptest.NewRequest(tc.method, "/xrpc/com.atproto.server."+tc.nsid, nil)
				r.Header.Set("Authorization", "Bearer "+tc.token)
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, r)
				if (current && w.Code != 200) || (!current && w.Code/100 != 4) {
					t.Fatalf("late legacy %s: %d", tc.nsid, w.Code)
				}
			}
			r := httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
			setProxyTestOAuth(t, s, r, account.Did, "atproto")
			if err := s.db.Exec(context.Background(), "UPDATE oauth_tokens SET session_version = ? WHERE sub = ?", nil, repo.SessionVersion, account.Did).Error; err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if (current && w.Code != 200) || (!current && w.Code/100 != 4) {
				t.Fatalf("late OAuth access: %d", w.Code)
			}
		})
	}
}

func TestPasswordRecoveryPreservesOtherBrowserAccounts(t *testing.T) {
	s, account := recoveryServer(t)
	other := s.createTestAccount(t, "other-browser.pds.test")
	sess := sessions.NewSession(nil, "legacy-cookie")
	setSessionDids(sess, []string{account.Did, other.Did})
	accounts, changed, err := s.getSessionAccountActors(context.Background(), sess)
	if err != nil || changed || len(accounts) != 2 {
		t.Fatalf("legacy cookie rejected: %v", err)
	}
	if w := resetWithCode(s, requestRecoveryCode(t, s, account)); w.Code != 200 {
		t.Fatalf("reset: %d", w.Code)
	}
	accounts, changed, err = s.getSessionAccountActors(context.Background(), sess)
	if err != nil || !changed || len(accounts) != 1 || accounts[0].Repo.Did != other.Did || getActiveSessionDid(sess) != other.Did {
		t.Fatalf("wrong browser account revoked: %v", err)
	}
}

func TestPasswordRecoveryOAuthExchange(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, version := range []int64{0, 1} {
			t.Run(grant+"/"+map[int64]string{0: "stale", 1: "current"}[version], func(t *testing.T) {
				s, account := recoveryServer(t)
				ctx := context.Background()
				if w := resetWithCode(s, requestRecoveryCode(t, s, account)); w.Code != 200 {
					t.Fatalf("reset: %d", w.Code)
				}
				proof := newTestDpopProof(t, s, "POST", "https://"+testHostname+"/oauth/token", nil)
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
				verifier := strings.Repeat("verifier", 8)
				hash := sha256.Sum256([]byte(verifier))
				challenge := base64.RawURLEncoding.EncodeToString(hash[:])
				params := provider.ParRequest{
					Scope: "atproto", RedirectURI: "http://127.0.0.1/", DpopJkt: &jkt,
					CodeChallenge: &challenge, CodeChallengeMethod: "S256",
				}
				form := url.Values{"client_id": {"http://localhost"}, "grant_type": {grant}}
				if grant == "authorization_code" {
					auth := provider.OauthAuthorizationRequest{RequestId: "recovery-auth", ClientId: "http://localhost", Parameters: params, ExpiresAt: time.Now().Add(time.Hour)}
					if err := s.db.Create(ctx, &auth, nil).Error; err != nil {
						t.Fatal(err)
					}
					cookie := browserSignin(t, s, account, "new-recovery-password")
					consent := url.Values{"request_uri": {oauth.EncodeRequestUri(auth.RequestId)}, "accept_or_reject": {"accept"}}
					r := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(consent.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					r.AddCookie(cookie)
					w := httptest.NewRecorder()
					s.echo.ServeHTTP(w, r)
					if w.Code != 303 {
						t.Fatalf("consent: %d %s", w.Code, w.Body.String())
					}
					var saved provider.OauthAuthorizationRequest
					if err := s.db.First(ctx, &saved, "request_id = ?", auth.RequestId).Error; err != nil {
						t.Fatal(err)
					}
					if saved.SessionVersion != 1 || saved.Code == nil {
						t.Fatal("consent did not capture current session version")
					}
					if err := s.db.Exec(ctx, "UPDATE oauth_authorization_requests SET session_version = ? WHERE request_id = ?", nil, version, auth.RequestId).Error; err != nil {
						t.Fatal(err)
					}
					form.Set("code", *saved.Code)
					form.Set("redirect_uri", params.RedirectURI)
					form.Set("code_verifier", verifier)
				} else {
					token := provider.OauthToken{ClientId: "http://localhost", ClientAuth: provider.ClientAuth{Method: "none"}, Sub: account.Did,
						Parameters: params, Token: "old-access", RefreshToken: "old-refresh", SessionVersion: version, ExpiresAt: time.Now().Add(time.Hour)}
					if err := s.db.Create(ctx, &token, nil).Error; err != nil {
						t.Fatal(err)
					}
					form.Set("refresh_token", token.RefreshToken)
				}
				r := httptest.NewRequest("POST", "https://"+testHostname+"/oauth/token", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("DPoP", proof)
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, r)
				if version == 0 {
					if w.Code/100 != 4 {
						t.Fatalf("stale exchange: %d %s", w.Code, w.Body.String())
					}
					return
				}
				if w.Code != 200 {
					t.Fatalf("current exchange: %d %s", w.Code, w.Body.String())
				}
				var response OauthTokenResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				var saved provider.OauthToken
				if err := s.db.First(ctx, &saved, "token = ?", response.AccessToken).Error; err != nil {
					t.Fatal(err)
				}
				if saved.SessionVersion != 1 || saved.Sub != account.Did || saved.RefreshToken != response.RefreshToken {
					t.Fatal("exchange lost session binding")
				}
			})
		}
	}
}

func TestPasswordRecoverySchemaUpgrade(t *testing.T) {
	s, account := recoveryServer(t)
	ctx := context.Background()
	repo, err := s.getRepoActorByDid(ctx, account.Did)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := s.createSession(ctx, &repo.Repo)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
	setProxyTestOAuth(t, s, r, account.Did, "atproto")
	code := "old-consent"
	if err := s.db.Create(ctx, &provider.OauthAuthorizationRequest{RequestId: "old-request", Sub: &account.Did, Code: &code}, nil).Error; err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"repos", "tokens", "refresh_tokens", "oauth_tokens", "oauth_authorization_requests"} {
		if err := s.db.Exec(ctx, "ALTER TABLE "+table+" DROP COLUMN session_version", nil).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := s.db.AutoMigrate(&models.Repo{}, &models.Token{}, &models.RefreshToken{}, &provider.OauthToken{}, &provider.OauthAuthorizationRequest{}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"repos", "tokens", "refresh_tokens", "oauth_tokens", "oauth_authorization_requests"} {
		var count int64
		if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM "+table+" WHERE session_version = 0", nil).Scan(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s did not migrate existing row to version zero", table)
		}
	}
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("migrated OAuth session: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/xrpc/com.atproto.server.refreshSession", nil)
	r.Header.Set("Authorization", "Bearer "+legacy.RefreshToken)
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("migrated legacy session: %d", w.Code)
	}
}
