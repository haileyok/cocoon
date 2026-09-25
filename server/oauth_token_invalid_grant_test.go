package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/oauth/provider"
)

// postOauthToken drives /oauth/token through the full router with a fresh
// DPoP proof, the way a real client would.
func postOauthToken(t *testing.T, s *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	proof := newTestDpopProof(t, s, "POST", "https://"+testHostname+"/oauth/token", nil)
	r := httptest.NewRequest("POST", "https://"+testHostname+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

// assertInvalidGrant checks the RFC 6749 §5.2 error shape. OAuth clients key
// "this grant is dead, re-authenticate" off error=invalid_grant; any other
// code (e.g. the XRPC-style "InvalidToken") leaves them retrying forever.
func assertInvalidGrant(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("error = %q, want %q (body %s)", body["error"], "invalid_grant", w.Body.String())
	}
	if body["error_description"] == "" {
		t.Fatalf("missing error_description (body %s)", w.Body.String())
	}
}

func TestOauthTokenRefreshInvalidGrant(t *testing.T) {
	for _, tc := range []struct {
		name string
		// seed prepares the DB and returns the refresh token to present.
		seed func(t *testing.T, s *Server, account *testAccount) string
	}{
		{
			name: "unknown refresh token",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				return "never-issued"
			},
		},
		{
			name: "revoked by session version bump",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, account.Did, "revoked-refresh")
				if err := s.db.Exec(context.Background(), "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, account.Did).Error; err != nil {
					t.Fatal(err)
				}
				return "revoked-refresh"
			},
		},
		{
			name: "account no longer exists",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, "did:plc:doesnotexistxxxxxxxxxxxx", "orphan-refresh")
				return "orphan-refresh"
			},
		},
		{
			name: "session expired",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, account.Did, "old-session-refresh")
				old := time.Now().Add(-15 * 24 * time.Hour)
				if err := s.db.Exec(context.Background(), "UPDATE oauth_tokens SET created_at = ? WHERE refresh_token = ?", nil, old, "old-session-refresh").Error; err != nil {
					t.Fatal(err)
				}
				return "old-session-refresh"
			},
		},
		{
			name: "refresh token expired",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, account.Did, "stale-refresh")
				old := time.Now().Add(-15 * 24 * time.Hour)
				if err := s.db.Exec(context.Background(), "UPDATE oauth_tokens SET updated_at = ? WHERE refresh_token = ?", nil, old, "stale-refresh").Error; err != nil {
					t.Fatal(err)
				}
				return "stale-refresh"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			refresh := tc.seed(t, s, account)
			w := postOauthToken(t, s, url.Values{
				"client_id":     {"http://localhost"},
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
			})
			assertInvalidGrant(t, w)
		})
	}
}

func TestOauthTokenAuthorizationCodeInvalidGrant(t *testing.T) {
	const redirectURI = "http://127.0.0.1/"
	verifier := strings.Repeat("verifier", 8)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	for _, tc := range []struct {
		name string
		// seed prepares the DB and returns the authorization code to present.
		seed func(t *testing.T, s *Server, account *testAccount) string
	}{
		{
			name: "unknown or already-used code",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				return "never-issued-code"
			},
		},
		{
			name: "revoked by session version bump",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				ctx := context.Background()
				auth := provider.OauthAuthorizationRequest{
					RequestId: "stale-auth",
					ClientId:  "http://localhost",
					Parameters: provider.ParRequest{
						Scope: "atproto", RedirectURI: redirectURI,
						CodeChallenge: &challenge, CodeChallengeMethod: "S256",
					},
					ExpiresAt: time.Now().Add(time.Hour),
					Sub:       to.StringPtr(account.Did),
					Code:      to.StringPtr("stale-code"),
				}
				if err := s.db.Create(ctx, &auth, nil).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Exec(ctx, "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, account.Did).Error; err != nil {
					t.Fatal(err)
				}
				return "stale-code"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			code := tc.seed(t, s, account)
			w := postOauthToken(t, s, url.Values{
				"client_id":     {"http://localhost"},
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {redirectURI},
				"code_verifier": {verifier},
			})
			assertInvalidGrant(t, w)
		})
	}
}

// seedRefreshToken inserts an OAuth token for a public (auth method "none")
// client with no DPoP key binding, so the request reaches the grant checks.
func seedRefreshToken(t *testing.T, s *Server, sub, refresh string) {
	t.Helper()
	token := provider.OauthToken{
		ClientId:     "http://localhost",
		ClientAuth:   provider.ClientAuth{Method: "none"},
		Sub:          sub,
		Parameters:   provider.ParRequest{Scope: "atproto", RedirectURI: "http://127.0.0.1/"},
		Token:        "access-" + refresh,
		RefreshToken: refresh,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := s.db.Create(context.Background(), &token, nil).Error; err != nil {
		t.Fatal(err)
	}
}
