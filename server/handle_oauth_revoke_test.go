package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// newTestDpopProof builds a signed DPoP proof JWT acceptable to the server's
// DpopManager: a fresh ES256 key, the public JWK in the header, and a nonce
// drawn from the provider. When accessToken is non-nil, the `ath` claim binds
// the proof to that token (required when validating a resource request).
func newTestDpopProof(t *testing.T, s *Server, method, htu string, accessToken *string) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("build public jwk: %v", err)
	}
	pubBytes, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	var jwkMap map[string]any
	if err := json.Unmarshal(pubBytes, &jwkMap); err != nil {
		t.Fatalf("unmarshal public jwk: %v", err)
	}

	claims := jwt.MapClaims{
		"iat":   time.Now().Unix(),
		"jti":   helpers.RandomVarchar(20),
		"htm":   method,
		"htu":   htu,
		"nonce": s.oauthProvider.NextNonce(),
	}
	if accessToken != nil {
		hash := sha256.Sum256([]byte(*accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap

	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return signed
}

func countOauthTokens(t *testing.T, s *Server) int64 {
	t.Helper()
	var n int64
	if err := s.db.Raw(context.Background(), "SELECT COUNT(*) FROM oauth_tokens", nil).Scan(&n).Error; err != nil {
		t.Fatalf("count oauth tokens: %v", err)
	}
	return n
}

func seedOauthToken(t *testing.T, s *Server, clientID, accessToken, refreshToken string) {
	t.Helper()
	tok := &provider.OauthToken{
		ClientId: clientID,
		Sub:      "did:plc:revoketestsubjectxxxxxxx",
		Parameters: provider.ParRequest{
			AuthenticateClientRequestBase: provider.AuthenticateClientRequestBase{ClientID: clientID},
			Scope:                         "atproto",
		},
		ExpiresAt:    time.Now().Add(time.Hour),
		Token:        accessToken,
		RefreshToken: refreshToken,
	}
	if err := s.db.Create(context.Background(), tok, nil).Error; err != nil {
		t.Fatalf("seed oauth token: %v", err)
	}
}

func revokeForm(clientID, token string) string {
	form := url.Values{
		"client_id": {clientID},
		"token":     {token},
	}
	return form.Encode()
}

// TestHandleOauthRevokeDeletesToken verifies a known token is removed and the
// endpoint responds 200.
func TestHandleOauthRevokeDeletesToken(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	seedOauthToken(t, s, "http://localhost", "access-abc", "refresh-abc")

	c, rec := newRequestContext(http.MethodPost, "/oauth/revoke", revokeForm("http://localhost", "access-abc"), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err := s.handleOauthRevoke(c); err != nil {
		c.Error(err)
	}

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body %s)", rec.Code, rec.Body.String())
	}
	if n := countOauthTokens(t, s); n != 0 {
		t.Fatalf("expected token row deleted, got %d rows", n)
	}
}

// TestHandleOauthRevokeByRefreshToken verifies the token_type_hint-agnostic
// match: revoking by the refresh token also clears the row.
func TestHandleOauthRevokeByRefreshToken(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	seedOauthToken(t, s, "http://localhost", "access-abc", "refresh-abc")

	c, rec := newRequestContext(http.MethodPost, "/oauth/revoke", revokeForm("http://localhost", "refresh-abc"), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err := s.handleOauthRevoke(c); err != nil {
		c.Error(err)
	}

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body %s)", rec.Code, rec.Body.String())
	}
	if n := countOauthTokens(t, s); n != 0 {
		t.Fatalf("expected token row deleted, got %d rows", n)
	}
}

// TestHandleOauthRevokeUnknownToken verifies revocation of an unknown token is a
// 200 no-op (RFC 7009 §2.2).
func TestHandleOauthRevokeUnknownToken(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	c, rec := newRequestContext(http.MethodPost, "/oauth/revoke", revokeForm("http://localhost", "does-not-exist"), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err := s.handleOauthRevoke(c); err != nil {
		c.Error(err)
	}

	if rec.Code != 200 {
		t.Fatalf("expected 200 for unknown token, got %d (body %s)", rec.Code, rec.Body.String())
	}
}

// TestHandleOauthRevokeScopedToClient verifies a token issued to another client
// is not revoked: deletion is scoped by client_id.
func TestHandleOauthRevokeScopedToClient(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	seedOauthToken(t, s, "http://localhost", "access-abc", "refresh-abc")

	// "http://localhost/" is a distinct (but still valid) localhost client_id.
	c, rec := newRequestContext(http.MethodPost, "/oauth/revoke", revokeForm("http://localhost/", "access-abc"), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err := s.handleOauthRevoke(c); err != nil {
		c.Error(err)
	}

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body %s)", rec.Code, rec.Body.String())
	}
	if n := countOauthTokens(t, s); n != 1 {
		t.Fatalf("expected token to survive cross-client revoke, got %d rows", n)
	}
}

// TestOauthSessionMiddlewareUnknownTokenReturns401 verifies that a DPoP access
// token with no backing oauth_tokens row (e.g. after revocation) is rejected
// with 401 invalid_token and does not call next.
func TestOauthSessionMiddlewareUnknownTokenReturns401(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	accessToken := "revoked-access-token"
	proof := newTestDpopProof(t, s, http.MethodGet, "https://"+testHostname+"/xrpc/com.atproto.server.getSession", &accessToken)

	c, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.server.getSession", "", map[string]string{
		"Authorization": "DPoP " + accessToken,
		"DPoP":          proof,
	})

	called := false
	next := func(e echo.Context) error {
		called = true
		return nil
	}

	if err := s.handleOauthSessionMiddleware(next)(c); err != nil {
		c.Error(err)
	}

	if called {
		t.Fatal("next should not be called for an unknown token")
	}
	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d (body %s)", rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "invalid_token" {
		t.Fatalf("expected error invalid_token, got %q", body["error"])
	}
}
