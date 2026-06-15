package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// newTestDpopProof builds a signed DPoP proof JWT acceptable to the server's
// DpopManager: a fresh ES256 key, the public JWK in the header, and a nonce
// drawn from the provider so the proof passes nonce validation.
func newTestDpopProof(t *testing.T, s *Server, method, htu string) string {
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

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":   time.Now().Unix(),
		"jti":   helpers.RandomVarchar(20),
		"htm":   method,
		"htu":   htu,
		"nonce": s.oauthProvider.NextNonce(),
	})
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap

	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return signed
}

func parForm(redirectURI string) string {
	form := url.Values{
		"client_id":             {"http://localhost"},
		"response_type":         {"code"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"state-1"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"atproto"},
	}
	return form.Encode()
}

func countAuthRequests(t *testing.T, s *Server) int64 {
	t.Helper()
	var n int64
	if err := s.db.Raw(context.Background(), "SELECT COUNT(*) FROM oauth_authorization_requests", nil).Scan(&n).Error; err != nil {
		t.Fatalf("count auth requests: %v", err)
	}
	return n
}

// TestHandleOauthParRejectsUnregisteredRedirectURI verifies that PAR refuses a
// redirect_uri the client has not registered, before persisting any request.
func TestHandleOauthParRejectsUnregisteredRedirectURI(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	body := parForm("https://evil.example.com/cb")
	proof := newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/par")
	c, rec := newRequestContext(http.MethodPost, "/oauth/par", body, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         proof,
	})

	if err := s.handleOauthPar(c); err != nil {
		c.Error(err)
	}

	if rec.Code != 400 {
		t.Fatalf("expected 400 for unregistered redirect_uri, got %d (body %s)", rec.Code, rec.Body.String())
	}
	if n := countAuthRequests(t, s); n != 0 {
		t.Fatalf("expected no authorization request rows, got %d", n)
	}
}

// TestHandleOauthParAcceptsRegisteredRedirectURI verifies that a redirect_uri
// in the client's metadata is accepted and an authorization request persisted.
func TestHandleOauthParAcceptsRegisteredRedirectURI(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	body := parForm("http://127.0.0.1/")
	proof := newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/par")
	c, rec := newRequestContext(http.MethodPost, "/oauth/par", body, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         proof,
	})

	if err := s.handleOauthPar(c); err != nil {
		c.Error(err)
	}

	if rec.Code != 201 {
		t.Fatalf("expected 201 for registered redirect_uri, got %d (body %s)", rec.Code, rec.Body.String())
	}
	if n := countAuthRequests(t, s); n != 1 {
		t.Fatalf("expected exactly one authorization request row, got %d", n)
	}

	var resp OauthParResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode par response: %v", err)
	}
	if resp.RequestURI == "" {
		t.Fatalf("expected a request_uri in response, got empty")
	}
}
