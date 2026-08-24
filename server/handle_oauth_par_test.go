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
	"github.com/haileyok/cocoon/oauth/client"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

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
	proof := newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/par", nil)
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
	proof := newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/par", nil)
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

// TestClientAssertionClockSkew verifies that PAR client authentication tolerates
// normal clock skew without accepting assertions that are materially future-dated.
func TestClientAssertionClockSkew(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, "test-key"); err != nil {
		t.Fatal(err)
	}
	keys := jwk.NewSet()
	if err := keys.AddKey(key); err != nil {
		t.Fatal(err)
	}

	const (
		clientID = "https://client.example/metadata.json"
		audience = "https://" + testHostname
	)
	s := newTestServer(t)
	attachOauthProvider(t, s)
	p := s.oauthProvider
	cl := &client.Client{
		Metadata: &client.Metadata{
			ClientID:                clientID,
			TokenEndpointAuthMethod: "private_key_jwt",
		},
		JWKS: keys,
	}

	sign := func(t *testing.T, issuedAt time.Time) string {
		t.Helper()
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": clientID,
			"sub": clientID,
			"aud": audience,
			"jti": "test-jti",
			"iat": issuedAt.Unix(),
		})
		token.Header["kid"] = "test-key"
		raw, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	assertionType := "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	for _, tt := range []struct {
		name      string
		issuedAt  time.Time
		wantError bool
	}{
		{name: "small positive clock skew", issuedAt: time.Now().Add(10 * time.Second)},
		{name: "excessive positive clock skew", issuedAt: time.Now().Add(time.Minute), wantError: true},
		{name: "assertion too old", issuedAt: time.Now().Add(-2 * time.Minute), wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertion := sign(t, tt.issuedAt)
			_, err := p.Authenticate(t.Context(), provider.AuthenticateClientRequestBase{
				ClientID:            clientID,
				ClientAssertionType: &assertionType,
				ClientAssertion:     &assertion,
			}, cl)
			if tt.wantError && err == nil {
				t.Fatal("expected authentication error")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected authentication error: %v", err)
			}
		})
	}
}

// TestHandleOauthParWithoutDpopProof verifies that a PAR request without a
// DPoP proof header or dpop_jkt parameter is rejected with use_dpop_nonce,
// not a panic.
func TestHandleOauthParWithoutDpopProof(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)

	body := parForm("http://127.0.0.1/")
	c, rec := newRequestContext(http.MethodPost, "/oauth/par", body, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})

	if err := s.handleOauthPar(c); err != nil {
		c.Error(err)
	}

	if rec.Code != 400 {
		t.Fatalf("expected 400 for PAR without DPoP, got %d (body %s)", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp["error"] != "use_dpop_nonce" {
		t.Fatalf("expected error use_dpop_nonce, got %q", resp["error"])
	}
	if rec.Header().Get("DPoP-Nonce") == "" {
		t.Fatal("expected DPoP-Nonce header in response")
	}
	if n := countAuthRequests(t, s); n != 0 {
		t.Fatalf("expected no authorization request rows, got %d", n)
	}
}
