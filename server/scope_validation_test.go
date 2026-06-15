package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

// stubResolver is a hermetic PermissionSetResolver: only NSIDs in valid resolve.
type stubResolver struct {
	valid map[string]bool
}

func (r stubResolver) ResolvePermissionSet(ctx context.Context, nsid string) error {
	if r.valid[nsid] {
		return nil
	}
	return fmt.Errorf("permission set %q not found", nsid)
}

func parScopeForm(scope string) string {
	form := url.Values{
		"client_id":             {"http://localhost"},
		"response_type":         {"code"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"state-1"},
		"redirect_uri":          {"http://127.0.0.1/"},
		"scope":                 {scope},
	}
	return form.Encode()
}

func postPar(t *testing.T, s *Server, scope string) (int, map[string]string) {
	t.Helper()
	proof := newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/par")
	c, rec := newRequestContext(http.MethodPost, "/oauth/par", parScopeForm(scope), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         proof,
	})
	if err := s.handleOauthPar(c); err != nil {
		c.Error(err)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestParRejectsMalformedScope(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = stubResolver{valid: map[string]bool{}}

	code, body := postPar(t, s, "atproto repo:not a nsid")
	if code != 400 {
		t.Fatalf("expected 400 for malformed scope, got %d (%v)", code, body)
	}
	if body["error"] != "invalid_scope" {
		t.Fatalf("expected error invalid_scope, got %q", body["error"])
	}
}

func TestParRejectsUnresolvableInclude(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = stubResolver{valid: map[string]bool{"site.standard.authFull": true}}

	code, body := postPar(t, s, "atproto include:earth.cirrus.check.invalidnonexistentpermissionset")
	if code != 400 {
		t.Fatalf("expected 400 for unresolvable include, got %d (%v)", code, body)
	}
	if body["error"] != "invalid_scope" {
		t.Fatalf("expected error invalid_scope, got %q", body["error"])
	}
}

func TestParAcceptsResolvableInclude(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = stubResolver{valid: map[string]bool{"site.standard.authFull": true}}

	code, body := postPar(t, s, "atproto include:site.standard.authFull")
	if code != 201 {
		t.Fatalf("expected 201 for resolvable include, got %d (%v)", code, body)
	}
}

func TestParAcceptsLegacyScopes(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	// No resolver needed; legacy scopes contain no include.
	s.scopeResolver = stubResolver{valid: map[string]bool{}}

	code, body := postPar(t, s, "atproto transition:generic")
	if code != 201 {
		t.Fatalf("expected 201 for legacy scopes, got %d (%v)", code, body)
	}
}
