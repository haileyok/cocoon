package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestHandleOauthJwksPublishesKey asserts the JWKS endpoint serves the server's
// public signing key (EC public JWK with kid, no private material).
func TestHandleOauthJwksPublishesKey(t *testing.T) {
	s := newTestServer(t)

	e, rec := newRequestContext(http.MethodGet, "/oauth/jwks", "", nil)
	if err := s.handleOauthJwks(e); err != nil {
		t.Fatalf("handleOauthJwks: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v; raw=%s", err, rec.Body.String())
	}
	if len(body.Keys) == 0 {
		t.Fatalf("keys is empty; body=%s", rec.Body.String())
	}

	k := body.Keys[0]
	for _, field := range []string{"kty", "crv", "x", "y", "kid"} {
		v, ok := k[field]
		if !ok || v == "" {
			t.Fatalf("public jwk missing %q; jwk=%v", field, k)
		}
	}
	if k["kty"] != "EC" {
		t.Fatalf("kty = %v, want EC", k["kty"])
	}
	if _, ok := k["d"]; ok {
		t.Fatalf("public jwk must not contain private component \"d\"; jwk=%v", k)
	}
}
