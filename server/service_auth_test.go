package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	secp256k1secec "gitlab.com/yawning/secp256k1-voi/secec"
)

// mintServiceAuthToken builds an ES256K service-auth JWT signed with the given
// raw k256 key, mirroring how handleServerGetServiceAuth signs tokens.
func mintServiceAuthToken(t *testing.T, signingKey []byte, iss, aud, lxm string, exp time.Time) string {
	t.Helper()

	header, _ := json.Marshal(map[string]string{"alg": "ES256K", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss": iss,
		"aud": aud,
		"lxm": lxm,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
		"jti": "test-jti",
	})

	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(input))

	sk, err := secp256k1secec.NewPrivateKey(signingKey)
	if err != nil {
		t.Fatalf("load signing key: %v", err)
	}
	R, S, _, err := sk.SignRaw(rand.Reader, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	rBytes, sBytes := R.Bytes(), S.Bytes()
	rawsig := make([]byte, 64)
	copy(rawsig[32-len(rBytes):32], rBytes)
	copy(rawsig[64-len(sBytes):], sBytes)

	return input + "." + base64.RawURLEncoding.EncodeToString(rawsig)
}

func TestValidateServiceAuthClaims(t *testing.T) {
	const (
		wantAud = "did:web:pds.test"
		wantLxm = "com.atproto.server.createAccount"
	)

	tests := []struct {
		name    string
		claims  jwt.MapClaims
		wantErr bool
	}{
		{"valid", jwt.MapClaims{"aud": wantAud, "lxm": wantLxm}, false},
		{"wrong aud", jwt.MapClaims{"aud": "did:web:evil.example", "lxm": wantLxm}, true},
		{"missing aud", jwt.MapClaims{"lxm": wantLxm}, true},
		{"wrong lxm", jwt.MapClaims{"aud": wantAud, "lxm": "com.atproto.repo.createRecord"}, true},
		{"missing lxm", jwt.MapClaims{"aud": wantAud}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServiceAuthClaims(tt.claims, wantAud, wantLxm)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateServiceAuthClaims err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestLegacyMiddlewareServiceAuthAud exercises the service-auth path of the
// legacy session middleware: a token whose aud does not equal this PDS's DID
// must be rejected; one with the correct aud must pass through.
func TestLegacyMiddlewareServiceAuthAud(t *testing.T) {
	const lxm = "com.atproto.repo.createRecord"
	target := "/xrpc/" + lxm

	run := func(t *testing.T, aud string) (called bool, code int) {
		s := newTestServer(t)
		acct := s.createTestAccount(t, "alice.pds.test")

		next := func(c echo.Context) error {
			called = true
			return c.String(http.StatusOK, "ok")
		}

		tok := mintServiceAuthToken(t, acct.SigningKey, acct.Did, aud, lxm, time.Now().Add(time.Minute))
		c, rec := newRequestContext(http.MethodPost, target, "", map[string]string{
			"authorization": "Bearer " + tok,
		})

		if err := s.handleLegacySessionMiddleware(next)(c); err != nil {
			c.Error(err)
		}
		return called, rec.Code
	}

	t.Run("wrong aud rejected", func(t *testing.T) {
		called, code := run(t, "did:web:evil.example")
		if called {
			t.Fatal("next handler was reached for a token addressed to a different service")
		}
		if code == http.StatusOK {
			t.Fatalf("expected rejection status, got %d", code)
		}
	})

	t.Run("correct aud allowed", func(t *testing.T) {
		called, code := run(t, testDid)
		if !called {
			t.Fatal("next handler was not reached for a correctly-addressed token")
		}
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d", code)
		}
	})
}
