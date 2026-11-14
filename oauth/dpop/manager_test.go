package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// TestCheckProofClockSkew verifies DPoP proofs tolerate small clock skew
// between client and server instead of failing golang-jwt's zero-leeway
// "Token used before issued" check.
func TestCheckProofClockSkew(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	var pubMap map[string]any
	if err := json.Unmarshal(pubJSON, &pubMap); err != nil {
		t.Fatal(err)
	}

	dm := NewManager(ManagerArgs{
		NonceSecret: make([]byte, 32),
		Hostname:    "pds.example.com",
	})

	sign := func(t *testing.T, iat time.Time, extra jwt.MapClaims) string {
		t.Helper()
		claims := jwt.MapClaims{
			"jti":   uuid.NewString(),
			"htm":   http.MethodPost,
			"htu":   "https://pds.example.com/oauth/par",
			"iat":   iat.Unix(),
			"nonce": dm.NextNonce(),
		}
		for k, v := range extra {
			claims[k] = v
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["typ"] = "dpop+jwt"
		tok.Header["jwk"] = pubMap
		s, err := tok.SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	now := time.Now()
	tests := []struct {
		name      string
		iat       time.Time
		extra     jwt.MapClaims
		wantError bool
	}{
		{name: "client clock 4s ahead", iat: now.Add(4 * time.Second)},
		{name: "client clock 45s ahead", iat: now.Add(45 * time.Second), wantError: true},
		{name: "too old", iat: now.Add(-10 * time.Minute), wantError: true},
		{name: "expired exp", iat: now, extra: jwt.MapClaims{"exp": now.Add(-time.Minute).Unix()}, wantError: true},
		{name: "future nbf within tolerance", iat: now, extra: jwt.MapClaims{"nbf": now.Add(3 * time.Second).Unix()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("DPoP", sign(t, tt.iat, tt.extra))

			_, err := dm.CheckProof(http.MethodPost, "/oauth/par", h, nil)
			if tt.wantError && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
