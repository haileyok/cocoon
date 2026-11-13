package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/haileyok/cocoon/oauth/client"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestGetClientIdentifiesCocoon(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := jwk.NewSet()
	if err := keys.AddKey(key); err != nil {
		t.Fatal(err)
	}

	// Gate each endpoint separately so a metadata failure cannot hide a
	// missing User-Agent on the later JWKS request.
	for _, gatedPath := range []string{"/metadata.json", "/jwks.json"} {
		t.Run(gatedPath, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == gatedPath && r.UserAgent() != "Cocoon (+https://github.com/haileyok/cocoon)" {
					http.Error(w, "Cocoon identification required", http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/metadata.json":
					fmt.Fprintf(w, `{
						"client_id": "https://%s/metadata.json",
						"client_uri": "https://example.com",
						"redirect_uris": ["https://example.com/callback"],
						"scope": "atproto",
						"grant_types": ["authorization_code"],
						"response_types": ["code"],
						"application_type": "web",
						"dpop_bound_access_tokens": true,
						"token_endpoint_auth_method": "private_key_jwt",
						"token_endpoint_auth_signing_alg": "ES256",
						"jwks_uri": "https://%s/jwks.json"
					}`, r.Host, r.Host)
				case "/jwks.json":
					if err := json.NewEncoder(w).Encode(keys); err != nil {
						t.Error(err)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			// Use the test server's client to permit loopback and trust its TLS
			// certificate; production SSRF restrictions are tested separately.
			manager := client.NewManager(client.ManagerArgs{Cli: srv.Client()})
			clientID := srv.URL + "/metadata.json"
			got, err := manager.GetClient(context.Background(), clientID)
			if err != nil {
				t.Fatalf("GetClient: %v", err)
			}
			if got.Metadata.ClientID != clientID {
				t.Errorf("client ID = %q, want %q", got.Metadata.ClientID, clientID)
			}
			if got.JWKS == nil || got.JWKS.Len() != 1 {
				t.Fatal("expected one remote signing key")
			}
			gotKey, _ := got.JWKS.Key(0)
			if !jwk.Equal(gotKey, key) {
				t.Error("remote signing key does not match")
			}
		})
	}
}
