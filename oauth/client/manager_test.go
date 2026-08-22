package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestGetClientJWKSWithRefreshRotatesInlineMetadataKey(t *testing.T) {
	oldKey := testClientPublicJWK(t, "old")
	newKey := testClientPublicJWK(t, "new")

	var mu sync.RWMutex
	metadataKey := oldKey
	var metadataRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		metadataRequests++
		key := metadataKey
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(testClientMetadata(t, r, key, ""))
	}))
	defer server.Close()

	clientID := server.URL + "/client"
	manager := NewManager(ManagerArgs{Cli: server.Client()})

	keys, err := manager.GetClientJWKS(t.Context(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	assertClientKey(t, keys, "old")

	mu.Lock()
	metadataKey = newKey
	mu.Unlock()

	keys, err = manager.GetClientJWKS(t.Context(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	assertClientKey(t, keys, "old")
	mu.RLock()
	if metadataRequests != 1 {
		t.Fatalf("normal lookup made %d metadata requests, want 1", metadataRequests)
	}
	mu.RUnlock()

	keys, err = manager.GetClientJWKSWithRefresh(t.Context(), clientID, true)
	if err != nil {
		t.Fatal(err)
	}
	assertClientKey(t, keys, "new")
	mu.RLock()
	if metadataRequests != 2 {
		t.Fatalf("forced lookup made %d metadata requests, want 2", metadataRequests)
	}
	mu.RUnlock()
}

func TestGetClientJWKSWithRefreshRotatesJWKSEndpointKey(t *testing.T) {
	oldKey := testClientPublicJWK(t, "old")
	newKey := testClientPublicJWK(t, "new")

	var mu sync.RWMutex
	jwksKey := oldKey
	var metadataRequests, jwksRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/client":
			metadataRequests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(testClientMetadata(t, r, jwksKey, serverURLForJWKSEndpoint(r)))
		case "/jwks":
			jwksRequests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(testClientJWKS(t, jwksKey))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	clientID := server.URL + "/client"
	manager := NewManager(ManagerArgs{Cli: server.Client()})

	keys, err := manager.GetClientJWKS(t.Context(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	assertClientKey(t, keys, "old")

	mu.Lock()
	jwksKey = newKey
	mu.Unlock()

	keys, err = manager.GetClientJWKS(t.Context(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	assertClientKey(t, keys, "old")
	mu.RLock()
	if metadataRequests != 1 || jwksRequests != 1 {
		t.Fatalf("normal lookup requests metadata=%d jwks=%d, want 1/1", metadataRequests, jwksRequests)
	}
	mu.RUnlock()

	keys, err = manager.GetClientJWKSWithRefresh(t.Context(), clientID, true)
	if err != nil {
		t.Fatal(err)
	}
	assertClientKey(t, keys, "new")
	mu.RLock()
	if metadataRequests != 2 || jwksRequests != 2 {
		t.Fatalf("forced lookup requests metadata=%d jwks=%d, want 2/2", metadataRequests, jwksRequests)
	}
	mu.RUnlock()
}

func testClientPublicJWK(t *testing.T, kid string) jwk.Key {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	return key
}

func testClientMetadata(t *testing.T, request *http.Request, key jwk.Key, jwksURI string) []byte {
	t.Helper()
	keyBytes, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	var keyObject map[string]any
	if err := json.Unmarshal(keyBytes, &keyObject); err != nil {
		t.Fatal(err)
	}
	metadata := map[string]any{
		"client_id":                       "http://" + request.Host + request.URL.Path,
		"client_uri":                      "https://client.example.com",
		"redirect_uris":                   []string{"https://client.example.com/callback"},
		"grant_types":                     []string{"authorization_code"},
		"response_types":                  []string{"code"},
		"application_type":                "web",
		"dpop_bound_access_tokens":        true,
		"scope":                           "atproto",
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
	}
	if jwksURI == "" {
		metadata["jwks"] = map[string]any{"keys": []any{keyObject}}
	} else {
		metadata["jwks_uri"] = jwksURI
	}
	body, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func testClientJWKS(t *testing.T, key jwk.Key) []byte {
	t.Helper()
	keyBytes, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	var keyObject map[string]any
	if err := json.Unmarshal(keyBytes, &keyObject); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"keys": []any{keyObject}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func serverURLForJWKSEndpoint(request *http.Request) string {
	return "http://" + request.Host + "/jwks"
}

func assertClientKey(t *testing.T, keys jwk.Set, want string) {
	t.Helper()
	if keys.Len() != 1 {
		t.Fatalf("key set length = %d, want 1", keys.Len())
	}
	if _, ok := keys.LookupKeyID(want); !ok {
		t.Fatalf("key set does not contain %q", want)
	}
}
