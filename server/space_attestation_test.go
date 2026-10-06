package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/haileyok/cocoon/space"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Ported from packages/pds/tests/client-attestation.test.ts
// (bluesky-social/atproto 5b95b2f2).
//
// The reference unit-tests ClientAttestationVerifier against an injected fetch
// answering a fixed route table. Cocoon verifies attestations inside
// getSpaceCredential (server/space_attestation.go: verifyClientAttestation),
// so each reference case becomes a getSpaceCredential exchange for an
// allowList space whose allowed list holds the client_id under test: a resolve
// means a credential was minted, a reject means the error the reference pins.
// The mock client app stands in for app.example.com, serving metadata and JWKS
// over real HTTP (inline or by jwks_uri, per the reference's metadata()); a
// client whose metadata or jwks_uri cannot be resolved is one served by
// attestRoutesApp with the route missing, so the fetch 404s.

// attestNet is the network the attestation cases run on: an authority hosting
// allowList spaces, a member exchanging delegation tokens for credentials, and
// a mock client app installed so the authority can resolve it.
type attestNet struct {
	net       *spaceNet
	authority *spacePDS
	alice     *actor
	dan       *actor
	app       *mockClientApp
}

func newAttestNet(t *testing.T) *attestNet {
	t.Helper()
	n := newSpaceNet(t)
	a := &attestNet{net: n, authority: n.newPDS()}
	a.alice = a.authority.createActor("alice") // the space authority
	a.dan = a.authority.createActor("dan")     // the member exchanging for a credential
	a.app = n.newMockClientApp(clientAppOpts{})
	a.app.installOn(a.authority)
	return a
}

// hostAud is the audience the authority answers to as space host, the
// reference's SPACE_HOST.
func (a *attestNet) hostAud() string {
	return space.SpaceHostAud(a.alice.did)
}

// attestSpace creates an allowList space admitting clientID, the client_id the
// case under test presents as.
func (a *attestNet) attestSpace(t *testing.T, clientID string) string {
	t.Helper()
	return createSpace(t, a.alice, spaceOpts{members: []*actor{a.dan}, appAccess: allowList(clientID)})
}

// attestExchange exchanges a delegation token for a credential presenting the
// attestation, as the reference's verifier.verify(attestation, spaceHost).
func (a *attestNet) attestExchange(t *testing.T, spaceURI, attestation string) xres {
	t.Helper()
	return exchange(t, a.authority, spaceURI, delegationTokenFor(t, a.dan, spaceURI), newP256Key(t), attestation)
}

// attestRejected asserts an exchange was refused as an invalid client
// attestation, with the message the reference pins where it pins one.
func attestRejected(t *testing.T, r xres, wantMessage string) {
	t.Helper()
	if r.status != 400 || r.errName() != "InvalidClientAttestation" {
		t.Fatalf("want 400 InvalidClientAttestation, got %d: %s", r.status, r.raw)
	}
	if wantMessage != "" && !strings.Contains(r.message(), wantMessage) {
		t.Fatalf("want a message containing %q, got %q", wantMessage, r.message())
	}
}

// attestSignKey generates an independent signing key, as the reference's
// otherKey: a key the client does not publish.
func attestSignKey(t *testing.T) jwk.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Set(jwk.KeyIDKey, "key-1")
	_ = k.Set(jwk.AlgorithmKey, jwa.ES256)
	return k
}

// attestMintFor signs an attestation with explicit iss and sub, for the one
// reference case where they disagree (the mock app's attest always agrees).
func attestMintFor(t *testing.T, signer jwk.Key, iss, sub, aud string) string {
	t.Helper()
	now := time.Now().Unix()
	payload, err := json.Marshal(map[string]any{
		"iss": iss, "sub": sub, "aud": aud,
		"iat": now, "exp": now + 60, "jti": "nonce-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.TypeKey, "atproto-client-attestation+jwt")
	_ = hdrs.Set(jws.KeyIDKey, signer.KeyID())
	out, err := jws.Sign(payload, jws.WithKey(jwa.ES256, signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// attestClientMetadata is the reference suite's metadata() document.
func attestClientMetadata(clientID string, extra map[string]any) map[string]any {
	md := map[string]any{
		"client_id": clientID, "client_name": "Example App",
		"redirect_uris":              []string{"https://app.example.com/cb"},
		"response_types":             []string{"code"},
		"grant_types":                []string{"authorization_code"},
		"scope":                      "atproto",
		"application_type":           "web",
		"token_endpoint_auth_method": "private_key_jwt",
		"dpop_bound_access_tokens":   true,
	}
	for k, v := range extra {
		md[k] = v
	}
	return md
}

// attestRoutesApp stands up a client app serving a fixed route table, as the
// reference's verifierFor(routes): documents resolve only as far as the table
// allows, and every other path 404s. Returns the client_id and jwks_uri the
// served metadata would name.
func attestRoutesApp(t *testing.T, routesFor func(base string) map[string]any) (clientID, jwksURI string) {
	t.Helper()
	var routes map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	base := strings.Replace(srv.URL, "localhost", "127.0.0.1", 1)
	routes = routesFor(base)
	return base + "/client-metadata.json", base + "/jwks.json"
}

func TestClientAttestationVerification(t *testing.T) {
	a := newAttestNet(t)

	t.Run("accepts an attestation signed by a key in the client jwks", func(t *testing.T) {
		// The reference's metadata({ jwks: { keys: [clientKey.publicJwk] } }).
		inline := a.net.newMockClientApp(clientAppOpts{inlineJwks: true})
		sp := a.attestSpace(t, inline.clientID)
		res := a.attestExchange(t, sp, inline.attest(t, a.hostAud(), attestOpts{}))
		mustOK(t, res)
		if res.str("credential") == "" {
			t.Fatalf("no credential minted: %s", res.raw)
		}
	})

	t.Run("accepts an attestation when the client publishes a jwks_uri", func(t *testing.T) {
		// The mock app publishes its JWKS by uri by default.
		sp := a.attestSpace(t, a.app.clientID)
		res := a.attestExchange(t, sp, a.app.attest(t, a.hostAud(), attestOpts{}))
		mustOK(t, res)
		if res.str("credential") == "" {
			t.Fatalf("no credential minted: %s", res.raw)
		}
	})

	t.Run("refuses a replayed attestation, but not a second fresh one", func(t *testing.T) {
		// Single-use per the spec. A captured attestation would otherwise let
		// anyone present as an allow-listed client until it expired, which is
		// exactly the impersonation appAccess allowList is meant to stop.
		sp := a.attestSpace(t, a.app.clientID)
		replayed := a.app.attest(t, a.hostAud(), attestOpts{})

		mustOK(t, a.attestExchange(t, sp, replayed))
		attestRejected(t, a.attestExchange(t, sp, replayed), "already been used")
		mustOK(t, a.attestExchange(t, sp, a.app.attest(t, a.hostAud(), attestOpts{})))
	})

	t.Run("refuses an attestation with no jti to consume", func(t *testing.T) {
		sp := a.attestSpace(t, a.app.clientID)
		res := a.attestExchange(t, sp, a.app.attest(t, a.hostAud(), attestOpts{noJti: true}))
		// The reference expects a reject naming the jti; the token is refused
		// before the client is even resolved.
		attestRejected(t, res, "jti")
	})

	t.Run("refuses an attestation signed by a key the client does not publish", func(t *testing.T) {
		// The forgery this whole check exists to stop: anyone can claim a
		// client_id, only the real client can sign for it.
		sp := a.attestSpace(t, a.app.clientID)
		attestRejected(t, a.attestExchange(t, sp, a.app.attest(t, a.hostAud(), attestOpts{signWith: attestSignKey(t)})), "Invalid client attestation")
	})

	t.Run("refuses an attestation addressed to another space host", func(t *testing.T) {
		sp := a.attestSpace(t, a.app.clientID)
		attestRejected(t, a.attestExchange(t, sp, a.app.attest(t, "did:plc:elsewhere#atproto_space_host", attestOpts{})), "Invalid client attestation")
	})

	t.Run("refuses an expired attestation", func(t *testing.T) {
		sp := a.attestSpace(t, a.app.clientID)
		attestRejected(t, a.attestExchange(t, sp, a.app.attest(t, a.hostAud(), attestOpts{expiresIn: -120})), "Invalid client attestation")
	})

	t.Run("refuses an attestation whose iss and sub disagree", func(t *testing.T) {
		sp := a.attestSpace(t, a.app.clientID)
		attested := attestMintFor(t, a.app.key, a.app.clientID, "https://other.example/x", a.hostAud())
		attestRejected(t, a.attestExchange(t, sp, attested), "Invalid client attestation")
	})

	t.Run("refuses when the client publishes no keys", func(t *testing.T) {
		// The reference's metadata() with neither jwks nor jwks_uri.
		noKeys := a.net.newMockClientApp(clientAppOpts{publishKeys: boolp(false)})
		sp := a.attestSpace(t, noKeys.clientID)
		attestRejected(t, a.attestExchange(t, sp, noKeys.attest(t, a.hostAud(), attestOpts{})), "publishes no keys")
	})

	t.Run("refuses when the client metadata cannot be resolved", func(t *testing.T) {
		// The reference's verifierFor({}): no route answers the client_id.
		clientID, _ := attestRoutesApp(t, func(string) map[string]any { return nil })
		sp := a.attestSpace(t, clientID)
		attestRejected(t, a.attestExchange(t, sp, a.app.attest(t, a.hostAud(), attestOpts{iss: clientID})), "Could not resolve client metadata")
	})

	t.Run("refuses when the jwks_uri cannot be resolved", func(t *testing.T) {
		// The metadata resolves, but the jwks_uri it names does not.
		clientID, jwksURI := attestRoutesApp(t, func(base string) map[string]any {
			return map[string]any{
				"/client-metadata.json": attestClientMetadata(base+"/client-metadata.json", map[string]any{"jwks_uri": base + "/jwks.json"}),
			}
		})
		_ = jwksURI
		sp := a.attestSpace(t, clientID)
		attestRejected(t, a.attestExchange(t, sp, a.app.attest(t, a.hostAud(), attestOpts{iss: clientID})), "Could not resolve client JWKS")
	})
}
