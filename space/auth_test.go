package space

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var testAuthNow = time.Unix(1_700_000_000, 0)
var testAuthSpace = "at://did:plc:z72i7hdynmk6r22z27h6tvur/space/com.example.space/alpha"
var testAuthAuthority = "did:plc:z72i7hdynmk6r22z27h6tvur"
var testAuthUser = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"

func testP256Signer(t *testing.T) *ECDSASigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewECDSASigner(key, "ES256", nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
func testVerifier(t *testing.T, signer *ECDSASigner) *ECDSAVerifier {
	t.Helper()
	v, err := NewECDSAVerifier(signer.PublicKey(), "ES256")
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func testClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestSpaceTokenContractsRoundTrip(t *testing.T) {
	signer := testP256Signer(t)
	v := testVerifier(t, signer)
	delegation, err := CreateDelegationToken(CreateSpaceTokenOptions{
		Iss: testAuthUser, Sub: testAuthSpace, Aud: testAuthAuthority + SpaceHostAudienceSuffix,
		JTI: "delegation-vector", Now: testClock(testAuthNow),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSpaceToken(TokenDelegation, delegation)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Typ != DelegationTokenType || parsed.Header.Alg != "ES256" || parsed.Header.Kid != "#atproto" {
		t.Fatalf("unexpected delegation header: %#v", parsed.Header)
	}
	if got := *parsed.Claims.Aud; got != testAuthAuthority+SpaceHostAudienceSuffix {
		t.Fatal(got)
	}
	if _, err := VerifyDelegationToken(context.Background(), delegation, VerifySpaceTokenOptions{Verifier: v, Now: testClock(testAuthNow)}); err != nil {
		t.Fatal(err)
	}

	jktBytes := make([]byte, 32)
	for i := range jktBytes {
		jktBytes[i] = byte(i)
	}
	jkt := base64.RawURLEncoding.EncodeToString(jktBytes)
	credential, err := CreateCredential(CreateSpaceTokenOptions{
		Iss: testAuthAuthority, Sub: testAuthSpace, DPoPJKT: jkt, Kid: SpaceSigningKeyID,
		JTI: "credential-vector", Now: testClock(testAuthNow),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := VerifyCredential(context.Background(), credential, VerifySpaceTokenOptions{Verifier: v, Now: testClock(testAuthNow), Issuer: testAuthAuthority, Subject: testAuthSpace})
	if err != nil {
		t.Fatal(err)
	}
	if ct.Claims.Aud != nil || ct.Claims.Cnf == nil || ct.Claims.Cnf.JKT != jkt {
		t.Fatalf("credential claims: %#v", ct.Claims)
	}

	attestation, err := CreateClientAttestation(CreateSpaceTokenOptions{
		Iss: "https://client.example/id", Sub: "https://client.example/id", Aud: testAuthAuthority + SpaceHostAudienceSuffix,
		JTI: "attestation-vector", Now: testClock(testAuthNow),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	at, err := VerifyClientAttestation(context.Background(), attestation, VerifySpaceTokenOptions{Verifier: v, Now: testClock(testAuthNow), Audience: testAuthAuthority + SpaceHostAudienceSuffix})
	if err != nil {
		t.Fatal(err)
	}
	if at.Header.Kid != "" || at.Claims.Iss != at.Claims.Sub {
		t.Fatalf("attestation: %#v", at)
	}
}

func TestSpaceTokenStrictClaimMatrices(t *testing.T) {
	signer := testP256Signer(t)
	valid, err := CreateDelegationToken(CreateSpaceTokenOptions{Iss: testAuthUser, Sub: testAuthSpace, Aud: testAuthAuthority + SpaceHostAudienceSuffix, JTI: "strict", Now: testClock(testAuthNow)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, ".")
	payload := `{"iss":"` + testAuthUser + `","iss":"` + testAuthUser + `","sub":"` + testAuthSpace + `","aud":"` + testAuthAuthority + SpaceHostAudienceSuffix + `","iat":1700000000,"exp":1700000060,"jti":"strict"}`
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(payload))
	if _, err := ParseSpaceToken(TokenDelegation, strings.Join(parts, ".")); err == nil {
		t.Fatal("duplicate claim accepted")
	}
	payload = `{"iss":"` + testAuthUser + `","sub":"` + testAuthSpace + `","aud":"` + testAuthAuthority + SpaceHostAudienceSuffix + `","iat":1700000000,"exp":1700000060,"jti":"strict","extra":true}`
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(payload))
	if _, err := ParseSpaceToken(TokenDelegation, strings.Join(parts, ".")); err == nil {
		t.Fatal("unknown claim accepted")
	}
	payload = `{"iss":"` + testAuthUser + `","sub":"` + testAuthSpace + `","aud":[],"iat":1700000000,"exp":1700000060,"jti":"strict"}`
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(payload))
	if _, err := ParseSpaceToken(TokenDelegation, strings.Join(parts, ".")); err == nil {
		t.Fatal("wrong claim type accepted")
	}

	if _, err := CreateDelegationToken(CreateSpaceTokenOptions{Iss: testAuthUser, Sub: testAuthSpace, Aud: "wrong", JTI: "bad", Now: testClock(testAuthNow)}, signer); err == nil {
		t.Fatal("wrong delegation audience accepted")
	}
	if _, err := CreateCredential(CreateSpaceTokenOptions{Iss: testAuthAuthority, Sub: testAuthSpace, Aud: "forbidden", DPoPJKT: "bad", JTI: "bad", Now: testClock(testAuthNow)}, signer); err == nil {
		t.Fatal("invalid credential claims accepted")
	}
	if _, err := CreateClientAttestation(CreateSpaceTokenOptions{Iss: "a", Sub: "b", Aud: testAuthAuthority + SpaceHostAudienceSuffix, JTI: "bad", Now: testClock(testAuthNow)}, signer); err == nil {
		t.Fatal("mismatched attestation issuer accepted")
	}
}

func TestSpaceTokenExpiryAndReplayAreAtomic(t *testing.T) {
	signer := testP256Signer(t)
	verifier := testVerifier(t, signer)
	tok, err := CreateDelegationToken(CreateSpaceTokenOptions{Iss: testAuthUser, Sub: testAuthSpace, Aud: testAuthAuthority + SpaceHostAudienceSuffix, JTI: "concurrent", Now: testClock(testAuthNow)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDelegationToken(context.Background(), tok, VerifySpaceTokenOptions{Verifier: verifier, Now: testClock(testAuthNow.Add(2 * time.Minute))}); err == nil {
		t.Fatal("expired token accepted")
	}
	store := NewMemoryReplayStoreWithClock(testClock(testAuthNow))
	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	var mu sync.Mutex
	successes := 0
	replays := 0
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, e := VerifyDelegationToken(context.Background(), tok, VerifySpaceTokenOptions{Verifier: verifier, Now: testClock(testAuthNow), Replay: store})
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				successes++
			} else if errors.Is(e, ErrReplay) {
				replays++
			} else {
				t.Errorf("unexpected concurrent error: %v", e)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || replays != n-1 {
		t.Fatalf("replay outcomes success=%d replay=%d", successes, replays)
	}
}

func TestDPoPProofChecksAndReplay(t *testing.T) {
	signer := testP256Signer(t)
	jkt, err := DpopJKTForKey(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := CreateDpopProof(signer, CreateDpopProofOptions{Htm: "POST", Htu: "https://HOST.example/path?query=ignored#fragment", JTI: "dpop-issuance", Now: testClock(testAuthNow)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyDpopProof(context.Background(), proof, VerifyDpopProofOptions{Htm: "POST", Htu: "https://host.example/path?different=1", JKT: jkt, Now: testClock(testAuthNow)})
	if err != nil {
		t.Fatal(err)
	}
	if got.JKT != jkt || got.HTU != "https://host.example/path" {
		t.Fatalf("proof: %#v", got)
	}
	if _, err := VerifyDpopProof(context.Background(), proof, VerifyDpopProofOptions{Htm: "GET", Htu: "https://host.example/path", Now: testClock(testAuthNow)}); err == nil {
		t.Fatal("method mismatch accepted")
	}
	if _, err := VerifyDpopProof(context.Background(), proof, VerifyDpopProofOptions{Htm: "POST", Htu: "https://other.example/path", Now: testClock(testAuthNow)}); err == nil {
		t.Fatal("URL mismatch accepted")
	}
	if _, err := VerifyDpopProof(context.Background(), proof, VerifyDpopProofOptions{Htm: "POST", Htu: "https://host.example/path", JKT: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Now: testClock(testAuthNow)}); err == nil {
		t.Fatal("jkt mismatch accepted")
	}

	credential := "credential.jwt"
	bound, err := CreateDpopProof(signer, CreateDpopProofOptions{Htm: "GET", Htu: "https://host.example/repo", Credential: credential, JTI: "dpop-bound", Now: testClock(testAuthNow)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDpopProof(context.Background(), bound, VerifyDpopProofOptions{Htm: "GET", Htu: "https://host.example/repo", Credential: "wrong", Now: testClock(testAuthNow)}); err == nil {
		t.Fatal("ath mismatch accepted")
	}
	if _, err := VerifyDpopProof(context.Background(), bound, VerifyDpopProofOptions{Htm: "GET", Htu: "https://host.example/repo", Credential: credential, JKT: jkt, Now: testClock(testAuthNow)}); err != nil {
		t.Fatal(err)
	}
	store := NewMemoryReplayStoreWithClock(testClock(testAuthNow))
	if _, err := VerifyDpopProof(context.Background(), bound, VerifyDpopProofOptions{Htm: "GET", Htu: "https://host.example/repo", Credential: credential, JKT: jkt, Replay: store, Now: testClock(testAuthNow)}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDpopProof(context.Background(), bound, VerifyDpopProofOptions{Htm: "GET", Htu: "https://host.example/repo", Credential: credential, JKT: jkt, Replay: store, Now: testClock(testAuthNow)}); !errors.Is(err, ErrReplay) {
		t.Fatalf("second proof error = %v", err)
	}
}

func TestDPoPProofAcceptsOptionalNonce(t *testing.T) {
	signer := testP256Signer(t)
	proof, err := CreateDpopProof(signer, CreateDpopProofOptions{
		Htm: "POST", Htu: "https://host.example/xrpc/com.atproto.space.getSpaceCredential",
		Nonce: "oauth-nonce", JTI: "dpop-with-nonce", Now: testClock(testAuthNow),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDpopProof(context.Background(), proof, VerifyDpopProofOptions{
		Htm: "POST", Htu: "https://host.example/xrpc/com.atproto.space.getSpaceCredential",
		Now: testClock(testAuthNow),
	}); err != nil {
		t.Fatalf("nonce-bearing issuance proof rejected: %v", err)
	}
}

func TestDPoPProofAcceptsStandardPublicJWKMetadata(t *testing.T) {
	signer := testP256Signer(t)
	proof, err := CreateDpopProof(signer, CreateDpopProofOptions{
		Htm: "POST", Htu: "https://host.example/xrpc/com.atproto.space.getSpaceCredential",
		JTI: "dpop-atcute-jwk", Now: testClock(testAuthNow),
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("DPoP header jwk = %T, want object", header["jwk"])
	}
	jwk["alg"] = "ES256"
	jwk["kid"] = "dpop-key"
	jwk["use"] = "sig"
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(headerBytes)
	signature, err := signer.Sign([]byte(parts[0] + "." + parts[1]))
	if err != nil {
		t.Fatal(err)
	}
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)

	if _, err := VerifyDpopProof(context.Background(), strings.Join(parts, "."), VerifyDpopProofOptions{
		Htm: "POST", Htu: "https://host.example/xrpc/com.atproto.space.getSpaceCredential",
		Now: testClock(testAuthNow),
	}); err != nil {
		t.Fatalf("standard public JWK metadata rejected: %v", err)
	}
}

func TestAtprotoES256KTokenAdapter(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewAtprotoSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAtprotoVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := CreateDelegationToken(CreateSpaceTokenOptions{
		Iss: testAuthUser, Sub: testAuthSpace, Aud: testAuthAuthority + SpaceHostAudienceSuffix,
		JTI: "es256k-vector", Now: testClock(testAuthNow),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := VerifyDelegationToken(context.Background(), tok, VerifySpaceTokenOptions{Verifier: verifier, Now: testClock(testAuthNow)})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Alg != "ES256K" {
		t.Fatalf("alg = %q", parsed.Header.Alg)
	}
}

func TestClientAttestationExplicitKidSelectsMultiKeyResolver(t *testing.T) {
	signerA := testP256Signer(t)
	signerB := testP256Signer(t)
	verifierA := testVerifier(t, signerA)
	verifierB := testVerifier(t, signerB)
	keys := map[string]Verifier{"client-a": verifierA, "client-b": verifierB}
	var requests []KeyResolutionRequest
	var mu sync.Mutex
	resolver := SigningKeyResolverFunc(func(_ context.Context, req KeyResolutionRequest) (Verifier, error) {
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()
		key := keys[req.Kid]
		if key == nil {
			return nil, errors.New("unknown client kid")
		}
		return key, nil
	})
	for _, tc := range []struct {
		kid    string
		signer Signer
		jti    string
	}{
		{kid: "client-a", signer: signerA, jti: "client-a-jti"},
		{kid: "client-b", signer: signerB, jti: "client-b-jti"},
	} {
		tok, err := CreateClientAttestation(CreateSpaceTokenOptions{
			Iss: "https://client.example/id", Sub: "https://client.example/id",
			Aud: testAuthAuthority + SpaceHostAudienceSuffix, Kid: tc.kid, JTI: tc.jti,
			Now: testClock(testAuthNow),
		}, tc.signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSpaceToken(TokenClientAttestation, tok)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Header.Kid != tc.kid {
			t.Fatalf("kid = %q, want %q", parsed.Header.Kid, tc.kid)
		}
		if _, err := VerifyClientAttestation(context.Background(), tok, VerifySpaceTokenOptions{SigningKeyResolver: resolver, Now: testClock(testAuthNow)}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || requests[0].Kid != "client-a" || requests[1].Kid != "client-b" {
		t.Fatalf("resolver requests = %#v", requests)
	}
	for _, req := range requests {
		if req.ForceRefresh {
			t.Fatal("valid multi-key resolution unexpectedly refreshed")
		}
	}
}

func TestSpaceTokenKeyRefreshRetriesOnceAfterSignatureFailure(t *testing.T) {
	cachedSigner := testP256Signer(t)
	freshSigner := testP256Signer(t)
	cachedVerifier := testVerifier(t, cachedSigner)
	freshVerifier := testVerifier(t, freshSigner)
	tok, err := CreateDelegationToken(CreateSpaceTokenOptions{
		Iss: testAuthUser, Sub: testAuthSpace, Aud: testAuthAuthority + SpaceHostAudienceSuffix,
		JTI: "refresh-jti", Now: testClock(testAuthNow),
	}, freshSigner)
	if err != nil {
		t.Fatal(err)
	}
	var requests []KeyResolutionRequest
	resolver := SigningKeyResolverFunc(func(_ context.Context, req KeyResolutionRequest) (Verifier, error) {
		requests = append(requests, req)
		if req.ForceRefresh {
			return freshVerifier, nil
		}
		return cachedVerifier, nil
	})
	if _, err := VerifyDelegationToken(context.Background(), tok, VerifySpaceTokenOptions{SigningKeyResolver: resolver, Now: testClock(testAuthNow)}); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0].ForceRefresh || !requests[1].ForceRefresh {
		t.Fatalf("refresh requests = %#v", requests)
	}
	unsafeResolver := SigningKeyResolverFunc(func(_ context.Context, req KeyResolutionRequest) (Verifier, error) {
		if req.ForceRefresh {
			return cachedVerifier, nil
		}
		return cachedVerifier, nil
	})
	if _, err := VerifyDelegationToken(context.Background(), tok, VerifySpaceTokenOptions{SigningKeyResolver: unsafeResolver, Now: testClock(testAuthNow)}); err == nil {
		t.Fatal("accepted token after both cached and refreshed keys failed")
	}
}

func TestCredentialDpopRequiresExpectedJKT(t *testing.T) {
	signer := testP256Signer(t)
	jkt, err := DpopJKTForKey(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	credential := "credential.jwt"
	proof, err := CreateDpopProof(signer, CreateDpopProofOptions{
		Htm: "GET", Htu: "https://host.example/repo", Credential: credential,
		JTI: "jkt-required", Now: testClock(testAuthNow),
	})
	if err != nil {
		t.Fatal(err)
	}
	base := VerifyDpopProofOptions{Htm: "GET", Htu: "https://host.example/repo", Credential: credential, Now: testClock(testAuthNow)}
	if _, err := VerifyDpopProof(context.Background(), proof, base); err == nil {
		t.Fatal("credential-mode proof accepted without expected JKT")
	}
	base.JKT = strings.Repeat("A", 43)
	if base.JKT == jkt {
		t.Fatal("test JKT unexpectedly matched")
	}
	if _, err := VerifyDpopProof(context.Background(), proof, base); err == nil {
		t.Fatal("credential-mode proof accepted with mismatched JKT")
	}
	base.JKT = jkt
	if _, err := VerifyDpopProof(context.Background(), proof, base); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeDpopHTUWHATWGCommonCases(t *testing.T) {
	cases := map[string]string{
		"HTTP://EXAMPLE.COM:80/a/./b/../c?query=1#fragment": "http://example.com/a/c",
		"HTTPS://EXAMPLE.COM:443/a/./b/../c":                "https://example.com/a/c",
		"https://Example.COM:8443/a//b/../c":                "https://example.com:8443/a//c",
		"https://Example.COM/a/%2e%2e/%2E":                  "https://example.com/a/%2e%2e/%2E",
		"https://[2001:DB8::1]:443/./repo":                  "https://[2001:db8::1]/repo",
		"https://example.com":                               "https://example.com/",
	}
	for input, want := range cases {
		got, err := NormalizeDpopHTU(input)
		if err != nil {
			t.Errorf("NormalizeDpopHTU(%q): %v", input, err)
		} else if got != want {
			t.Errorf("NormalizeDpopHTU(%q) = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{
		"https://user:pass@example.com/repo",
		"https://éxample.com/repo",
		"https://例え.テスト/repo",
	} {
		if _, err := NormalizeDpopHTU(input); err == nil {
			t.Errorf("NormalizeDpopHTU(%q) unexpectedly accepted unsupported host", input)
		}
	}
}

type replayExpiryRecorder struct {
	expiresAt time.Time
}

func (r *replayExpiryRecorder) Consume(_ context.Context, _ string, _ string, expiresAt time.Time) error {
	r.expiresAt = expiresAt
	return nil
}

func TestReplayDeadlinesIncludeClockSkew(t *testing.T) {
	signer := testP256Signer(t)
	verifier := testVerifier(t, signer)
	replay := &replayExpiryRecorder{}
	tok, err := CreateDelegationToken(CreateSpaceTokenOptions{
		Iss: testAuthUser, Sub: testAuthSpace, Aud: testAuthAuthority + SpaceHostAudienceSuffix,
		JTI: "deadline-token", Now: testClock(testAuthNow),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDelegationToken(context.Background(), tok, VerifySpaceTokenOptions{
		Verifier: verifier, Replay: replay, Now: testClock(testAuthNow), ClockSkew: ClockSkew,
	}); err != nil {
		t.Fatal(err)
	}
	wantTokenDeadline := testAuthNow.Add(DelegationLifetime).Add(ClockSkew)
	if !replay.expiresAt.Equal(wantTokenDeadline) {
		t.Fatalf("token replay deadline = %s, want %s", replay.expiresAt, wantTokenDeadline)
	}

	jkt, err := DpopJKTForKey(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	replay.expiresAt = time.Time{}
	proof, err := CreateDpopProof(signer, CreateDpopProofOptions{
		Htm: "GET", Htu: "https://example.com/repo", JTI: "deadline-dpop", Now: testClock(testAuthNow),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDpopProof(context.Background(), proof, VerifyDpopProofOptions{
		Htm: "GET", Htu: "https://example.com/repo", JKT: jkt, Replay: replay,
		Now: testClock(testAuthNow), ClockSkew: ClockSkew,
	}); err != nil {
		t.Fatal(err)
	}
	wantDpopDeadline := testAuthNow.Add(MaxDpopProofAge).Add(ClockSkew)
	if !replay.expiresAt.Equal(wantDpopDeadline) {
		t.Fatalf("DPoP replay deadline = %s, want %s", replay.expiresAt, wantDpopDeadline)
	}

	clock := testAuthNow
	store := NewMemoryReplayStoreWithClock(func() time.Time { return clock })
	deadline := clock.Add(time.Second)
	if err := store.Consume(context.Background(), "boundary", "test", deadline); err != nil {
		t.Fatal(err)
	}
	clock = deadline.Add(-time.Nanosecond)
	if err := store.Consume(context.Background(), "boundary", "test", deadline); !errors.Is(err, ErrReplay) {
		t.Fatalf("before deadline error = %v", err)
	}
	clock = deadline
	if err := store.Consume(context.Background(), "boundary", "test", deadline); !errors.Is(err, ErrReplay) {
		t.Fatalf("at deadline error = %v", err)
	}
	clock = deadline.Add(time.Nanosecond)
	if err := store.Consume(context.Background(), "boundary", "test", deadline); err != nil {
		t.Fatalf("after deadline error = %v", err)
	}
}

func TestReplayBatchRollbackAndConcurrentIdenticalMemoryBatches(t *testing.T) {
	expires := testAuthNow.Add(time.Hour)
	store := NewMemoryReplayStoreWithClock(testClock(testAuthNow))
	if err := store.Consume(context.Background(), "batch-middle", "delegation", expires); err != nil {
		t.Fatal(err)
	}
	batch := []ReplayArtifact{
		{JTI: "batch-first", TokenType: "delegation", ExpiresAt: expires},
		{JTI: "batch-middle", TokenType: "delegation", ExpiresAt: expires},
		{JTI: "batch-third", TokenType: "client", ExpiresAt: expires},
	}
	if err := store.ConsumeBatch(context.Background(), batch); !errors.Is(err, ErrReplay) {
		t.Fatalf("batch with consumed middle artifact = %v, want ErrReplay", err)
	}
	if err := store.ConsumeBatch(context.Background(), []ReplayArtifact{batch[0], batch[2]}); err != nil {
		t.Fatalf("fresh artifacts were burned by failed batch: %v", err)
	}

	concurrent := NewMemoryReplayStoreWithClock(testClock(testAuthNow))
	identical := []ReplayArtifact{
		{JTI: "concurrent-delegation", TokenType: "delegation", ExpiresAt: expires},
		{JTI: "concurrent-dpop", TokenType: "dpop", ExpiresAt: expires},
		{JTI: "concurrent-attestation", TokenType: "client", ExpiresAt: expires},
	}
	const attempts = 32
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- concurrent.ConsumeBatch(context.Background(), identical)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrReplay):
			replays++
		default:
			t.Fatalf("unexpected concurrent batch error: %v", err)
		}
	}
	if successes != 1 || replays != attempts-1 {
		t.Fatalf("concurrent identical batches successes=%d replays=%d, want 1/%d", successes, replays, attempts-1)
	}
}

func TestReplayNamespaceAllowsCrossTypeAndRejectsSameTypeDuplicates(t *testing.T) {
	store := NewMemoryReplayStoreWithClock(testClock(testAuthNow))
	expires := testAuthNow.Add(time.Hour)
	if err := store.Consume(context.Background(), "same-jti", "delegation", expires); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "same-jti", "dpop", expires); err != nil {
		t.Fatalf("same JTI across token types = %v", err)
	}
	if err := store.ConsumeBatch(context.Background(), []ReplayArtifact{
		{JTI: "duplicate", TokenType: "delegation", ExpiresAt: expires},
		{JTI: "duplicate", TokenType: "delegation", ExpiresAt: expires},
	}); !errors.Is(err, ErrReplay) {
		t.Fatalf("same-type duplicate batch = %v, want ErrReplay", err)
	}
}

func TestReplayNamespaceCrossTypeConcurrency(t *testing.T) {
	store := NewMemoryReplayStoreWithClock(testClock(testAuthNow))
	expires := testAuthNow.Add(time.Hour)
	types := []string{"delegation", "dpop", "service-auth", "client-attestation"}
	start := make(chan struct{})
	results := make(chan error, len(types))
	var wg sync.WaitGroup
	wg.Add(len(types))
	for _, tokenType := range types {
		go func(tokenType string) {
			defer wg.Done()
			<-start
			results <- store.Consume(context.Background(), "cross-type-jti", tokenType, expires)
		}(tokenType)
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("cross-type concurrent consume = %v", err)
		}
	}
}

func TestGORMReplayLegacyRawJTIBlocksUntilExpiry(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "legacy-replay.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.SpaceReplayJTI{}); err != nil {
		t.Fatal(err)
	}
	store := NewGORMReplayStore(db)
	now := time.Now()
	legacy := &models.SpaceReplayJTI{JTI: "legacy-jti", TokenType: "delegation", ExpiresAt: now.Add(time.Hour)}
	if err := db.Create(legacy).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "legacy-jti", "dpop", now.Add(time.Hour)); !errors.Is(err, ErrReplay) {
		t.Fatalf("unexpired legacy row = %v, want ErrReplay", err)
	}
	if err := db.Model(&models.SpaceReplayJTI{}).Where("jti = ?", legacy.JTI).
		Update("expires_at", now.Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "legacy-jti", "dpop", now.Add(time.Hour)); err != nil {
		t.Fatalf("namespaced consume after legacy removal = %v", err)
	}
	var row models.SpaceReplayJTI
	if err := db.First(&row, "jti = ?", replayKey("legacy-jti", "dpop")).Error; err != nil {
		t.Fatal(err)
	}
}

func TestGORMReplayBatchRollsBackOnReplay(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "replay.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.SpaceReplayJTI{}); err != nil {
		t.Fatal(err)
	}
	store := NewGORMReplayStore(db)
	expires := time.Now().Add(time.Hour)
	if err := store.Consume(context.Background(), "gorm-middle", "delegation", expires); err != nil {
		t.Fatal(err)
	}
	batch := []ReplayArtifact{
		{JTI: "gorm-first", TokenType: "delegation", ExpiresAt: expires},
		{JTI: "gorm-middle", TokenType: "delegation", ExpiresAt: expires},
		{JTI: "gorm-third", TokenType: "client", ExpiresAt: expires},
	}
	if err := store.ConsumeBatch(context.Background(), batch); !errors.Is(err, ErrReplay) {
		t.Fatalf("GORM batch with consumed middle artifact = %v, want ErrReplay", err)
	}
	if err := store.ConsumeBatch(context.Background(), []ReplayArtifact{batch[0], batch[2]}); err != nil {
		t.Fatalf("GORM fresh artifacts were burned by failed batch: %v", err)
	}
}
