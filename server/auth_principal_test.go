package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/golang-jwt/jwt/v4"
	cocoon_identity "github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type testDIDDocumentFetcher func(context.Context, string) (*cocoon_identity.DidDoc, error)

func (f testDIDDocumentFetcher) FetchDoc(ctx context.Context, did string) (*cocoon_identity.DidDoc, error) {
	return f(ctx, did)
}
func (f testDIDDocumentFetcher) ResolveHandle(context.Context, string) (string, error) {
	return "", errors.New("test DID fetcher does not resolve handles")
}
func (f testDIDDocumentFetcher) BustDoc(context.Context, string) error { return nil }
func (f testDIDDocumentFetcher) BustDid(context.Context, string) error { return nil }

const authTestSpace = "at://did:plc:z72i7hdynmk6r22z27h6tvur/space/com.example.space/alpha"
const authTestAuthority = "did:plc:z72i7hdynmk6r22z27h6tvur"

type spaceAuthFixture struct {
	token       string
	proof       string
	authority   *space.ECDSASigner
	proofSigner *space.ECDSASigner
	jkt         string
}

func newSpaceAuthFixture(t *testing.T, method, htu string) spaceAuthFixture {
	t.Helper()
	authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := space.NewECDSASigner(authorityKey, "ES256", nil)
	if err != nil {
		t.Fatal(err)
	}
	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofSigner, err := space.NewECDSASigner(proofKey, "ES256", nil)
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := space.DpopJKTForKey(proofSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	token, err := space.CreateCredential(space.CreateSpaceTokenOptions{
		Iss: authTestAuthority, Sub: authTestSpace, DPoPJKT: jkt,
		Kid: space.SpaceSigningKeyID, JTI: "server-auth-credential-" + strings.ToLower(method),
	}, authority)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := space.CreateDpopProof(proofSigner, space.CreateDpopProofOptions{
		Htm: method, Htu: htu, Credential: token, JTI: "server-auth-proof-" + strings.ToLower(method),
	})
	if err != nil {
		t.Fatal(err)
	}
	return spaceAuthFixture{token: token, proof: proof, authority: authority, proofSigner: proofSigner, jkt: jkt}
}

func installSpaceFixture(s *Server, fixture spaceAuthFixture) {
	verifier, err := space.NewECDSAVerifier(fixture.authority.PublicKey(), "ES256")
	if err != nil {
		panic(err)
	}
	s.SetSpaceAuthorityKeyResolver(SpaceAuthorityKeyResolverFunc(func(_ context.Context, req space.KeyResolutionRequest) (space.Verifier, error) {
		if req.Issuer != authTestAuthority {
			return nil, errors.New("unexpected issuer")
		}
		return verifier, nil
	}))
	s.SetSpaceReplayStore(space.NewMemoryReplayStore())
}

func runAuthMiddleware(t *testing.T, middleware echo.MiddlewareFunc, method, target string, headers map[string]string) (bool, echo.Context, int) {
	t.Helper()
	c, rec := newRequestContext(method, target, "", headers)
	called := false
	next := func(e echo.Context) error {
		called = true
		return e.NoContent(http.StatusOK)
	}
	if err := middleware(next)(c); err != nil {
		c.Error(err)
	}
	return called, c, rec.Code
}

func TestSpaceCredentialDispatchInstallsTypedPrincipalWithoutOAuthLookup(t *testing.T) {
	s := newTestServer(t)
	target := "https://pds.test/xrpc/com.example.space.read"
	fixture := newSpaceAuthFixture(t, http.MethodGet, target)
	installSpaceFixture(s, fixture)

	called, c, code := runAuthMiddleware(t, s.OAuthOrSpaceCredential, http.MethodGet, target, map[string]string{
		"Authorization": "DPoP " + fixture.token,
		"DPoP":          fixture.proof,
	})
	if !called || code != http.StatusOK {
		t.Fatalf("credential dispatch called=%v status=%d", called, code)
	}
	principal, ok := PrincipalFromContext(c).(*SpaceCredentialPrincipal)
	if !ok {
		t.Fatalf("principal type = %T, want *SpaceCredentialPrincipal", PrincipalFromContext(c))
	}
	if principal.SpaceURI != authTestSpace || principal.AuthorityDID != authTestAuthority || principal.DPoPJKT != fixture.jkt {
		t.Fatalf("unexpected credential principal: %#v", principal)
	}
}

func TestSpaceCredentialNeverAcceptedByOAuthOnly(t *testing.T) {
	s := newTestServer(t)
	target := "https://pds.test/xrpc/com.example.space.write"
	fixture := newSpaceAuthFixture(t, http.MethodPost, target)
	installSpaceFixture(s, fixture)

	called, _, code := runAuthMiddleware(t, s.OAuthOnly, http.MethodPost, target, map[string]string{
		"Authorization": "DPoP " + fixture.token,
		"DPoP":          fixture.proof,
	})
	if called || code == http.StatusOK {
		t.Fatalf("Space credential reached OAuth-only write route: called=%v status=%d", called, code)
	}
}

func TestOAuthTokenIsNotAcceptedAsSpaceCredential(t *testing.T) {
	s := newTestServer(t)
	claims := jwt.MapClaims{"sub": "did:plc:oauthsubjectxxxxxxxx", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "scope": "atproto"}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "JWT"
	raw, err := token.SignedString(s.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://pds.test/xrpc/com.example.space.read"
	called, _, code := runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, map[string]string{
		"Authorization": "DPoP " + raw,
	})
	if called || code == http.StatusOK {
		t.Fatalf("OAuth JWT was accepted as Space credential: called=%v status=%d", called, code)
	}
}

func TestDelegationExchangeAcceptsBearerDelegationToken(t *testing.T) {
	s := newTestServer(t)
	target := "https://pds.test/xrpc/com.atproto.space.getSpaceCredential"
	fixture := newSpaceAuthFixture(t, http.MethodPost, target)
	installSpaceFixture(s, fixture)

	delegation, err := space.CreateDelegationToken(space.CreateSpaceTokenOptions{
		Iss: authTestAuthority, Sub: authTestSpace,
		Aud: authTestAuthority + space.SpaceHostAudienceSuffix,
		JTI: "server-auth-delegation-bearer",
	}, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := space.CreateDpopProof(fixture.proofSigner, space.CreateDpopProofOptions{
		Htm: http.MethodPost, Htu: target, JTI: "server-auth-delegation-proof",
	})
	if err != nil {
		t.Fatal(err)
	}

	called, c, code := runAuthMiddleware(t, s.DelegationExchange, http.MethodPost, target, map[string]string{
		"Authorization": "Bearer " + delegation,
		"DPoP":          proof,
	})
	if !called || code != http.StatusOK {
		t.Fatalf("Bearer delegation exchange called=%v status=%d", called, code)
	}
	principal, ok := PrincipalFromContext(c).(*DelegationPrincipal)
	if !ok || principal.SpaceURI != authTestSpace || principal.AuthorityDID != authTestAuthority {
		t.Fatalf("delegation principal = %#v", PrincipalFromContext(c))
	}
}

func TestOAuthOnlyDispatchesLegacySessionBearer(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "legacy-space-auth.pds.test")
	repo, err := s.getRepoActorByDid(t.Context(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.createSession(t.Context(), &repo.Repo)
	if err != nil {
		t.Fatal(err)
	}
	called, c, code := runAuthMiddleware(t, s.OAuthOnly, http.MethodGet, "https://pds.test/xrpc/com.atproto.space.listSpaces", map[string]string{
		"Authorization": "Bearer " + session.AccessToken,
	})
	if !called || code != http.StatusOK {
		t.Fatalf("legacy Bearer session called=%v status=%d", called, code)
	}
	principal, ok := PrincipalFromContext(c).(*OAuthPrincipal)
	if !ok || !principal.Legacy || principal.Subject != account.Did {
		t.Fatalf("legacy principal = %#v", PrincipalFromContext(c))
	}
}

func TestOAuthOnlyDispatchRejectsBearerToken(t *testing.T) {
	s := newTestServer(t)
	called, _, code := runAuthMiddleware(t, s.OAuthOnly, http.MethodGet, "https://pds.test/xrpc/com.atproto.space.listSpaces", map[string]string{
		"Authorization": "Bearer oauth-bearer-access",
	})
	if called || code == http.StatusOK {
		t.Fatalf("Bearer OAuth token bypassed DPoP: called=%v status=%d", called, code)
	}
}

func TestSpaceCredentialFailuresTypDPoPJKTATHReplayAndTombstone(t *testing.T) {
	target := "https://pds.test/xrpc/com.example.space.read"

	t.Run("wrong typ", func(t *testing.T) {
		s := newTestServer(t)
		fixture := newSpaceAuthFixture(t, http.MethodGet, target)
		installSpaceFixture(s, fixture)
		authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := space.NewECDSASigner(authorityKey, "ES256", nil)
		if err != nil {
			t.Fatal(err)
		}
		delegation, err := space.CreateDelegationToken(space.CreateSpaceTokenOptions{Iss: authTestAuthority, Sub: authTestSpace, Aud: authTestAuthority + space.SpaceHostAudienceSuffix, JTI: "wrong-typ"}, signer)
		if err != nil {
			t.Fatal(err)
		}
		called, _, code := runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, map[string]string{"Authorization": "DPoP " + delegation, "DPoP": fixture.proof})
		if called || code == http.StatusOK {
			t.Fatal("delegation token accepted by credential-only policy")
		}
	})

	t.Run("bad DPoP typ", func(t *testing.T) {
		s := newTestServer(t)
		fixture := newSpaceAuthFixture(t, http.MethodGet, target)
		installSpaceFixture(s, fixture)
		bad := strings.Replace(fixture.proof, "", "", 1)
		parts := strings.Split(bad, ".")
		var header map[string]any
		if err := json.Unmarshal(mustDecodeSegment(t, parts[0]), &header); err != nil {
			t.Fatal(err)
		}
		header["typ"] = "JWT"
		hb, _ := json.Marshal(header)
		parts[0] = base64.RawURLEncoding.EncodeToString(hb)
		bad = strings.Join(parts, ".")
		called, _, code := runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, map[string]string{"Authorization": "DPoP " + fixture.token, "DPoP": bad})
		if called || code == http.StatusOK {
			t.Fatal("bad DPoP typ accepted")
		}
	})

	t.Run("jkt mismatch", func(t *testing.T) {
		s := newTestServer(t)
		fixture := newSpaceAuthFixture(t, http.MethodGet, target)
		installSpaceFixture(s, fixture)
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		other, err := space.NewECDSASigner(otherKey, "ES256", nil)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := space.CreateDpopProof(other, space.CreateDpopProofOptions{Htm: http.MethodGet, Htu: target, Credential: fixture.token, JTI: "jkt-mismatch"})
		if err != nil {
			t.Fatal(err)
		}
		called, _, code := runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, map[string]string{"Authorization": "DPoP " + fixture.token, "DPoP": proof})
		if called || code == http.StatusOK {
			t.Fatal("JKT mismatch accepted")
		}
	})

	t.Run("ath mismatch", func(t *testing.T) {
		s := newTestServer(t)
		fixture := newSpaceAuthFixture(t, http.MethodGet, target)
		installSpaceFixture(s, fixture)
		proof, err := space.CreateDpopProof(fixture.proofSigner, space.CreateDpopProofOptions{Htm: http.MethodGet, Htu: target, Credential: "different-token", JTI: "ath-mismatch"})
		if err != nil {
			t.Fatal(err)
		}
		called, _, code := runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, map[string]string{"Authorization": "DPoP " + fixture.token, "DPoP": proof})
		if called || code == http.StatusOK {
			t.Fatal("ath mismatch accepted")
		}
	})

	t.Run("replay", func(t *testing.T) {
		s := newTestServer(t)
		fixture := newSpaceAuthFixture(t, http.MethodGet, target)
		installSpaceFixture(s, fixture)
		headers := map[string]string{"Authorization": "DPoP " + fixture.token, "DPoP": fixture.proof}
		called, _, code := runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, headers)
		if !called || code != http.StatusOK {
			t.Fatalf("first credential request called=%v status=%d", called, code)
		}
		called, _, code = runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, headers)
		if called || code == http.StatusOK {
			t.Fatalf("replayed DPoP proof accepted: called=%v status=%d", called, code)
		}
	})

	t.Run("tombstone", func(t *testing.T) {
		s := newTestServer(t)
		fixture := newSpaceAuthFixture(t, http.MethodGet, target)
		installSpaceFixture(s, fixture)
		if err := s.db.Create(context.Background(), &models.SpaceTombstone{Space: authTestSpace, OwnerDID: authTestAuthority, DeletedAt: time.Now()}, nil).Error; err != nil {
			t.Fatal(err)
		}
		called, _, code := runAuthMiddleware(t, s.SpaceCredentialOnly, http.MethodGet, target, map[string]string{"Authorization": "DPoP " + fixture.token, "DPoP": fixture.proof})
		if called || code == http.StatusOK {
			t.Fatal("tombstoned Space credential accepted")
		}
	})
}

func TestDIDSpaceAuthorityResolverFallsBackToAtprotoKey(t *testing.T) {
	fixture := newSpaceAuthFixture(t, http.MethodGet, "https://pds.test/xrpc/test")
	verifier, err := space.NewECDSAVerifier(fixture.authority.PublicKey(), "ES256")
	if err != nil {
		t.Fatal(err)
	}
	var kids []string
	resolver := NewDIDSpaceAuthorityKeyResolver(SpaceAuthorityKeySourceFunc(func(_ context.Context, _, kid, _ string) (space.Verifier, error) {
		kids = append(kids, kid)
		if kid == space.FallbackSigningKeyID {
			return verifier, nil
		}
		return nil, errors.New("space key unavailable")
	}))
	got, err := resolver.ResolveSigningKey(context.Background(), space.KeyResolutionRequest{Issuer: authTestAuthority, Kid: space.SpaceSigningKeyID, Algorithm: "ES256"})
	if err != nil || got == nil {
		t.Fatalf("fallback resolver err=%v key=%v", err, got)
	}
	if len(kids) != 2 || kids[0] != space.SpaceSigningKeyID || kids[1] != space.FallbackSigningKeyID {
		t.Fatalf("resolver kids = %#v", kids)
	}
}

func TestPassportSpaceAuthorityResolverUsesExactKidAlgorithmAndRefresh(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "did:plc:z72i7hdynmk6r22z27h6tvur"
	var refreshed bool
	fetcher := testDIDDocumentFetcher(func(ctx context.Context, did string) (*cocoon_identity.DidDoc, error) {
		if did != issuer {
			return nil, errors.New("unexpected issuer")
		}
		refreshed, _ = ctx.Value("skip-cache").(bool)
		return &cocoon_identity.DidDoc{Id: issuer, VerificationMethods: []cocoon_identity.DidDocVerificationMethod{{
			Id: issuer + "#atproto_space", Type: "Multikey", Controller: issuer, PublicKeyMultibase: public.Multibase(),
		}}}, nil
	})
	resolver := NewPassportSpaceAuthorityKeyResolver(fetcher)
	if _, err := resolver.ResolveSigningKey(context.Background(), space.KeyResolutionRequest{Issuer: issuer, Kid: issuer + "#wrong", Algorithm: "ES256K"}); err == nil {
		t.Fatal("unknown kid resolved")
	}
	if _, err := resolver.ResolveSigningKey(context.Background(), space.KeyResolutionRequest{Issuer: issuer, Kid: issuer + "#atproto_space", Algorithm: "ES256"}); err == nil {
		t.Fatal("algorithm mismatch resolved")
	}
	if _, err := resolver.ResolveSigningKey(context.Background(), space.KeyResolutionRequest{Issuer: issuer, Kid: issuer + "#atproto_space", Algorithm: "ES256K", ForceRefresh: true}); err != nil {
		t.Fatal(err)
	}
	if !refreshed {
		t.Fatal("ForceRefresh did not set Passport skip-cache context")
	}
}

func TestLegacyMiddlewareDoesNotRouteSpaceCredentialToOAuth(t *testing.T) {
	s := newTestServer(t)
	target := "https://pds.test/xrpc/com.example.space.read"
	fixture := newSpaceAuthFixture(t, http.MethodGet, target)
	installSpaceFixture(s, fixture)
	called, _, code := runAuthMiddleware(t, s.handleLegacySessionMiddleware, http.MethodGet, target, map[string]string{
		"Authorization": "DPoP " + fixture.token,
		"DPoP":          fixture.proof,
	})
	if called || code == http.StatusOK {
		t.Fatalf("legacy middleware routed Space credential onward: called=%v status=%d", called, code)
	}
}

func TestServiceAuthOnlyInstallsTypedPrincipal(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "service.pds.test")
	key, err := atcrypto.ParsePrivateBytesK256(account.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "did:plc:z72i7hdynmk6r22z27h6tvur"
	s.passport = testDIDDocumentFetcher(func(_ context.Context, did string) (*cocoon_identity.DidDoc, error) {
		if did != issuer {
			return nil, errors.New("unexpected DID lookup")
		}
		return &cocoon_identity.DidDoc{Id: issuer, VerificationMethods: []cocoon_identity.DidDocVerificationMethod{{
			Id: issuer + "#atproto", Type: "Multikey", Controller: issuer, PublicKeyMultibase: public.Multibase(),
		}}}, nil
	})
	const lxm = "com.atproto.server.createAccount"
	target := "https://pds.test/xrpc/" + lxm
	token := mintServiceAuthToken(t, account.SigningKey, issuer, testDid, lxm, time.Now().Add(time.Minute))
	called, c, code := runAuthMiddleware(t, s.ServiceAuthOnly, http.MethodPost, target, map[string]string{
		"Authorization": "Bearer " + token,
	})
	if !called || code != http.StatusOK {
		t.Fatalf("service-auth dispatch called=%v status=%d", called, code)
	}
	principal, ok := PrincipalFromContext(c).(*ServiceAuthPrincipal)
	if !ok || principal.Issuer != issuer || principal.Audience != testDid || principal.LXM != lxm {
		t.Fatalf("unexpected service-auth principal: %#v (%T)", PrincipalFromContext(c), PrincipalFromContext(c))
	}
	claims, err := peekJWTClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := serviceAuthNumericClaim(jwt.MapClaims(claims), "exp")
	if err != nil {
		t.Fatal(err)
	}
	var replay models.SpaceReplayJTI
	if err := s.db.First(context.Background(), &replay, "token_type = ?", serviceAuthReplayTokenType).Error; err != nil {
		t.Fatalf("service-auth replay row missing: %v", err)
	}
	if replay.TokenType != serviceAuthReplayTokenType || !replay.ExpiresAt.Equal(time.Unix(exp, 0).Add(serviceAuthClockSkew)) {
		t.Fatalf("service-auth replay row = %#v, want type %q and exp+skew deadline", replay, serviceAuthReplayTokenType)
	}

	called, _, code = runAuthMiddleware(t, s.ServiceAuthOnly, http.MethodPost, target, map[string]string{
		"Authorization": "Bearer " + token,
	})
	if called || code == http.StatusOK {
		t.Fatalf("replayed service-auth token accepted: called=%v status=%d", called, code)
	}
}

func TestServiceAuthAcceptsES256WithMatchingDIDKey(t *testing.T) {
	s := newTestServer(t)
	const issuer = "did:plc:z72i7hdynmk6r22z27h6tvur"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := atcrypto.ParsePublicUncompressedBytesP256(elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y))
	if err != nil {
		t.Fatal(err)
	}
	s.SetPassport(testDIDDocumentFetcher(func(_ context.Context, did string) (*cocoon_identity.DidDoc, error) {
		if did != issuer {
			return nil, errors.New("unexpected DID lookup")
		}
		return &cocoon_identity.DidDoc{Id: issuer, VerificationMethods: []cocoon_identity.DidDocVerificationMethod{{
			Id: issuer + "#p256", Type: "Multikey", Controller: issuer, PublicKeyMultibase: public.Multibase(),
		}}}, nil
	}))
	const lxm = "com.atproto.server.createAccount"
	claims := jwt.MapClaims{
		"iss": issuer, "aud": testDid, "lxm": lxm, "jti": "es256-service-auth",
		"iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "JWT"
	token.Header["kid"] = issuer + "#p256"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	called, _, code := runAuthMiddleware(t, s.ServiceAuthOnly, http.MethodPost, "https://evil.example/xrpc/"+lxm, map[string]string{
		"Authorization": "Bearer " + raw,
		"Host":          "attacker.example",
	})
	if !called || code != http.StatusOK {
		t.Fatalf("ES256 service-auth dispatch called=%v status=%d", called, code)
	}
}

func TestServiceAuthInvalidClaimsDoNotConsumeReplay(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "service-retry.pds.test")
	key, err := atcrypto.ParsePrivateBytesK256(account.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "did:plc:z72i7hdynmk6r22z27h6tvur"
	s.SetPassport(testDIDDocumentFetcher(func(_ context.Context, did string) (*cocoon_identity.DidDoc, error) {
		if did != issuer {
			return nil, errors.New("unexpected DID lookup")
		}
		return &cocoon_identity.DidDoc{Id: issuer, VerificationMethods: []cocoon_identity.DidDocVerificationMethod{{
			Id: issuer + "#atproto", Type: "Multikey", Controller: issuer, PublicKeyMultibase: public.Multibase(),
		}}}, nil
	}))
	const lxm = "com.atproto.server.createAccount"
	const jti = "service-auth-retry"
	invalid := mintServiceAuthTokenWithJTI(t, account.SigningKey, issuer, "did:web:wrong.example", lxm, time.Now().Add(time.Minute), jti)
	if _, err := s.validateServiceAuthToken(context.Background(), invalid, lxm); err == nil {
		t.Fatal("wrong-audience service-auth token was accepted")
	}
	valid := mintServiceAuthTokenWithJTI(t, account.SigningKey, issuer, testDid, lxm, time.Now().Add(time.Minute), jti)
	validated, err := s.validateServiceAuthToken(context.Background(), valid, lxm)
	if err != nil {
		t.Fatalf("valid retry was rejected after invalid attempt: %v", err)
	}
	if validated.JTI != jti {
		t.Fatalf("validated JTI = %q, want %q", validated.JTI, jti)
	}
	var replay models.SpaceReplayJTI
	if err := s.db.First(context.Background(), &replay, "token_type = ?", serviceAuthReplayTokenType).Error; err != nil {
		t.Fatalf("service-auth replay row missing: %v", err)
	}
	if replay.TokenType != serviceAuthReplayTokenType {
		t.Fatalf("service-auth replay type = %q, want %q", replay.TokenType, serviceAuthReplayTokenType)
	}
}

func TestRequestURLCanonicalizesConfiguredHostAndScheme(t *testing.T) {
	s := newTestServer(t)
	c, _ := newRequestContext(http.MethodGet, "https://evil.example/xrpc/com.example.read?x=1", "", map[string]string{
		"Host": "attacker.example",
	})
	if got, want := s.requestURL(c), "https://pds.test/xrpc/com.example.read?x=1"; got != want {
		t.Fatalf("configured-host request URL = %q, want %q", got, want)
	}

	s.config.Version = "dev"
	c, _ = newRequestContext(http.MethodGet, "http://evil.example/xrpc/com.example.read", "", nil)
	if got, want := s.requestURL(c), "http://pds.test/xrpc/com.example.read"; got != want {
		t.Fatalf("dev request URL = %q, want %q", got, want)
	}

	s.config.Version = "test"
	c, _ = newRequestContext(http.MethodGet, "/xrpc/com.example.read", "", map[string]string{"Host": "proxy-attacker.example"})
	if got, want := s.requestURL(c), "https://pds.test/xrpc/com.example.read"; got != want {
		t.Fatalf("proxy request URL = %q, want %q", got, want)
	}
}

func TestSpacesEnabledDefaultFalse(t *testing.T) {
	s := newTestServer(t)
	if s.config.SpacesEnabled {
		t.Fatal("SpacesEnabled defaulted to true")
	}
	var args Args
	if args.SpacesEnabled {
		t.Fatal("Args SpacesEnabled defaulted to true")
	}
}

func TestSpacesNamespaceGuardBlocksProxyWhenDisabled(t *testing.T) {
	s := newTestServer(t)
	s.echo = echo.New()
	s.addSpacesNamespaceGuards()

	for _, target := range []string{
		"/xrpc/com.atproto.space.getRecord",
		"/xrpc/com.atproto.space.unimplementedAlphaMethod",
		"/xrpc/com.atproto.simplespace.getSpace",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		s.echo.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("GET %s status = %d, want %d", target, rec.Code, http.StatusNotImplemented)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["error"] != "NotSupported" {
			t.Fatalf("GET %s body = %v", target, body)
		}
	}
}

func TestEnabledSpaceRoutesUseNativeAuthPolicies(t *testing.T) {
	s := newTestServer(t)
	s.echo = echo.New()
	s.addSpaceRoutes()
	s.addSpacesNamespaceGuards()

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/xrpc/com.atproto.space.createRecord"},
		{http.MethodGet, "/xrpc/com.atproto.space.listSpaces"},
		{http.MethodGet, "/xrpc/com.atproto.space.getRecord"},
		{http.MethodGet, "/xrpc/com.atproto.space.listRepos"},
	}
	for _, test := range tests {
		req := httptest.NewRequest(test.method, test.path, nil)
		rec := httptest.NewRecorder()
		s.echo.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want native auth rejection %d (body %s)", test.method, test.path, rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.space.notImplemented", nil)
	rec := httptest.NewRecorder()
	s.echo.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("unimplemented Spaces method status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
}

func TestCORSAllowsBrowserSpaceCredentialExchange(t *testing.T) {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(cocoonCORSConfig()))
	e.POST("/xrpc/com.atproto.space.getSpaceCredential", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodOptions, "/xrpc/com.atproto.space.getSpaceCredential", nil)
	req.Header.Set(echo.HeaderOrigin, "https://pdsls.dev")
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodPost)
	req.Header.Set(echo.HeaderAccessControlRequestHeaders, "atproto-accept-labelers,authorization,content-type,dpop,x-bsky-topics,x-future-client-header")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get(echo.HeaderAccessControlAllowOrigin); got != "https://pdsls.dev" {
		t.Fatalf("allow-origin = %q, want reflected origin", got)
	}
	if got := rec.Header().Get(echo.HeaderAccessControlAllowCredentials); got != "true" {
		t.Fatalf("allow-credentials = %q, want true", got)
	}
	allowHeaders := strings.ToLower(rec.Header().Get(echo.HeaderAccessControlAllowHeaders))
	for _, want := range []string{"authorization", "content-type", "dpop", "atproto-accept-labelers", "x-bsky-topics", "x-future-client-header"} {
		if !strings.Contains(allowHeaders, want) {
			t.Fatalf("allow-headers = %q, missing %q", allowHeaders, want)
		}
	}
	if got := rec.Header().Get(echo.HeaderAccessControlAllowMethods); !strings.Contains(got, http.MethodPost) {
		t.Fatalf("allow-methods = %q, missing POST", got)
	}
}

func TestProxyResponseHeadersPreserveCocoonCORS(t *testing.T) {
	dst := make(http.Header)
	dst.Set(echo.HeaderAccessControlAllowOrigin, "https://bsky.app")
	dst.Set(echo.HeaderAccessControlAllowCredentials, "true")
	dst.Set(echo.HeaderAccessControlExposeHeaders, "DPoP-Nonce,WWW-Authenticate")
	dst.Set(echo.HeaderVary, echo.HeaderOrigin)

	src := make(http.Header)
	src.Set(echo.HeaderAccessControlAllowOrigin, "https://bsky.social")
	src.Set(echo.HeaderAccessControlAllowCredentials, "false")
	src.Set(echo.HeaderAccessControlExposeHeaders, "upstream-only")
	src.Set(echo.HeaderVary, "Accept-Encoding")
	src.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	src.Set("X-Upstream", "preserved")

	copyProxyResponseHeaders(dst, src)

	if got := dst.Get(echo.HeaderAccessControlAllowOrigin); got != "https://bsky.app" {
		t.Fatalf("allow-origin = %q, want Cocoon origin", got)
	}
	if got := dst.Get(echo.HeaderAccessControlAllowCredentials); got != "true" {
		t.Fatalf("allow-credentials = %q, want true", got)
	}
	if got := dst.Get(echo.HeaderAccessControlExposeHeaders); got != "DPoP-Nonce,WWW-Authenticate" {
		t.Fatalf("expose-headers = %q, want Cocoon headers", got)
	}
	vary := strings.Join(dst.Values(echo.HeaderVary), ",")
	if !strings.Contains(vary, echo.HeaderOrigin) || !strings.Contains(vary, "Accept-Encoding") {
		t.Fatalf("vary = %q, want both local and upstream dimensions", vary)
	}
	if got := dst.Get("X-Upstream"); got != "preserved" {
		t.Fatalf("upstream header = %q, want preserved", got)
	}
}

func mustDecodeSegment(t *testing.T, segment string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
