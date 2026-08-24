package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	atproto_identity "github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/golang-jwt/jwt/v4"
	cocoon_identity "github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// PrincipalType identifies the authenticated protocol principal installed on a
// request. A principal is installed only after its protocol-specific verifier
// has completed successfully.
type PrincipalType string

const (
	PrincipalOAuth           PrincipalType = "oauth"
	PrincipalSpaceCredential PrincipalType = "space_credential"
	PrincipalDelegation      PrincipalType = "space_delegation"
	PrincipalServiceAuth     PrincipalType = "service_auth"

	// Verbose aliases are useful to callers that prefer type-prefixed names.
	PrincipalTypeOAuth           = PrincipalOAuth
	PrincipalTypeSpaceCredential = PrincipalSpaceCredential
	PrincipalTypeDelegation      = PrincipalDelegation
	PrincipalTypeServiceAuth     = PrincipalServiceAuth
)

// Principal is the common request-context authentication contract. Concrete
// principals deliberately retain protocol-specific claims for handlers that
// need them, while new handlers can make authorization decisions without
// reading legacy context keys.
type Principal interface {
	PrincipalType() PrincipalType
}

// RequestPrincipal and AuthPrincipal are compatibility spellings for Principal.
type RequestPrincipal = Principal
type AuthPrincipal = Principal

// OAuthPrincipal describes an OAuth access token that passed token and (when
// applicable) DPoP/token-database validation.
type OAuthPrincipal struct {
	Subject  string
	ClientID string
	Scopes   []string
	DPoPJKT  string
	Token    string
	Repo     *models.RepoActor
	// Legacy marks a password/session access token. Reference atproto permits
	// these tokens on authorization routes and bypasses granular OAuth scopes.
	Legacy bool
}

func (p *OAuthPrincipal) PrincipalType() PrincipalType { return PrincipalOAuth }
func (p *OAuthPrincipal) GetSubject() string {
	if p == nil {
		return ""
	}
	return p.Subject
}
func (p *OAuthPrincipal) GetClientID() string {
	if p == nil {
		return ""
	}
	return p.ClientID
}
func (p *OAuthPrincipal) GetScopes() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.Scopes...)
}

// SpaceCredentialPrincipal describes a verified, DPoP-bound Space credential.
type SpaceCredentialPrincipal struct {
	SpaceURI     string
	AuthorityDID string
	DPoPJKT      string
	Token        string
	Claims       space.SpaceTokenClaims
	TokenClaims  space.SpaceTokenClaims
	Repo         *models.RepoActor
}

func (p *SpaceCredentialPrincipal) PrincipalType() PrincipalType { return PrincipalSpaceCredential }
func (p *SpaceCredentialPrincipal) GetSpaceURI() string {
	if p == nil {
		return ""
	}
	return p.SpaceURI
}
func (p *SpaceCredentialPrincipal) GetAuthorityDID() string {
	if p == nil {
		return ""
	}
	return p.AuthorityDID
}
func (p *SpaceCredentialPrincipal) GetDPoPJKT() string {
	if p == nil {
		return ""
	}
	return p.DPoPJKT
}

// DelegationPrincipal is installed by DelegationExchange after both the
// delegation token and issuance DPoP proof have been verified.
type DelegationPrincipal struct {
	SpaceURI     string
	AuthorityDID string
	Token        string
	Claims       space.SpaceTokenClaims
	DPoPJKT      string
	DPoPJTI      string
	DPoPIssuedAt time.Time
}

func (p *DelegationPrincipal) PrincipalType() PrincipalType { return PrincipalDelegation }

// ServiceAuthPrincipal describes a verified atproto service-auth token.
type ServiceAuthPrincipal struct {
	Issuer   string
	Audience string
	LXM      string
	Token    string
	Repo     *models.RepoActor
}

func (p *ServiceAuthPrincipal) PrincipalType() PrincipalType { return PrincipalServiceAuth }
func (p *ServiceAuthPrincipal) GetIssuer() string {
	if p == nil {
		return ""
	}
	return p.Issuer
}
func (p *ServiceAuthPrincipal) GetAudience() string {
	if p == nil {
		return ""
	}
	return p.Audience
}
func (p *ServiceAuthPrincipal) GetLXM() string {
	if p == nil {
		return ""
	}
	return p.LXM
}

const principalContextKey = "principal"

// SetPrincipal installs the typed principal and a compatibility alias in an
// Echo context. The alias is intentionally not used for authorization.
func SetPrincipal(e echo.Context, principal Principal) {
	if e == nil {
		return
	}
	e.Set(principalContextKey, principal)
	e.Set("auth_principal", principal)
}

// PrincipalFromContext returns the verified request principal, if any.
func PrincipalFromContext(e echo.Context) Principal {
	if e == nil {
		return nil
	}
	p, _ := e.Get(principalContextKey).(Principal)
	return p
}

// GetPrincipal is a compatibility accessor for new handlers.
func GetPrincipal(e echo.Context) Principal { return PrincipalFromContext(e) }

// Policy names are intentionally explicit. A route should select one policy
// rather than composing the old legacy and OAuth middlewares by accident.
type AuthPolicy string

const (
	PolicyOAuthOnly           AuthPolicy = "oauth_only"
	PolicyOAuthOrSpace        AuthPolicy = "oauth_or_space_credential"
	PolicyDelegationExchange  AuthPolicy = "delegation_exchange"
	PolicySpaceCredentialOnly AuthPolicy = "space_credential_only"
	PolicyServiceAuthOnly     AuthPolicy = "service_auth_only"
)

// Aliases use the names from the endpoint policy design.
const (
	OAuthOnlyPolicy              = PolicyOAuthOnly
	OAuthOrSpaceCredentialPolicy = PolicyOAuthOrSpace
	DelegationExchangePolicy     = PolicyDelegationExchange
	SpaceCredentialOnlyPolicy    = PolicySpaceCredentialOnly
	ServiceAuthOnlyPolicy        = PolicyServiceAuthOnly
)

// SpaceAuthorityKeyResolver resolves a Space authority verification key. The
// request's kid is untrusted until VerifySpaceToken verifies the signature; a
// resolver must therefore use it only as a key selection hint.
type SpaceAuthorityKeyResolver interface {
	ResolveSigningKey(context.Context, space.KeyResolutionRequest) (space.Verifier, error)
}

// SpaceAuthorityKeyResolverFunc adapts a function to SpaceAuthorityKeyResolver.
type SpaceAuthorityKeyResolverFunc func(context.Context, space.KeyResolutionRequest) (space.Verifier, error)

func (f SpaceAuthorityKeyResolverFunc) ResolveSigningKey(ctx context.Context, req space.KeyResolutionRequest) (space.Verifier, error) {
	if f == nil {
		return nil, errors.New("nil Space authority key resolver")
	}
	return f(ctx, req)
}

// DIDDocumentFetcher is the small Passport contract needed by Space auth. It
// keeps production backed by the server's Passport while allowing hermetic
// tests to provide a fake document source.
type DIDDocumentFetcher interface {
	FetchDoc(context.Context, string) (*cocoon_identity.DidDoc, error)
	ResolveHandle(context.Context, string) (string, error)
	BustDoc(context.Context, string) error
	BustDid(context.Context, string) error
}

// didDocumentIdentity is shared by Space authority and service-auth
// verification. A DID document is accepted only when its declared id is empty
// or exactly the requested canonical DID; keys and services are otherwise
// converted without changing their ids.
func didDocumentIdentity(issuer string, doc *cocoon_identity.DidDoc) (atproto_identity.Identity, error) {
	did, err := syntax.ParseDID(issuer)
	if err != nil || string(did) != issuer {
		return atproto_identity.Identity{}, fmt.Errorf("issuer is not a canonical DID")
	}
	if doc == nil {
		return atproto_identity.Identity{}, errors.New("DID document is empty")
	}
	if doc.Id != "" && doc.Id != issuer {
		return atproto_identity.Identity{}, errors.New("DID document id does not match issuer")
	}
	verificationMethods := make([]atproto_identity.DocVerificationMethod, len(doc.VerificationMethods))
	for i, method := range doc.VerificationMethods {
		verificationMethods[i] = atproto_identity.DocVerificationMethod{
			ID: method.Id, Type: method.Type, PublicKeyMultibase: method.PublicKeyMultibase,
			Controller: method.Controller,
		}
	}
	services := make([]atproto_identity.DocService, len(doc.Service))
	for i, service := range doc.Service {
		services[i] = atproto_identity.DocService{ID: service.Id, Type: service.Type, ServiceEndpoint: service.ServiceEndpoint}
	}
	return atproto_identity.ParseIdentity(&atproto_identity.DIDDocument{
		DID: did, AlsoKnownAs: doc.AlsoKnownAs, VerificationMethod: verificationMethods, Service: services,
	}), nil
}

// didDocumentVerifier selects exactly kid (or the identity's normal primary
// key when kid is omitted by a legacy service-auth JWT) and requires the
// published key type to agree with alg. It deliberately does not fall back to
// another key id: kid is a selection hint, not permission to broaden trust.
func didDocumentVerifier(ctx context.Context, fetcher DIDDocumentFetcher, req space.KeyResolutionRequest) (space.Verifier, error) {
	if fetcher == nil {
		return nil, errors.New("DID document resolver is unavailable")
	}
	if req.Issuer == "" || (req.Kid == "" && req.Algorithm != "ES256K" && req.Algorithm != "ES256") {
		return nil, errors.New("invalid DID key resolution request")
	}
	if req.Algorithm != "ES256K" && req.Algorithm != "ES256" {
		return nil, fmt.Errorf("unsupported DID signing algorithm %q", req.Algorithm)
	}
	resolveCtx := ctx
	if resolveCtx == nil {
		resolveCtx = context.Background()
	}
	if req.ForceRefresh {
		resolveCtx = context.WithValue(resolveCtx, "skip-cache", true)
	}
	doc, err := fetcher.FetchDoc(resolveCtx, req.Issuer)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %s: %w", req.Issuer, err)
	}
	parsed, err := didDocumentIdentity(req.Issuer, doc)
	if err != nil {
		return nil, err
	}
	var key atcrypto.PublicKey
	if req.Kid == "" {
		key, err = parsed.PublicKey()
	} else {
		kid := req.Kid
		if strings.HasPrefix(kid, "#") {
			kid = strings.TrimPrefix(kid, "#")
		} else if strings.HasPrefix(kid, req.Issuer+"#") {
			kid = strings.TrimPrefix(kid, req.Issuer+"#")
		} else if strings.Contains(kid, "#") {
			return nil, errors.New("DID key id is not canonical")
		}
		if kid == "" {
			return nil, errors.New("DID key id is empty")
		}
		key, err = parsed.GetPublicKey(kid)
	}
	if err != nil || key == nil {
		if err == nil {
			err = errors.New("verification method is unavailable")
		}
		return nil, fmt.Errorf("DID key %q: %w", req.Kid, err)
	}
	switch req.Algorithm {
	case "ES256K":
		if _, ok := key.(*atcrypto.PublicKeyK256); !ok {
			return nil, errors.New("DID key is not an ES256K key")
		}
	case "ES256":
		if _, ok := key.(*atcrypto.PublicKeyP256); !ok {
			return nil, errors.New("DID key is not an ES256 key")
		}
	}
	return space.VerifierFunc{Alg: req.Algorithm, Func: func(input, sig []byte) error {
		return key.HashAndVerifyLenient(input, sig)
	}}, nil
}

// PassportSpaceAuthorityKeyResolver is the production DID-backed resolver for
// Space credentials and delegation tokens.
type PassportSpaceAuthorityKeyResolver struct{ Passport DIDDocumentFetcher }

func NewPassportSpaceAuthorityKeyResolver(passport DIDDocumentFetcher) *PassportSpaceAuthorityKeyResolver {
	return &PassportSpaceAuthorityKeyResolver{Passport: passport}
}

func (r *PassportSpaceAuthorityKeyResolver) ResolveSigningKey(ctx context.Context, req space.KeyResolutionRequest) (space.Verifier, error) {
	if r == nil {
		return nil, errors.New("nil Passport Space authority key resolver")
	}
	if req.Kid == "" {
		return nil, errors.New("Space authority kid is required")
	}
	return didDocumentVerifier(ctx, r.Passport, req)
}

// SpaceAuthorityKeySource is the adapter contract for test/local key lookups.
// Production uses PassportSpaceAuthorityKeyResolver above.
type SpaceAuthorityKeySource interface {
	ResolveSpaceKey(context.Context, string, string, string) (space.Verifier, error)
}

// SpaceAuthorityKeySourceFunc adapts a DID/key lookup function.
type SpaceAuthorityKeySourceFunc func(context.Context, string, string, string) (space.Verifier, error)

func (f SpaceAuthorityKeySourceFunc) ResolveSpaceKey(ctx context.Context, issuer, kid, alg string) (space.Verifier, error) {
	if f == nil {
		return nil, errors.New("nil Space authority key source")
	}
	return f(ctx, issuer, kid, alg)
}

// DIDSpaceAuthorityKeyResolver adapts a DID key source and retries a
// #atproto_space lookup with the legacy #atproto key id. This is the explicit
// fallback contract; it does not itself perform network resolution.
type DIDSpaceAuthorityKeyResolver struct{ Source SpaceAuthorityKeySource }

func NewDIDSpaceAuthorityKeyResolver(source SpaceAuthorityKeySource) *DIDSpaceAuthorityKeyResolver {
	return &DIDSpaceAuthorityKeyResolver{Source: source}
}

func (r *DIDSpaceAuthorityKeyResolver) ResolveSigningKey(ctx context.Context, req space.KeyResolutionRequest) (space.Verifier, error) {
	if r == nil || r.Source == nil {
		return nil, errors.New("nil Space authority key source")
	}
	kids := []string{req.Kid}
	if req.Kid == space.SpaceSigningKeyID {
		kids = append(kids, space.FallbackSigningKeyID)
	}
	var lastErr error
	for _, kid := range kids {
		verifier, err := r.Source.ResolveSpaceKey(ctx, req.Issuer, kid, req.Algorithm)
		if err == nil && verifier != nil {
			return verifier, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("Space authority key not found")
	}
	return nil, lastErr
}

// SetPassport injects the Passport-compatible identity source used by
// service-auth and production Space authority key resolution. It is primarily
// useful for hermetic tests and hosts with a custom identity cache.
func (s *Server) SetPassport(passport DIDDocumentFetcher) {
	if s != nil {
		s.passport = passport
		s.spaceKeyResolver = NewPassportSpaceAuthorityKeyResolver(passport)
	}
}

// SetSpaceAuthorityKeyResolver injects the DID/JWKS resolver used by Space
// credential and delegation verification. It is primarily useful for tests
// and for hosts with an identity cache.
func (s *Server) SetSpaceAuthorityKeyResolver(resolver SpaceAuthorityKeyResolver) {
	if s != nil {
		s.spaceKeyResolver = resolver
	}
}

// SetSpaceReplayStore injects a replay store. Production New configures a
// durable GORM store; tests may use space.MemoryReplayStore.
func (s *Server) SetSpaceReplayStore(store space.ReplayStore) {
	if s != nil {
		s.spaceReplay = store
	}
}

// AuthDispatcher is the one entry point for route-specific authentication.
// It never calls legacy middleware for Space token types.
func (s *Server) AuthDispatcher(policy AuthPolicy, next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		if s == nil {
			return authUnauthorized(e, "authentication is unavailable")
		}
		scheme, raw, err := parseAuthorization(e.Request().Header.Get("Authorization"))
		if err != nil {
			return authUnauthorized(e, err.Error())
		}

		switch policy {
		case PolicyOAuthOnly:
			if scheme == "bearer" {
				return s.dispatchLegacySpaceOAuth(e, next, raw)
			}
			if scheme != "dpop" {
				return authUnauthorized(e, "Space OAuth routes require Bearer or DPoP authorization")
			}
			kind, err := classifyDPoPToken(raw)
			if err != nil || kind != authTokenOAuth {
				return authUnauthorized(e, "token is not an OAuth access token")
			}
			return s.dispatchOAuth(e, next, scheme, raw)

		case PolicyOAuthOrSpace:
			if scheme == "bearer" {
				return s.dispatchLegacySpaceOAuth(e, next, raw)
			}
			if scheme == "dpop" {
				kind, err := classifyDPoPToken(raw)
				if err != nil {
					return authUnauthorized(e, "unsupported DPoP token type")
				}
				switch kind {
				case authTokenOAuth:
					return s.dispatchOAuth(e, next, scheme, raw)
				case authTokenCredential:
					if e.Request().Method != http.MethodGet && e.Request().Method != http.MethodHead {
						return authUnauthorized(e, "Space credentials are read-only")
					}
					return s.dispatchSpaceCredential(e, next, raw)
				default:
					return authUnauthorized(e, "token is not valid for a read route")
				}
			}
			return authUnauthorized(e, "read route requires DPoP OAuth or a Space credential")

		case PolicyDelegationExchange:
			if scheme != "bearer" && scheme != "dpop" {
				return authUnauthorized(e, "delegation exchange requires Bearer or DPoP authorization")
			}
			kind, err := classifyDPoPToken(raw)
			if err != nil || kind != authTokenDelegation {
				return authUnauthorized(e, "token is not a delegation token")
			}
			return s.dispatchDelegation(e, next, raw)

		case PolicySpaceCredentialOnly:
			if scheme != "dpop" {
				return authUnauthorized(e, "Space routes require DPoP authorization")
			}
			kind, err := classifyDPoPToken(raw)
			if err != nil || kind != authTokenCredential {
				return authUnauthorized(e, "token is not a Space credential")
			}
			return s.dispatchSpaceCredential(e, next, raw)

		case PolicyServiceAuthOnly:
			if scheme != "bearer" {
				return authUnauthorized(e, "service auth requires Bearer authorization")
			}
			return s.dispatchServiceAuth(e, next, raw)
		default:
			return authUnauthorized(e, "unknown authentication policy")
		}
	}
}

// Explicit policy constructors. These methods are suitable as Echo route
// middleware and do not need to be combined with legacy middleware.
func (s *Server) OAuthOnly(next echo.HandlerFunc) echo.HandlerFunc {
	return s.AuthDispatcher(PolicyOAuthOnly, next)
}
func (s *Server) OAuthOrSpaceCredential(next echo.HandlerFunc) echo.HandlerFunc {
	return s.AuthDispatcher(PolicyOAuthOrSpace, next)
}
func (s *Server) DelegationExchange(next echo.HandlerFunc) echo.HandlerFunc {
	return s.AuthDispatcher(PolicyDelegationExchange, next)
}
func (s *Server) SpaceCredentialOnly(next echo.HandlerFunc) echo.HandlerFunc {
	return s.AuthDispatcher(PolicySpaceCredentialOnly, next)
}
func (s *Server) ServiceAuthOnly(next echo.HandlerFunc) echo.HandlerFunc {
	return s.AuthDispatcher(PolicyServiceAuthOnly, next)
}

// Constructor-function spellings make policy selection explicit at call sites
// that prefer package-level middleware constructors.
func NewOAuthOnlyMiddleware(s *Server, next echo.HandlerFunc) echo.HandlerFunc {
	return s.OAuthOnly(next)
}
func NewOAuthOrSpaceCredentialMiddleware(s *Server, next echo.HandlerFunc) echo.HandlerFunc {
	return s.OAuthOrSpaceCredential(next)
}
func NewDelegationExchangeMiddleware(s *Server, next echo.HandlerFunc) echo.HandlerFunc {
	return s.DelegationExchange(next)
}
func NewSpaceCredentialOnlyMiddleware(s *Server, next echo.HandlerFunc) echo.HandlerFunc {
	return s.SpaceCredentialOnly(next)
}
func NewServiceAuthOnlyMiddleware(s *Server, next echo.HandlerFunc) echo.HandlerFunc {
	return s.ServiceAuthOnly(next)
}

type authTokenKind uint8

const (
	authTokenOAuth authTokenKind = iota
	authTokenCredential
	authTokenDelegation
	authTokenAttestation
)

func parseAuthorization(raw string) (scheme, token string, err error) {
	parts := strings.Fields(raw)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", errors.New("invalid Authorization header")
	}
	return strings.ToLower(parts[0]), parts[1], nil
}

// classifyDPoPToken intentionally decodes only the untrusted JWT header. It
// is a dispatch hint, never an authentication decision; the selected verifier
// must verify the complete token before installing a principal.
func classifyDPoPToken(raw string) (authTokenKind, error) {
	typ, err := peekJWTType(raw)
	if err != nil {
		return 0, err
	}
	switch typ {
	case space.CredentialTokenType:
		return authTokenCredential, nil
	case space.DelegationTokenType:
		return authTokenDelegation, nil
	case space.ClientAttestationTokenType:
		return authTokenAttestation, nil
	case "JWT":
		return authTokenOAuth, nil
	default:
		return 0, fmt.Errorf("unsupported JWT typ %q", typ)
	}
}

func peekJWTType(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", errors.New("invalid JWT structure")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid JWT header encoding")
	}
	var header map[string]json.RawMessage
	if err := decodeJSONObject(b, &header); err != nil {
		return "", errors.New("invalid JWT header")
	}
	rawTyp, ok := header["typ"]
	if !ok {
		return "", errors.New("JWT typ is required")
	}
	var typ string
	if err := json.Unmarshal(rawTyp, &typ); err != nil || typ == "" {
		return "", errors.New("JWT typ must be a string")
	}
	return typ, nil
}

// peekJWTClaims is used only to route a Bearer token to service-auth's
// dedicated verifier. Claims remain untrusted until that verifier completes.
func peekJWTClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[1] == "" {
		return nil, errors.New("invalid JWT structure")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT payload encoding")
	}
	var claims map[string]any
	if err := decodeJSONObject(b, &claims); err != nil {
		return nil, errors.New("invalid JWT claims")
	}
	return claims, nil
}

func decodeJSONObject(b []byte, dst any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (s *Server) verifyOAuthAccessToken(raw string) error {
	if s.privateKey == nil {
		return errors.New("OAuth signing key is unavailable")
	}
	parsed, err := jwt.ParseWithClaims(raw, jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 || token.Header["typ"] != "JWT" {
			return nil, errors.New("OAuth access token must use ES256/JWT")
		}
		return s.privateKey.Public(), nil
	})
	if err != nil || parsed == nil || !parsed.Valid {
		if err != nil {
			return err
		}
		return errors.New("invalid OAuth access-token signature")
	}
	return nil
}

func (s *Server) dispatchLegacySpaceOAuth(e echo.Context, next echo.HandlerFunc, raw string) error {
	return s.handleLegacySessionMiddleware(func(c echo.Context) error {
		repo, _ := c.Get("repo").(*models.RepoActor)
		subject, _ := c.Get("did").(string)
		if subject == "" && repo != nil {
			subject = repo.Repo.Did
		}
		if subject == "" {
			return authUnauthorized(c, "legacy session subject is unavailable")
		}
		SetPrincipal(c, &OAuthPrincipal{
			Subject: subject,
			Token:   raw,
			Repo:    repo,
			Legacy:  true,
		})
		if err := s.assertSpaceRepoAvailable(c, subject); err != nil {
			return err
		}
		return next(c)
	})(e)
}

func (s *Server) dispatchOAuth(e echo.Context, next echo.HandlerFunc, scheme, raw string) error {
	// Bearer tokens remain compatible with the existing token table, but a
	// token that is structurally a JWT must not be a Space token. DPoP OAuth
	// access tokens are always JWTs and receive mandatory signature validation
	// before the legacy DB/proof middleware is entered.
	if typ, err := peekJWTType(raw); err == nil {
		if typ != "JWT" {
			return authUnauthorized(e, "token is not an OAuth access token")
		}
		if err := s.verifyOAuthAccessToken(raw); err != nil {
			return authUnauthorized(e, "invalid OAuth access-token signature")
		}
	} else if scheme == "dpop" {
		return authUnauthorized(e, "invalid OAuth access token")
	}
	availableNext := func(c echo.Context) error {
		principal, ok := PrincipalFromContext(c).(*OAuthPrincipal)
		if !ok || principal == nil || principal.Subject == "" {
			return authUnauthorized(c, "OAuth principal is unavailable")
		}
		if err := s.assertSpaceRepoAvailable(c, principal.Subject); err != nil {
			return err
		}
		return next(c)
	}
	if scheme == "dpop" {
		if s.oauthProvider == nil {
			return authUnauthorized(e, "OAuth provider is unavailable")
		}
		// This is deliberately the only path that calls the legacy OAuth
		// token-table middleware. Space token types cannot reach this branch.
		return s.handleOauthSessionMiddleware(availableNext)(e)
	}

	var token provider.OauthToken
	if s.db == nil {
		return authUnauthorized(e, "OAuth database is unavailable")
	}
	if err := s.db.Raw(e.Request().Context(), "SELECT * FROM oauth_tokens WHERE token = ?", nil, raw).Scan(&token).Error; err != nil || token.Token == "" {
		return authUnauthorized(e, "invalid OAuth token")
	}
	if time.Now().After(token.ExpiresAt) {
		return authUnauthorized(e, "OAuth token expired")
	}
	repo, err := s.getRepoActorByDid(e.Request().Context(), token.Sub)
	if err != nil {
		return authUnauthorized(e, "OAuth subject is unavailable")
	}
	setOAuthPrincipal(e, &token, raw, repo)
	return availableNext(e)
}

func (s *Server) dispatchSpaceCredential(e echo.Context, next echo.HandlerFunc, raw string) error {
	if s.spaceKeyResolver == nil {
		return authUnauthorized(e, "Space authority key resolver is unavailable")
	}
	proofRaw := e.Request().Header.Get("DPoP")
	if proofRaw == "" {
		return authUnauthorized(e, "DPoP proof is required")
	}
	ctx := e.Request().Context()
	verified, err := space.VerifyCredential(ctx, raw, space.VerifySpaceTokenOptions{
		SigningKeyResolver: s.spaceKeyResolver,
		Context:            ctx,
	})
	if err != nil {
		return authUnauthorized(e, "invalid Space credential")
	}
	if err := s.checkSpaceAvailable(ctx, verified.Claims.Sub, verified.Claims.Iss); err != nil {
		return authUnauthorized(e, err.Error())
	}
	if verified.Claims.Cnf == nil {
		return authUnauthorized(e, "Space credential is not DPoP-bound")
	}
	proof, err := space.VerifyDpopProof(ctx, proofRaw, space.VerifyDpopProofOptions{
		HTTPMethod:        e.Request().Method,
		HTTPURL:           s.requestURL(e),
		Credential:        raw,
		CredentialPresent: true,
		ExpectedJKT:       verified.Claims.Cnf.JKT,
		Replay:            s.spaceReplayStore(),
		Context:           ctx,
	})
	if err != nil {
		return authUnauthorized(e, "invalid Space DPoP proof")
	}
	principal := &SpaceCredentialPrincipal{
		SpaceURI:     verified.Claims.Sub,
		AuthorityDID: verified.Claims.Iss,
		DPoPJKT:      proof.JKT,
		Token:        raw,
		Claims:       verified.Claims,
		TokenClaims:  verified.Claims,
	}
	SetPrincipal(e, principal)
	return next(e)
}

func (s *Server) dispatchDelegation(e echo.Context, next echo.HandlerFunc, raw string) error {
	if s.spaceKeyResolver == nil {
		return authUnauthorized(e, "Space authority key resolver is unavailable")
	}
	proofRaw := e.Request().Header.Get("DPoP")
	if proofRaw == "" {
		return authUnauthorized(e, "issuance DPoP proof is required")
	}
	ctx := e.Request().Context()
	verified, err := space.VerifyDelegationToken(ctx, raw, space.VerifySpaceTokenOptions{
		SigningKeyResolver: s.spaceKeyResolver,
		Context:            ctx,
	})
	if err != nil {
		return authUnauthorized(e, "invalid delegation token")
	}
	if status, statusErr := s.localRepoStatus(ctx, verified.Claims.Iss); statusErr != nil {
		return authUnauthorized(e, "unable to check delegation issuer")
	} else if status != "" {
		return authUnauthorized(e, repoStatusErrorName(status))
	}
	proof, err := space.VerifyDpopProof(ctx, proofRaw, space.VerifyDpopProofOptions{
		HTTPMethod: e.Request().Method,
		HTTPURL:    s.requestURL(e),
		Context:    ctx,
	})
	if err != nil {
		return authUnauthorized(e, "invalid issuance DPoP proof")
	}
	spaceRef, err := space.ParseSpaceURI(verified.Claims.Sub)
	if err != nil {
		return authUnauthorized(e, "invalid delegation Space subject")
	}
	SetPrincipal(e, &DelegationPrincipal{
		SpaceURI:     verified.Claims.Sub,
		AuthorityDID: string(spaceRef.AuthorityDID),
		Token:        raw,
		Claims:       verified.Claims,
		DPoPJKT:      proof.JKT,
		DPoPJTI:      proof.JTI,
		DPoPIssuedAt: proof.IssuedAt,
	})
	return next(e)
}

func (s *Server) dispatchServiceAuth(e echo.Context, next echo.HandlerFunc, raw string) error {
	path := e.Request().URL.Path
	const prefix = "/xrpc/"
	if !strings.HasPrefix(path, prefix) {
		return authUnauthorized(e, "service-auth endpoint is invalid")
	}
	nsid, err := syntax.ParseNSID(strings.TrimPrefix(path, prefix))
	if err != nil || string(nsid) != strings.TrimPrefix(path, prefix) {
		return authUnauthorized(e, "service-auth endpoint is invalid")
	}
	validated, err := s.validateServiceAuthToken(e.Request().Context(), raw, string(nsid))
	if err != nil {
		return authUnauthorized(e, "invalid service-auth token")
	}
	SetPrincipal(e, &ServiceAuthPrincipal{
		Issuer: validated.Issuer, Audience: validated.Audience, LXM: validated.LXM, Token: raw,
	})
	return next(e)
}

func setOAuthPrincipal(e echo.Context, token *provider.OauthToken, raw string, repo *models.RepoActor) {
	if token == nil {
		return
	}
	jkt := ""
	if token.Parameters.DpopJkt != nil {
		jkt = *token.Parameters.DpopJkt
	}
	SetPrincipal(e, &OAuthPrincipal{
		Subject:  token.Sub,
		ClientID: token.ClientId,
		Scopes:   strings.Fields(token.Parameters.Scope),
		DPoPJKT:  jkt,
		Token:    raw,
		Repo:     repo,
	})
}

func (s *Server) spaceReplayStore() space.ReplayStore {
	if s.spaceReplay != nil {
		return s.spaceReplay
	}
	if s.db != nil {
		// This is a durable store. It is intentionally not a process-local
		// memory fallback when a production DB is available.
		return space.NewGORMReplayStore(s.db.Client())
	}
	return space.NewMemoryReplayStore()
}

func (s *Server) requestURL(e echo.Context) string {
	req := e.Request()
	host := ""
	if s != nil && s.config != nil {
		host = strings.TrimSpace(s.config.Hostname)
	}
	if host == "" {
		// New() requires a configured hostname. Keep a useful fallback for
		// isolated tests/local callers that construct a Server directly, but
		// never let Request.Host override a configured production hostname.
		host = req.Host
	}

	// Public Cocoon deployments terminate TLS at the reverse proxy, so a
	// missing Request.TLS is not evidence that the externally visible URL is
	// plain HTTP. Only the explicit dev mode opts into HTTP; an absolute-form
	// request URL (and its Host) is not trusted for either authority or scheme.
	scheme := "https"
	if s != nil && s.config != nil && s.config.Version == "dev" {
		scheme = "http"
	} else if req.TLS != nil {
		scheme = "https"
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

func repoStatusErrorName(status string) string {
	switch status {
	case "deactivated":
		return "RepoDeactivated"
	case "suspended":
		return "RepoSuspended"
	case "takendown":
		return "RepoTakendown"
	default:
		return "RepoUnavailable"
	}
}

func (s *Server) localRepoStatus(ctx context.Context, did string) (string, error) {
	if s == nil || s.db == nil || did == "" {
		return "", nil
	}
	var repo models.Repo
	result := s.db.First(ctx, &repo, "did = ?", did)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if result.Error != nil {
		return "", result.Error
	}
	if status := repo.Status(); status != nil {
		return *status, nil
	}
	return "", nil
}

func (s *Server) checkSpaceAvailable(ctx context.Context, uri, authority string) error {
	if s.db == nil {
		return nil
	}
	var tombstone models.SpaceTombstone
	if err := s.db.First(ctx, &tombstone, "space = ?", uri).Error; err == nil {
		return errors.New("Space has been tombstoned")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("unable to check Space tombstone: %w", err)
	}

	// A host-local SimpleSpace row is authoritative when present. Missing rows
	// are allowed because a credential may identify a remote/unconfigured space.
	var configured models.SimpleSpace
	if err := s.db.First(ctx, &configured, "uri = ?", uri).Error; err == nil {
		if configured.Deleted || configured.DeletedAt != nil {
			return errors.New("Space is unavailable")
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("unable to check Space availability: %w", err)
	}

	// Likewise, reject a locally known deactivated authority, but do not make
	// local account presence a requirement for remote authorities.
	var repo models.Repo
	if err := s.db.First(ctx, &repo, "did = ?", authority).Error; err == nil {
		if repo.Deactivated {
			return errors.New("Space authority is unavailable")
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("unable to check Space authority: %w", err)
	}
	return nil
}

func authUnauthorized(e echo.Context, message string) error {
	if e == nil {
		return errors.New(message)
	}
	return e.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized", "error_description": message})
}
