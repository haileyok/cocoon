package space

// Pure cryptographic support for Spaces authorization tokens. This package
// deliberately has no HTTP, router, or middleware dependencies.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

const (
	DelegationTokenType        = "atproto-space-delegation+jwt"
	ClientAttestationTokenType = "atproto-client-attestation+jwt"
	CredentialTokenType        = "atproto-space-credential+jwt"
	SpaceHostAudienceSuffix    = "#atproto_space_host"
	DelegationSigningKeyID     = "#atproto"
	SpaceSigningKeyID          = "#atproto_space"
	FallbackSigningKeyID       = "#atproto"
	ClockSkew                  = 5 * time.Second
	DelegationLifetime         = 60 * time.Second
	ClientAttestationLifetime  = 60 * time.Second
	CredentialLifetime         = 2 * time.Hour
)

type TokenType string

const (
	TokenDelegation        TokenType = DelegationTokenType
	TokenClientAttestation TokenType = ClientAttestationTokenType
	TokenCredential        TokenType = CredentialTokenType
)

// SpaceTokenType is the terminology used by the reference implementation.
type SpaceTokenType = TokenType

type SpaceTokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type SpaceTokenConfirmation struct {
	JKT string `json:"jkt"`
}

type SpaceTokenClaims struct {
	Iss string                  `json:"iss"`
	Sub string                  `json:"sub"`
	Aud *string                 `json:"aud,omitempty"`
	Cnf *SpaceTokenConfirmation `json:"cnf,omitempty"`
	IAT int64                   `json:"iat"`
	Exp int64                   `json:"exp"`
	JTI string                  `json:"jti"`
}

type SpaceToken struct {
	Header       SpaceTokenHeader
	Claims       SpaceTokenClaims
	SigningInput []byte
	Signature    []byte
}

type SpaceAuthError struct {
	Code string
	Msg  string
	Err  error
}

func (e *SpaceAuthError) Error() string {
	if e.Err == nil {
		return e.Msg
	}
	if e.Msg == "" {
		return e.Err.Error()
	}
	return e.Msg + ": " + e.Err.Error()
}
func (e *SpaceAuthError) Unwrap() error { return e.Err }
func authErr(code, msg string, err error) error {
	return &SpaceAuthError{Code: code, Msg: msg, Err: err}
}

// Signer and Verifier make account-key and DID/JWKS integrations independent
// from this package. ECDSA signatures are JOSE's fixed-width R || S format.
type Signer interface {
	Algorithm() string
	Sign([]byte) ([]byte, error)
}
type Verifier interface {
	Algorithm() string
	Verify([]byte, []byte) error
}
type KeyResolver func(context.Context, string, string, string) (Verifier, error)

// KeyResolutionRequest is the typed request passed to resolvers that can
// refresh a cached DID/JWKS lookup after a signature failure. ForceRefresh is
// false for the initial lookup and true only for the single retry.
type KeyResolutionRequest struct {
	Issuer       string
	Kid          string
	Algorithm    string
	ForceRefresh bool
}

// SigningKeyResolver is the refresh-capable resolver contract. A resolver
// must not silently fall back to an unrelated key when ForceRefresh is true.
type SigningKeyResolver interface {
	ResolveSigningKey(context.Context, KeyResolutionRequest) (Verifier, error)
}

// SigningKeyResolverFunc adapts a typed resolver function to the interface.
type SigningKeyResolverFunc func(context.Context, KeyResolutionRequest) (Verifier, error)

func (f SigningKeyResolverFunc) ResolveSigningKey(ctx context.Context, req KeyResolutionRequest) (Verifier, error) {
	return f(ctx, req)
}

type SignerFunc struct {
	Alg  string
	Func func([]byte) ([]byte, error)
}

func (s SignerFunc) Algorithm() string { return s.Alg }
func (s SignerFunc) Sign(b []byte) ([]byte, error) {
	if s.Func == nil {
		return nil, errors.New("nil signer function")
	}
	return s.Func(b)
}

type VerifierFunc struct {
	Alg  string
	Func func([]byte, []byte) error
}

func (v VerifierFunc) Algorithm() string { return v.Alg }
func (v VerifierFunc) Verify(b, sig []byte) error {
	if v.Func == nil {
		return errors.New("nil verifier function")
	}
	return v.Func(b, sig)
}

type ECDSASigner struct {
	key    *ecdsa.PrivateKey
	alg    string
	random io.Reader
}

func NewECDSASigner(key *ecdsa.PrivateKey, alg string, random io.Reader) (*ECDSASigner, error) {
	if key == nil || key.Curve == nil {
		return nil, errors.New("nil ECDSA key")
	}
	if !validECDSAAlgorithm(alg) || !curveMatchesAlgorithm(key.Curve, alg) {
		return nil, fmt.Errorf("invalid %s ECDSA key", alg)
	}
	if random == nil {
		random = rand.Reader
	}
	return &ECDSASigner{key: key, alg: alg, random: random}, nil
}
func (s *ECDSASigner) Algorithm() string { return s.alg }
func (s *ECDSASigner) Sign(input []byte) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errors.New("nil ECDSA signer")
	}
	h := sha256.Sum256(input)
	r, ss, err := ecdsa.Sign(s.random, s.key, h[:])
	if err != nil {
		return nil, err
	}
	return encodeECDSASignature(r, ss, s.key.Params().BitSize), nil
}
func (s *ECDSASigner) PublicKey() *ecdsa.PublicKey {
	if s == nil || s.key == nil {
		return nil
	}
	return &s.key.PublicKey
}

type ECDSAVerifier struct {
	key *ecdsa.PublicKey
	alg string
}

func NewECDSAVerifier(key *ecdsa.PublicKey, alg string) (*ECDSAVerifier, error) {
	if key == nil || key.Curve == nil || !validECDSAAlgorithm(alg) || !curveMatchesAlgorithm(key.Curve, alg) {
		return nil, fmt.Errorf("invalid %s ECDSA public key", alg)
	}
	return &ECDSAVerifier{key: key, alg: alg}, nil
}
func (v *ECDSAVerifier) Algorithm() string { return v.alg }
func (v *ECDSAVerifier) Verify(input, sig []byte) error {
	if v == nil || v.key == nil || len(sig) != 64 {
		return errors.New("invalid ECDSA signature")
	}
	n := (v.key.Params().BitSize + 7) / 8
	r := new(big.Int).SetBytes(sig[:n])
	ss := new(big.Int).SetBytes(sig[n:])
	h := sha256.Sum256(input)
	if !ecdsa.Verify(v.key, h[:], r, ss) {
		return errors.New("signature verification failed")
	}
	return nil
}

// AtprotoSigner adapts the account ES256K implementation used by Cocoon.
type AtprotoSigner struct{ key *atcrypto.PrivateKeyK256 }

func NewAtprotoSigner(key *atcrypto.PrivateKeyK256) (*AtprotoSigner, error) {
	if key == nil {
		return nil, errors.New("nil atproto private key")
	}
	return &AtprotoSigner{key: key}, nil
}
func (s *AtprotoSigner) Algorithm() string                 { return "ES256K" }
func (s *AtprotoSigner) Sign(input []byte) ([]byte, error) { return s.key.HashAndSign(input) }

type AtprotoVerifier struct{ key atcrypto.PublicKey }

func NewAtprotoVerifier(key atcrypto.PublicKey) (*AtprotoVerifier, error) {
	if key == nil {
		return nil, errors.New("nil atproto public key")
	}
	return &AtprotoVerifier{key: key}, nil
}
func (v *AtprotoVerifier) Algorithm() string { return "ES256K" }
func (v *AtprotoVerifier) Verify(input, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("ES256K signature must be 64 bytes")
	}
	return v.key.HashAndVerifyLenient(input, sig)
}

func validECDSAAlgorithm(alg string) bool { return alg == "ES256" || alg == "ES256K" }
func curveMatchesAlgorithm(c elliptic.Curve, alg string) bool {
	if c == nil || c.Params() == nil {
		return false
	}
	if alg == "ES256" {
		return c == elliptic.P256()
	}
	name := strings.ToLower(c.Params().Name)
	return name == "secp256k1" || strings.Contains(name, "k-256")
}
func encodeECDSASignature(r, s *big.Int, bits int) []byte {
	n := (bits + 7) / 8
	out := make([]byte, n*2)
	rb, sb := r.Bytes(), s.Bytes()
	copy(out[n-len(rb):n], rb)
	copy(out[2*n-len(sb):], sb)
	return out
}

type CreateSpaceTokenOptions struct {
	Iss       string
	Sub       string
	Aud       string
	DPoPJKT   string
	Kid       string
	ExpiresIn time.Duration
	Now       func() time.Time
	Random    io.Reader
	JTI       string
}

type VerifySpaceTokenOptions struct {
	Resolver           KeyResolver
	KeyResolver        KeyResolver
	SigningKeyResolver SigningKeyResolver
	Verifier           Verifier
	Audience           string
	Subject            string
	Issuer             string
	Now                func() time.Time
	ClockSkew          time.Duration
	Replay             ReplayStore
	Context            context.Context
}

func CreateSpaceToken(kind TokenType, opts CreateSpaceTokenOptions, signer Signer) (string, error) {
	if signer == nil {
		return "", errors.New("nil token signer")
	}
	spec, err := tokenSpecFor(kind)
	if err != nil {
		return "", err
	}
	if !spec.algs[signer.Algorithm()] {
		return "", fmt.Errorf("%s signer algorithm %q is not allowed", kind, signer.Algorithm())
	}
	if opts.Iss == "" || opts.Sub == "" {
		return "", errors.New("token issuer and subject are required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ExpiresIn == 0 {
		opts.ExpiresIn = spec.lifetime
	}
	if opts.ExpiresIn <= 0 || opts.ExpiresIn > spec.lifetime {
		return "", fmt.Errorf("%s lifetime must be between 1 and %s", kind, spec.lifetime)
	}
	if opts.JTI == "" {
		opts.JTI, err = randomJTI(opts.Random)
		if err != nil {
			return "", err
		}
	}
	if !validJTI(opts.JTI) {
		return "", errors.New("invalid token jti")
	}
	if opts.ExpiresIn%time.Second != 0 {
		return "", errors.New("token lifetime must be an integral number of seconds")
	}
	if err := validateCreationClaims(kind, &opts); err != nil {
		return "", err
	}
	now := opts.Now().Unix()
	claims := SpaceTokenClaims{Iss: opts.Iss, Sub: opts.Sub, IAT: now, Exp: now + int64(opts.ExpiresIn/time.Second), JTI: opts.JTI}
	if opts.Aud != "" {
		aud := opts.Aud
		claims.Aud = &aud
	}
	if opts.DPoPJKT != "" {
		claims.Cnf = &SpaceTokenConfirmation{JKT: opts.DPoPJKT}
	}
	header := SpaceTokenHeader{Alg: signer.Algorithm(), Typ: spec.typ, Kid: spec.kid}
	if opts.Kid != "" {
		header.Kid = opts.Kid
	}
	if err := validateHeader(kind, header); err != nil {
		return "", err
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	input := h + "." + p
	sig, err := signer.Sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	if len(sig) != 64 {
		return "", errors.New("JWT ECDSA signature must be 64 bytes")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func CreateDelegationToken(opts CreateSpaceTokenOptions, signer Signer) (string, error) {
	return CreateSpaceToken(TokenDelegation, opts, signer)
}
func CreateClientAttestation(opts CreateSpaceTokenOptions, signer Signer) (string, error) {
	return CreateSpaceToken(TokenClientAttestation, opts, signer)
}
func CreateCredential(opts CreateSpaceTokenOptions, signer Signer) (string, error) {
	return CreateSpaceToken(TokenCredential, opts, signer)
}
func CreateSpaceCredential(opts CreateSpaceTokenOptions, signer Signer) (string, error) {
	return CreateCredential(opts, signer)
}

// ParseSpaceToken validates the complete JWT structure and all typed claims,
// but not its signature. It is intended solely to choose a separately resolved
// verification key before VerifySpaceToken performs mandatory verification.
func ParseSpaceToken(kind TokenType, raw string) (SpaceToken, error) {
	_, err := tokenSpecFor(kind)
	if err != nil {
		return SpaceToken{}, err
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return SpaceToken{}, authErr("BadJwt", "JWT must contain three non-empty parts", nil)
	}
	hb, err := decodeB64URL(parts[0])
	if err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT header encoding", err)
	}
	pb, err := decodeB64URL(parts[1])
	if err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT payload encoding", err)
	}
	sig, err := decodeB64URL(parts[2])
	if err != nil || len(sig) != 64 {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT signature encoding", err)
	}
	hm, err := strictObject(hb, map[string]bool{"alg": true, "typ": true, "kid": true})
	if err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT header", err)
	}
	pm, err := strictObject(pb, map[string]bool{"iss": true, "sub": true, "aud": true, "iat": true, "exp": true, "jti": true, "cnf": true})
	if err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT claims", err)
	}
	h := SpaceTokenHeader{}
	if h.Alg, err = requiredString(hm, "alg"); err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT alg", err)
	}
	if h.Typ, err = requiredString(hm, "typ"); err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT typ", err)
	}
	if v, ok := hm["kid"]; ok {
		h.Kid, err = stringValue(v)
		if err != nil || h.Kid == "" {
			return SpaceToken{}, authErr("BadJwt", "invalid JWT kid", err)
		}
	}
	if err := validateHeader(kind, h); err != nil {
		return SpaceToken{}, err
	}
	c := SpaceTokenClaims{}
	if c.Iss, err = requiredString(pm, "iss"); err != nil {
		return SpaceToken{}, authErr("BadJwtIss", "invalid JWT iss", err)
	}
	if c.Sub, err = requiredString(pm, "sub"); err != nil {
		return SpaceToken{}, authErr("BadJwtSub", "invalid JWT sub", err)
	}
	if v, ok := pm["aud"]; ok {
		a, e := stringValue(v)
		if e != nil || a == "" {
			return SpaceToken{}, authErr("BadJwtAudience", "invalid JWT aud", e)
		}
		c.Aud = &a
	}
	if c.IAT, err = requiredInt64(pm, "iat"); err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT iat", err)
	}
	if c.Exp, err = requiredInt64(pm, "exp"); err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT exp", err)
	}
	if c.JTI, err = requiredString(pm, "jti"); err != nil {
		return SpaceToken{}, authErr("BadJwt", "invalid JWT jti", err)
	}
	if v, ok := pm["cnf"]; ok {
		cnf, e := parseConfirmation(v)
		if e != nil {
			return SpaceToken{}, authErr("BadJwtCnf", "invalid JWT cnf", e)
		}
		c.Cnf = &cnf
	}
	if err := validateClaims(kind, &c); err != nil {
		return SpaceToken{}, err
	}
	return SpaceToken{Header: h, Claims: c, SigningInput: []byte(parts[0] + "." + parts[1]), Signature: sig}, nil
}

func VerifySpaceToken(ctx context.Context, kind TokenType, raw string, opts VerifySpaceTokenOptions) (SpaceToken, error) {
	tok, err := ParseSpaceToken(kind, raw)
	if err != nil {
		return SpaceToken{}, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ClockSkew == 0 {
		opts.ClockSkew = ClockSkew
	}
	now := opts.Now()
	if now.Add(opts.ClockSkew).Unix() < tok.Claims.IAT {
		return SpaceToken{}, authErr("JwtIssuedInFuture", "token issued in the future", nil)
	}
	if now.Add(-opts.ClockSkew).Unix() >= tok.Claims.Exp {
		return SpaceToken{}, authErr("JwtExpired", "token expired", nil)
	}
	if opts.Audience != "" && (tok.Claims.Aud == nil || *tok.Claims.Aud != opts.Audience) {
		return SpaceToken{}, authErr("BadJwtAudience", "token audience does not match", nil)
	}
	if opts.Subject != "" && tok.Claims.Sub != opts.Subject {
		return SpaceToken{}, authErr("BadJwtSub", "token subject does not match", nil)
	}
	if opts.Issuer != "" && tok.Claims.Iss != opts.Issuer {
		return SpaceToken{}, authErr("BadJwtIss", "token issuer does not match", nil)
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = opts.KeyResolver
	}
	resolveCtx := ctxOrBackground(opts.Context, ctx)
	verifier := opts.Verifier
	var refreshRequest KeyResolutionRequest
	if verifier == nil {
		refreshRequest = KeyResolutionRequest{Issuer: tok.Claims.Iss, Kid: tok.Header.Kid, Algorithm: tok.Header.Alg}
		if opts.SigningKeyResolver != nil {
			verifier, err = opts.SigningKeyResolver.ResolveSigningKey(resolveCtx, refreshRequest)
		} else if resolver != nil {
			verifier, err = resolver(resolveCtx, tok.Claims.Iss, tok.Header.Kid, tok.Header.Alg)
		}
	}
	if err != nil {
		return SpaceToken{}, authErr("BadJwtKey", "could not resolve token key", err)
	}
	if verifier == nil {
		return SpaceToken{}, authErr("BadJwtKey", "no token verification key", nil)
	}
	if verifier.Algorithm() != tok.Header.Alg {
		return SpaceToken{}, authErr("BadJwtAlgorithm", "verification key algorithm mismatch", nil)
	}
	if verifyErr := verifier.Verify(tok.SigningInput, tok.Signature); verifyErr != nil {
		if opts.SigningKeyResolver == nil {
			return SpaceToken{}, authErr("BadJwtSignature", "invalid token signature", verifyErr)
		}
		refreshRequest.ForceRefresh = true
		freshVerifier, refreshErr := opts.SigningKeyResolver.ResolveSigningKey(resolveCtx, refreshRequest)
		if refreshErr != nil {
			return SpaceToken{}, authErr("BadJwtKey", "could not refresh token key", refreshErr)
		}
		if freshVerifier == nil || freshVerifier.Algorithm() != tok.Header.Alg {
			return SpaceToken{}, authErr("BadJwtSignature", "invalid token signature", verifyErr)
		}
		if freshErr := freshVerifier.Verify(tok.SigningInput, tok.Signature); freshErr != nil {
			return SpaceToken{}, authErr("BadJwtSignature", "invalid token signature", freshErr)
		}
		verifier = freshVerifier
	}
	if opts.Replay != nil && tokenRequiresReplay(kind) {
		if err := opts.Replay.Consume(resolveCtx, tok.Claims.JTI, string(kind), time.Unix(tok.Claims.Exp, 0).Add(opts.ClockSkew)); err != nil {
			return SpaceToken{}, err
		}
	}
	return tok, nil
}
func VerifyDelegationToken(ctx context.Context, raw string, opts VerifySpaceTokenOptions) (SpaceToken, error) {
	return VerifySpaceToken(ctx, TokenDelegation, raw, opts)
}
func VerifyClientAttestation(ctx context.Context, raw string, opts VerifySpaceTokenOptions) (SpaceToken, error) {
	return VerifySpaceToken(ctx, TokenClientAttestation, raw, opts)
}
func VerifyCredential(ctx context.Context, raw string, opts VerifySpaceTokenOptions) (SpaceToken, error) {
	return VerifySpaceToken(ctx, TokenCredential, raw, opts)
}
func VerifySpaceCredential(ctx context.Context, raw string, opts VerifySpaceTokenOptions) (SpaceToken, error) {
	return VerifyCredential(ctx, raw, opts)
}
func ctxOrBackground(preferred, fallback context.Context) context.Context {
	if preferred != nil {
		return preferred
	}
	if fallback != nil {
		return fallback
	}
	return context.Background()
}

type tokenSpec struct {
	typ      string
	kid      string
	lifetime time.Duration
	replay   bool
	algs     map[string]bool
}

func tokenSpecFor(kind TokenType) (tokenSpec, error) {
	switch kind {
	case TokenDelegation:
		return tokenSpec{DelegationTokenType, DelegationSigningKeyID, DelegationLifetime, true, map[string]bool{"ES256": true, "ES256K": true}}, nil
	case TokenClientAttestation:
		return tokenSpec{ClientAttestationTokenType, "", ClientAttestationLifetime, true, map[string]bool{"ES256": true}}, nil
	case TokenCredential:
		return tokenSpec{CredentialTokenType, FallbackSigningKeyID, CredentialLifetime, false, map[string]bool{"ES256": true, "ES256K": true}}, nil
	default:
		return tokenSpec{}, fmt.Errorf("unknown Spaces token type %q", kind)
	}
}
func tokenRequiresReplay(kind TokenType) bool { s, _ := tokenSpecFor(kind); return s.replay }
func validateHeader(kind TokenType, h SpaceTokenHeader) error {
	s, err := tokenSpecFor(kind)
	if err != nil {
		return err
	}
	if !s.algs[h.Alg] {
		return authErr("BadJwtAlgorithm", "unsupported JWT algorithm", nil)
	}
	if h.Typ != s.typ {
		return authErr("BadJwtType", "wrong JWT typ", nil)
	}
	switch kind {
	case TokenDelegation:
		if h.Kid != DelegationSigningKeyID {
			return authErr("BadJwtKey", "delegation kid must be #atproto", nil)
		}
	case TokenClientAttestation:
		// Client attestations may omit kid or carry an explicit kid. The
		// resolver receives either value so a published multi-key JWKS can
		// select the exact client key.
	case TokenCredential:
		if h.Kid != SpaceSigningKeyID && h.Kid != FallbackSigningKeyID {
			return authErr("BadJwtKey", "credential kid must be #atproto_space or #atproto", nil)
		}
	}
	return nil
}
func validateClaims(kind TokenType, c *SpaceTokenClaims) error {
	if c.IAT <= 0 || c.Exp <= 0 || c.Exp <= c.IAT {
		return authErr("BadJwt", "iat/exp must be positive and ordered", nil)
	}
	if !validJTI(c.JTI) {
		return authErr("BadJwt", "jti is required", nil)
	}
	if c.Sub == "" {
		return authErr("BadJwtSub", "sub is required", nil)
	}
	spec, _ := tokenSpecFor(kind)
	if c.Exp-c.IAT > int64(spec.lifetime/time.Second) {
		return authErr("BadJwt", "token lifetime is too long", nil)
	}
	switch kind {
	case TokenDelegation:
		if _, err := syntax.ParseDID(c.Iss); err != nil {
			return authErr("BadJwtIss", "delegation iss must be a DID", err)
		}
		space, err := ParseSpaceURI(c.Sub)
		if err != nil {
			return authErr("BadJwtSub", "delegation sub must be a canonical space", err)
		}
		if c.Aud == nil || *c.Aud != string(space.AuthorityDID)+SpaceHostAudienceSuffix {
			return authErr("BadJwtAudience", "delegation audience is not the space authority", nil)
		}
		if c.Cnf != nil {
			return authErr("BadJwt", "delegation must not contain cnf", nil)
		}
	case TokenClientAttestation:
		if c.Iss != c.Sub {
			return authErr("BadJwtIss", "client attestation iss and sub must match", nil)
		}
		if c.Aud == nil || !validSpaceHostAudience(*c.Aud) {
			return authErr("BadJwtAudience", "client attestation aud is required", nil)
		}
		if c.Cnf != nil {
			return authErr("BadJwt", "client attestation must not contain cnf", nil)
		}
	case TokenCredential:
		space, err := ParseSpaceURI(c.Sub)
		if err != nil {
			return authErr("BadJwtSub", "credential sub must be a canonical space", err)
		}
		if _, err := syntax.ParseDID(c.Iss); err != nil || c.Iss != string(space.AuthorityDID) {
			return authErr("BadJwtIss", "credential issuer must be the space authority", err)
		}
		if c.Aud != nil {
			return authErr("BadJwtAudience", "credential must not contain aud", nil)
		}
		if c.Cnf == nil || !validJKT(c.Cnf.JKT) {
			return authErr("BadJwtCnf", "credential requires cnf.jkt", nil)
		}
	}
	return nil
}
func validateCreationClaims(kind TokenType, o *CreateSpaceTokenOptions) error {
	switch kind {
	case TokenDelegation:
		if _, err := syntax.ParseDID(o.Iss); err != nil {
			return fmt.Errorf("delegation issuer DID: %w", err)
		}
		space, err := ParseSpaceURI(o.Sub)
		if err != nil {
			return fmt.Errorf("delegation space subject: %w", err)
		}
		if o.Aud != string(space.AuthorityDID)+SpaceHostAudienceSuffix {
			return errors.New("delegation audience must be the space authority host audience")
		}
		if o.DPoPJKT != "" || (o.Kid != "" && o.Kid != DelegationSigningKeyID) {
			return errors.New("delegation has invalid cnf or kid")
		}
	case TokenClientAttestation:
		if o.Iss != o.Sub || o.Aud == "" || !validSpaceHostAudience(o.Aud) {
			return errors.New("client attestation requires matching client iss/sub and authority audience")
		}
		if o.DPoPJKT != "" {
			return errors.New("client attestation does not allow cnf")
		}
	case TokenCredential:
		space, err := ParseSpaceURI(o.Sub)
		if err != nil {
			return fmt.Errorf("credential space subject: %w", err)
		}
		if o.Iss != string(space.AuthorityDID) {
			return errors.New("credential issuer must be the space authority")
		}
		if _, err := syntax.ParseDID(o.Iss); err != nil {
			return fmt.Errorf("credential issuer DID: %w", err)
		}
		if o.Aud != "" || !validJKT(o.DPoPJKT) || (o.Kid != "" && o.Kid != SpaceSigningKeyID && o.Kid != FallbackSigningKeyID) {
			return errors.New("credential requires cnf.jkt, no audience, and a valid kid")
		}
	}
	return nil
}
func validSpaceHostAudience(s string) bool {
	if !strings.HasSuffix(s, SpaceHostAudienceSuffix) {
		return false
	}
	_, err := syntax.ParseDID(strings.TrimSuffix(s, SpaceHostAudienceSuffix))
	return err == nil
}
func validJTI(s string) bool { return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\r\n") }
func validJKT(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == sha256.Size && base64.RawURLEncoding.EncodeToString(b) == s
}
func randomJTI(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func decodeB64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errors.New("non-canonical base64url")
	}
	return b, nil
}
func strictObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '{' {
		return nil, errors.New("expected JSON object")
	}
	out := make(map[string]json.RawMessage)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok || !allowed[key] {
			return nil, fmt.Errorf("unknown object member %q", key)
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate object member %q", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("malformed JSON object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return out, nil
}
func requiredString(m map[string]json.RawMessage, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing %q", key)
	}
	s, err := stringValue(v)
	if err != nil || s == "" {
		if err == nil {
			err = errors.New("empty string")
		}
		return "", err
	}
	return s, nil
}
func stringValue(v json.RawMessage) (string, error) {
	if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		return "", errors.New("null is not a string")
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", err
	}
	return s, nil
}
func requiredInt64(m map[string]json.RawMessage, key string) (int64, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing %q", key)
	}
	var n int64
	if err := json.Unmarshal(v, &n); err != nil {
		return 0, err
	}
	return n, nil
}
func parseConfirmation(raw json.RawMessage) (SpaceTokenConfirmation, error) {
	m, err := strictObject(raw, map[string]bool{"jkt": true})
	if err != nil {
		return SpaceTokenConfirmation{}, err
	}
	jkt, err := requiredString(m, "jkt")
	if err != nil || !validJKT(jkt) {
		if err == nil {
			err = errors.New("invalid thumbprint")
		}
		return SpaceTokenConfirmation{}, err
	}
	return SpaceTokenConfirmation{JKT: jkt}, nil
}
