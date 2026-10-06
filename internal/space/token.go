package space

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// TokenType is one of the three space JWT kinds.
type TokenType string

const (
	TokenDelegation        TokenType = "delegation"
	TokenCredential        TokenType = "credential"
	TokenClientAttestation TokenType = "clientAttestation"
)

// TokenSpec describes how a token type is minted and checked.
type TokenSpec struct {
	Typ          string
	Kid          string
	ExpiresInSec int64
	RequireAud   bool
	RequireCnf   bool
	SingleUse    bool
}

// TokenSpecs follows SPACE_TOKEN_TYPES in @atproto/space. Credentials carry no
// audience: HTTP message signatures bind each use to an audience DID.
var TokenSpecs = map[TokenType]TokenSpec{
	TokenDelegation:        {Typ: "atproto-space-delegation+jwt", Kid: "#atproto", ExpiresInSec: 60, RequireAud: true, SingleUse: true},
	TokenCredential:        {Typ: "atproto-space-credential+jwt", Kid: "#atproto", ExpiresInSec: 600, RequireCnf: true},
	TokenClientAttestation: {Typ: "atproto-client-attestation+jwt", ExpiresInSec: 60, RequireAud: true, SingleUse: true},
}

const (
	// ClockSkewSec is the allowance applied to exp, and to a credential's iat.
	ClockSkewSec = 5
	// CredentialMaxAgeSec bounds a credential's lifetime.
	CredentialMaxAgeSec = 3600
)

// SpaceHostAud is the audience a delegation token and a client attestation
// name: the authority acting as space host.
func SpaceHostAud(authority string) string { return authority + "#atproto_space_host" }

// TokenError is a token failure with an XRPC-style code.
type TokenError struct {
	Code    string
	Message string
}

func (e *TokenError) Error() string { return e.Message }

func tokErr(code, format string, args ...any) *TokenError {
	return &TokenError{Code: code, Message: fmt.Sprintf(format, args...)}
}

type TokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type TokenCnf struct {
	Kid string `json:"kid"`
}

// TokenPayload's field order matches the reference's JSON output. Sub is the
// space URI, or the client_id for a client attestation.
type TokenPayload struct {
	Iss string    `json:"iss"`
	Sub string    `json:"sub"`
	Aud string    `json:"aud,omitempty"`
	Cnf *TokenCnf `json:"cnf,omitempty"`
	Iat int64     `json:"iat"`
	Exp int64     `json:"exp"`
	Jti string    `json:"jti"`
}

type Token struct {
	Header  TokenHeader
	Payload TokenPayload
}

// ParsedToken is a structurally valid token with its signing input, before any
// signature check.
type ParsedToken struct {
	Token
	SigningInput []byte
	Sig          []byte
}

type CreateTokenOpts struct {
	Iss string
	Sub string
	Aud string
	// KeyID is the did:key the credential is bound to (cnf.kid).
	KeyID string
	// ExpiresInSec overrides the type's default lifetime.
	ExpiresInSec *int64
	// Kid overrides the type's default header kid.
	Kid string
	// Now overrides the clock.
	Now time.Time
}

// JWTAlg is the JWT alg for a key: ES256 for P-256, ES256K for secp256k1.
func JWTAlg(key any) (string, error) {
	switch key.(type) {
	case *atcrypto.PrivateKeyP256, atcrypto.PrivateKeyP256, *atcrypto.PublicKeyP256:
		return "ES256", nil
	case *atcrypto.PrivateKeyK256, atcrypto.PrivateKeyK256, *atcrypto.PublicKeyK256:
		return "ES256K", nil
	}
	return "", fmt.Errorf("unsupported key type %T", key)
}

func randomHex16() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// CreateSpaceToken mints and signs a space token.
func CreateSpaceToken(typ TokenType, opts CreateTokenOpts, key atcrypto.PrivateKey) (string, error) {
	spec, ok := TokenSpecs[typ]
	if !ok {
		return "", fmt.Errorf("unknown token type %q", typ)
	}
	if spec.RequireAud && opts.Aud == "" {
		return "", tokErr("BadJwt", `a %s token requires an "aud"`, typ)
	}
	if spec.RequireCnf && opts.KeyID == "" {
		return "", tokErr("BadJwt", `a %s token requires a "keyId"`, typ)
	}
	exp := spec.ExpiresInSec
	if opts.ExpiresInSec != nil {
		exp = *opts.ExpiresInSec
	}
	if typ == TokenCredential && (exp <= 0 || exp > CredentialMaxAgeSec) {
		return "", tokErr("BadJwt", "invalid space credential lifetime")
	}
	alg, err := JWTAlg(key)
	if err != nil {
		return "", err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	header := TokenHeader{Alg: alg, Typ: spec.Typ, Kid: spec.Kid}
	if opts.Kid != "" {
		header.Kid = opts.Kid
	}
	iat := now.Unix()
	payload := TokenPayload{Iss: opts.Iss, Sub: opts.Sub, Aud: opts.Aud, Iat: iat, Exp: iat + exp, Jti: randomHex16()}
	if opts.KeyID != "" {
		payload.Cnf = &TokenCnf{Kid: opts.KeyID}
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := b64url(hb) + "." + b64url(pb)
	sig, err := key.HashAndSign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64url(sig), nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeB64URL accepts base64url with or without padding.
func decodeB64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func decodeJSONPart(s, part string) (map[string]json.RawMessage, error) {
	b, err := decodeB64URL(s)
	if err != nil {
		return nil, tokErr("BadJwt", "could not parse token %s: %v", part, err)
	}
	var m map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&m); err != nil || m == nil {
		return nil, tokErr("BadJwt", "could not parse token %s: not a JSON object", part)
	}
	return m, nil
}

func strField(m map[string]json.RawMessage, k string) (string, bool) {
	raw, ok := m[k]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func numField(m map[string]json.RawMessage, k string) (float64, bool) {
	raw, ok := m[k]
	if !ok {
		return 0, false
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// ParseSpaceToken validates a token's structure, without checking its
// signature. That is as far as a client attestation goes here, since its key
// comes from the client's JWKS rather than a DID document.
func ParseSpaceToken(typ TokenType, jwt string) (*ParsedToken, error) {
	spec, ok := TokenSpecs[typ]
	if !ok {
		return nil, fmt.Errorf("unknown token type %q", typ)
	}
	parts := bytes.Split([]byte(jwt), []byte("."))
	if len(parts) != 3 {
		return nil, tokErr("BadJwt", "malformed token: expected 3 parts")
	}
	hm, err := decodeJSONPart(string(parts[0]), "header")
	if err != nil {
		return nil, err
	}
	pm, err := decodeJSONPart(string(parts[1]), "payload")
	if err != nil {
		return nil, err
	}

	var t ParsedToken
	t.Header.Typ, _ = strField(hm, "typ")
	t.Header.Alg, _ = strField(hm, "alg")
	t.Header.Kid, _ = strField(hm, "kid")
	if t.Header.Typ != spec.Typ {
		return nil, tokErr("BadJwtType", `wrong token type: expected "%s", got "%s"`, spec.Typ, t.Header.Typ)
	}
	if t.Header.Alg == "" {
		return nil, tokErr("BadJwt", `missing token "alg"`)
	}
	p := &t.Payload
	if p.Iss, _ = strField(pm, "iss"); p.Iss == "" {
		return nil, tokErr("BadJwtIss", `missing token "iss"`)
	}
	if p.Sub, _ = strField(pm, "sub"); p.Sub == "" {
		return nil, tokErr("BadJwtSub", `missing token "sub"`)
	}
	exp, ok := numField(pm, "exp")
	if !ok {
		return nil, tokErr("BadJwt", `missing token "exp"`)
	}
	p.Exp = int64(exp)
	p.Aud, _ = strField(pm, "aud")
	if spec.RequireAud && p.Aud == "" {
		return nil, tokErr("BadJwtAudience", `missing token "aud"`)
	}
	if raw, ok := pm["cnf"]; ok {
		var cnf struct {
			Kid string `json:"kid"`
		}
		if json.Unmarshal(raw, &cnf) == nil && cnf.Kid != "" {
			p.Cnf = &TokenCnf{Kid: cnf.Kid}
		}
	}
	if spec.RequireCnf {
		if p.Cnf == nil {
			return nil, tokErr("BadJwtCnf", `missing token "cnf.kid"`)
		}
		if _, err := syntax.ParseDID(p.Cnf.Kid); err != nil {
			return nil, tokErr("BadJwtCnf", `missing token "cnf.kid"`)
		}
	}
	if p.Jti, _ = strField(pm, "jti"); p.Jti == "" {
		return nil, tokErr("BadJwt", `a %s token requires a "jti"`, typ)
	}
	iat, hasIat := numField(pm, "iat")
	p.Iat = int64(iat)
	if typ == TokenCredential && (!hasIat || exp <= iat || exp-iat > CredentialMaxAgeSec) {
		return nil, tokErr("BadJwt", "invalid space credential lifetime")
	}
	if typ == TokenClientAttestation && p.Iss != p.Sub {
		return nil, tokErr("BadJwtIss", `client attestation "iss" and "sub" must both be the client_id`)
	}
	sig, err := decodeB64URL(string(parts[2]))
	if err != nil {
		return nil, tokErr("BadJwt", "could not parse token signature")
	}
	t.SigningInput = []byte(string(parts[0]) + "." + string(parts[1]))
	t.Sig = sig
	return &t, nil
}

// SigningKeyFunc resolves the did:key an issuer signs with. forceRefresh asks
// for a fresh resolution, after a cached key failed to verify.
type SigningKeyFunc func(iss, kid string, forceRefresh bool) (string, error)

type VerifyTokenOpts struct {
	GetSigningKey SigningKeyFunc
	// Aud and Sub, when set, must match the token's.
	Aud string
	Sub string
	// Now overrides the clock.
	Now time.Time
}

// VerifySpaceToken parses a token, checks its timing, audience and subject,
// and verifies its signature against the issuer's key, retrying once with a
// freshly resolved key in case the key rotated.
func VerifySpaceToken(typ TokenType, jwt string, opts VerifyTokenOpts) (*Token, error) {
	t, err := ParseSpaceToken(typ, jwt)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	n := now.Unix()
	if typ == TokenCredential && t.Payload.Iat > n+ClockSkewSec {
		return nil, tokErr("BadJwt", "space credential issued in the future")
	}
	if n-ClockSkewSec >= t.Payload.Exp {
		return nil, tokErr("JwtExpired", "token expired")
	}
	if opts.Aud != "" && t.Payload.Aud != opts.Aud {
		return nil, tokErr("BadJwtAudience", "token audience does not match this service")
	}
	if opts.Sub != "" && t.Payload.Sub != opts.Sub {
		return nil, tokErr("BadJwtSub", "token subject does not match the requested space")
	}
	didKey, err := opts.GetSigningKey(t.Payload.Iss, t.Header.Kid, false)
	if err != nil {
		return nil, tokErr("BadJwtSignature", "could not resolve the token signing key: %v", err)
	}
	ok, err := matchesSignature(didKey, t)
	if err != nil {
		return nil, err
	}
	if ok {
		return &t.Token, nil
	}
	fresh, err := opts.GetSigningKey(t.Payload.Iss, t.Header.Kid, true)
	if err != nil {
		return nil, tokErr("BadJwtSignature", "could not resolve the token signing key: %v", err)
	}
	if fresh != didKey {
		ok, err := matchesSignature(fresh, t)
		if err != nil {
			return nil, err
		}
		if ok {
			return &t.Token, nil
		}
	}
	return nil, tokErr("BadJwtSignature", "invalid token signature")
}

func matchesSignature(didKey string, t *ParsedToken) (bool, error) {
	pub, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return false, tokErr("BadJwtSignature", "could not verify token signature: %v", err)
	}
	return VerifyJWTSignature(pub, t.Header.Alg, t.SigningInput, t.Sig)
}

// VerifyJWTSignature checks a compact, low-S JWT signature, refusing an alg
// that does not match the key.
func VerifyJWTSignature(pub atcrypto.PublicKey, alg string, input, sig []byte) (bool, error) {
	want, err := JWTAlg(pub)
	if err != nil {
		return false, tokErr("BadJwtSignature", "could not verify token signature: %v", err)
	}
	if alg != want {
		return false, tokErr("BadJwtSignature", "could not verify token signature: alg %q does not match the key", alg)
	}
	return pub.HashAndVerify(input, sig) == nil, nil
}
