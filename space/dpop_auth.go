package space

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DPOPProofType     = "dpop+jwt"
	DPOPPProofType    = DPOPProofType // compatibility spelling for callers
	DPOP_PROOF_TYP    = DPOPProofType
	MaxDpopProofAge   = 60 * time.Second
	MAX_PROOF_AGE_SEC = 60
)

type DpopProof struct {
	JTI      string
	JKT      string
	HTM      string
	HTU      string
	IssuedAt time.Time
}

type CreateDpopProofOptions struct {
	Htm               string
	Htu               string
	HTTPMethod        string
	HTTPURL           string
	Credential        string
	CredentialPresent bool
	JTI               string
	Now               func() time.Time
	Random            io.Reader
}

// DPoPSigner must expose its bare public P-256 JWK. Embedded key material is
// part of the proof header and is verified before any claim is trusted.
type DPoPSigner interface {
	Signer
	PublicJWK() ([]byte, error)
}

func (s *ECDSASigner) PublicJWK() ([]byte, error) {
	if s == nil || s.key == nil || s.alg != "ES256" || s.key.Curve != elliptic.P256() {
		return nil, errors.New("DPoP requires an ES256 P-256 signer")
	}
	return marshalP256JWK(&s.key.PublicKey)
}

// CreateDpopProof creates an RFC 9449 proof. The issuance form omits ath; set
// CredentialPresent (or Credential) when proving possession for a credential
// request.
func CreateDpopProof(signer DPoPSigner, opts CreateDpopProofOptions) (string, error) {
	if signer == nil || signer.Algorithm() != "ES256" {
		return "", errors.New("DPoP requires an ES256 signer")
	}
	method := opts.Htm
	if method == "" {
		method = opts.HTTPMethod
	}
	htu := opts.Htu
	if htu == "" {
		htu = opts.HTTPURL
	}
	if method == "" {
		return "", errors.New("DPoP htm is required")
	}
	normalized, err := NormalizeDpopHTU(htu)
	if err != nil {
		return "", err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.JTI == "" {
		opts.JTI, err = randomJTI(opts.Random)
		if err != nil {
			return "", err
		}
	}
	if !validJTI(opts.JTI) {
		return "", errors.New("invalid DPoP jti")
	}
	jwkBytes, err := signer.PublicJWK()
	if err != nil {
		return "", err
	}
	if _, _, err := parseP256JWK(jwkBytes); err != nil {
		return "", fmt.Errorf("invalid DPoP public JWK: %w", err)
	}
	claims := dpopClaims{JTI: opts.JTI, HTM: method, HTU: normalized, IAT: opts.Now().Unix()}
	if opts.CredentialPresent || opts.Credential != "" {
		if opts.Credential == "" {
			return "", errors.New("credential must not be empty")
		}
		h := sha256.Sum256([]byte(opts.Credential))
		ath := base64.RawURLEncoding.EncodeToString(h[:])
		claims.Ath = &ath
	}
	header := dpopHeader{Alg: "ES256", Typ: DPOPProofType, JWK: jwkBytes}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(hb)
	c := base64.RawURLEncoding.EncodeToString(cb)
	input := h + "." + c
	sig, err := signer.Sign([]byte(input))
	if err != nil {
		return "", err
	}
	if len(sig) != 64 {
		return "", errors.New("DPoP ES256 signature must be 64 bytes")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func CreateDPoPProof(signer DPoPSigner, opts CreateDpopProofOptions) (string, error) {
	return CreateDpopProof(signer, opts)
}

type VerifyDpopProofOptions struct {
	Htm               string
	Htu               string
	HTTPMethod        string
	HTTPURL           string
	Credential        string
	CredentialPresent bool
	JKT               string
	ExpectedJKT       string
	Now               func() time.Time
	ClockSkew         time.Duration
	Replay            ReplayStore
	Context           context.Context
}

// VerifyDpopProof checks signature, method, normalized URL, age, embedded-key
// thumbprint, and ath. Replay is consumed atomically after every other check.
func VerifyDpopProof(ctx context.Context, raw string, opts VerifyDpopProofOptions) (DpopProof, error) {
	method := opts.Htm
	if method == "" {
		method = opts.HTTPMethod
	}
	htu := opts.Htu
	if htu == "" {
		htu = opts.HTTPURL
	}
	if method == "" {
		return DpopProof{}, errors.New("DPoP request method is required")
	}
	normalized, err := NormalizeDpopHTU(htu)
	if err != nil {
		return DpopProof{}, err
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return DpopProof{}, authErr("BadDpopProof", "DPoP JWT must contain three non-empty parts", nil)
	}
	hb, err := decodeB64URL(parts[0])
	if err != nil {
		return DpopProof{}, authErr("BadDpopProof", "invalid DPoP header encoding", err)
	}
	cb, err := decodeB64URL(parts[1])
	if err != nil {
		return DpopProof{}, authErr("BadDpopProof", "invalid DPoP claims encoding", err)
	}
	sig, err := decodeB64URL(parts[2])
	if err != nil || len(sig) != 64 {
		return DpopProof{}, authErr("BadDpopProof", "invalid DPoP signature", err)
	}
	hm, err := strictObject(hb, map[string]bool{"alg": true, "typ": true, "jwk": true})
	if err != nil {
		return DpopProof{}, authErr("BadDpopProof", "invalid DPoP header", err)
	}
	cm, err := strictObject(cb, map[string]bool{"jti": true, "htm": true, "htu": true, "iat": true, "ath": true})
	if err != nil {
		return DpopProof{}, authErr("BadDpopProof", "invalid DPoP claims", err)
	}
	alg, err := requiredString(hm, "alg")
	if err != nil || alg != "ES256" {
		return DpopProof{}, authErr("BadDpopAlgorithm", "DPoP alg must be ES256", err)
	}
	typ, err := requiredString(hm, "typ")
	if err != nil || typ != DPOPProofType {
		return DpopProof{}, authErr("BadDpopType", "DPoP typ must be dpop+jwt", err)
	}
	jwkRaw, ok := hm["jwk"]
	if !ok {
		return DpopProof{}, authErr("BadDpopProof", "DPoP jwk is required", nil)
	}
	pub, jkt, err := parseP256JWK(jwkRaw)
	if err != nil {
		return DpopProof{}, authErr("BadDpopKey", "invalid embedded DPoP JWK", err)
	}
	verifier, err := NewECDSAVerifier(pub, "ES256")
	if err != nil {
		return DpopProof{}, authErr("BadDpopKey", "invalid embedded DPoP key", err)
	}
	if err := verifier.Verify([]byte(parts[0]+"."+parts[1]), sig); err != nil {
		return DpopProof{}, authErr("BadDpopSignature", "invalid DPoP signature", err)
	}
	jti, err := requiredString(cm, "jti")
	if err != nil || !validJTI(jti) {
		return DpopProof{}, authErr("BadDpopProof", "DPoP jti is required", err)
	}
	htm, err := requiredString(cm, "htm")
	if err != nil || htm != method {
		return DpopProof{}, authErr("BadDpopMethod", "DPoP htm does not match request", err)
	}
	htuClaim, err := requiredString(cm, "htu")
	if err != nil || htuClaim != normalized {
		return DpopProof{}, authErr("BadDpopURL", "DPoP htu does not match request", err)
	}
	iat, err := requiredInt64(cm, "iat")
	if err != nil || iat <= 0 {
		return DpopProof{}, authErr("BadDpopProof", "DPoP iat is required", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ClockSkew == 0 {
		opts.ClockSkew = ClockSkew
	}
	now := opts.Now()
	issued := time.Unix(iat, 0)
	if now.Add(opts.ClockSkew).Before(issued) {
		return DpopProof{}, authErr("DpopProofFuture", "DPoP proof is from the future", nil)
	}
	if now.Add(-opts.ClockSkew).Sub(issued) > MaxDpopProofAge {
		return DpopProof{}, authErr("DpopProofExpired", "DPoP proof is too old", nil)
	}
	ath, hasAth := "", false
	if rawAth, ok := cm["ath"]; ok {
		ath, err = stringValue(rawAth)
		if err != nil || ath == "" {
			return DpopProof{}, authErr("BadDpopATH", "invalid DPoP ath", err)
		}
		hasAth = true
	}
	credentialRequired := opts.CredentialPresent || opts.Credential != ""
	if credentialRequired {
		if opts.Credential == "" {
			return DpopProof{}, authErr("BadDpopATH", "credential is required", nil)
		}
		h := sha256.Sum256([]byte(opts.Credential))
		want := base64.RawURLEncoding.EncodeToString(h[:])
		if !hasAth || ath != want {
			return DpopProof{}, authErr("BadDpopATH", "DPoP ath does not match credential", nil)
		}
	} else if hasAth {
		return DpopProof{}, authErr("BadDpopATH", "DPoP ath is forbidden for issuance", nil)
	}
	expectedJKT := opts.JKT
	if expectedJKT == "" {
		expectedJKT = opts.ExpectedJKT
	}
	if credentialRequired {
		if !validJKT(expectedJKT) {
			return DpopProof{}, authErr("DpopKeyMismatch", "credential-mode DPoP verification requires a valid expected JKT", nil)
		}
		if jkt != expectedJKT {
			return DpopProof{}, authErr("DpopKeyMismatch", "DPoP key thumbprint does not match credential", nil)
		}
	} else if expectedJKT != "" {
		if !validJKT(expectedJKT) || jkt != expectedJKT {
			return DpopProof{}, authErr("DpopKeyMismatch", "DPoP key thumbprint does not match expected JKT", nil)
		}
	}
	if opts.Replay != nil {
		if err := opts.Replay.Consume(ctxOrBackground(opts.Context, ctx), jti, "dpop", issued.Add(MaxDpopProofAge).Add(opts.ClockSkew)); err != nil {
			return DpopProof{}, err
		}
	}
	return DpopProof{JTI: jti, JKT: jkt, HTM: htm, HTU: htuClaim, IssuedAt: issued}, nil
}

func VerifyDPoPProof(ctx context.Context, raw string, opts VerifyDpopProofOptions) (DpopProof, error) {
	return VerifyDpopProof(ctx, raw, opts)
}

// NormalizeDpopHTU implements the common WHATWG URL serialization needed by
// RFC 9449 htu: absolute HTTP(S), lower-case scheme/host, default ports
// removed, literal dot segments resolved, and query/fragment removed. Raw
// percent-encoded path octets are preserved and are never treated as dots.
func NormalizeDpopHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Scheme == "" {
		return "", errors.New("DPoP htu must be an absolute HTTP(S) URL without credentials")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("DPoP htu must use HTTP or HTTPS")
	}
	hostname := u.Hostname()
	if hostname == "" || strings.Contains(hostname, "%") {
		return "", errors.New("DPoP htu has an unsupported host")
	}
	for _, r := range hostname {
		if r > 127 {
			return "", errors.New("DPoP htu does not support non-ASCII IDNA hostnames")
		}
	}
	host := strings.ToLower(hostname)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("DPoP htu has an invalid port")
		}
		defaultPort := (scheme == "http" && portNumber == 80) || (scheme == "https" && portNumber == 443)
		if !defaultPort {
			host += ":" + strconv.Itoa(portNumber)
		}
	}
	path := removeDpopDotSegments(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

func removeDpopDotSegments(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return raw
	}
	segments := strings.Split(raw, "/")
	out := make([]string, 0, len(segments))
	for i, segment := range segments {
		switch segment {
		case ".":
			if i == len(segments)-1 {
				out = append(out, "")
			}
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if i == len(segments)-1 {
				out = append(out, "")
			}
		default:
			out = append(out, segment)
		}
	}
	result := strings.Join(out, "/")
	if result == "" {
		return "/"
	}
	if !strings.HasPrefix(result, "/") {
		return "/" + result
	}
	return result
}

func NormalizeHTU(raw string) (string, error) { return NormalizeDpopHTU(raw) }

func DpopJKTForKey(key *ecdsa.PublicKey) (string, error) {
	_, jkt, err := parseP256JWKFromKey(key)
	return jkt, err
}
func DPoPJKTForKey(key *ecdsa.PublicKey) (string, error) { return DpopJKTForKey(key) }

// RFC 7638 uses the lexicographically ordered required EC members.
type dpopHeader struct {
	Alg string          `json:"alg"`
	Typ string          `json:"typ"`
	JWK json.RawMessage `json:"jwk"`
}
type dpopClaims struct {
	JTI string  `json:"jti"`
	HTM string  `json:"htm"`
	HTU string  `json:"htu"`
	Ath *string `json:"ath,omitempty"`
	IAT int64   `json:"iat"`
}
type p256JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func marshalP256JWK(key *ecdsa.PublicKey) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("not a valid P-256 public key")
	}
	n := 32
	xb := key.X.Bytes()
	yb := key.Y.Bytes()
	x := make([]byte, n)
	y := make([]byte, n)
	copy(x[n-len(xb):], xb)
	copy(y[n-len(yb):], yb)
	return json.Marshal(p256JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(x), Y: base64.RawURLEncoding.EncodeToString(y)})
}
func parseP256JWK(raw []byte) (*ecdsa.PublicKey, string, error) {
	m, err := strictObject(raw, map[string]bool{"kty": true, "crv": true, "x": true, "y": true})
	if err != nil {
		return nil, "", err
	}
	kty, err := requiredString(m, "kty")
	if err != nil || kty != "EC" {
		return nil, "", errors.New("JWK kty must be EC")
	}
	crv, err := requiredString(m, "crv")
	if err != nil || crv != "P-256" {
		return nil, "", errors.New("JWK crv must be P-256")
	}
	xs, err := requiredString(m, "x")
	if err != nil {
		return nil, "", err
	}
	ys, err := requiredString(m, "y")
	if err != nil {
		return nil, "", err
	}
	xb, err := decodeB64URL(xs)
	if err != nil || len(xb) != 32 {
		return nil, "", errors.New("invalid JWK x")
	}
	yb, err := decodeB64URL(ys)
	if err != nil || len(yb) != 32 {
		return nil, "", errors.New("invalid JWK y")
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, "", errors.New("JWK point is not on P-256")
	}
	thumbJSON := []byte(`{"crv":"P-256","kty":"EC","x":"` + xs + `","y":"` + ys + `"}`)
	h := sha256.Sum256(thumbJSON)
	return key, base64.RawURLEncoding.EncodeToString(h[:]), nil
}
func parseP256JWKFromKey(key *ecdsa.PublicKey) (*ecdsa.PublicKey, string, error) {
	b, err := marshalP256JWK(key)
	if err != nil {
		return nil, "", err
	}
	return parseP256JWK(b)
}
