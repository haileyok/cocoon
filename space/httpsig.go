package space

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// HTTP message signatures (RFC 9421) as space requests use them: a signature
// over the authorization header and, for a credential, the audience DID.

const (
	sigLabel = "atproto-space"
	sigAlg   = "ecdsa-p256-sha256"
	// HeaderSpaceAudience names the audience DID a credential request is for.
	HeaderSpaceAudience = "Atproto-Space-Audience"
)

// SignatureError is a request signature failure (BadSpaceSignature).
type SignatureError struct {
	Message string
	Cause   error
}

func (e *SignatureError) Error() string { return e.Message }
func (e *SignatureError) Unwrap() error { return e.Cause }

func sigErr(format string, args ...any) *SignatureError {
	return &SignatureError{Message: fmt.Sprintf(format, args...)}
}

func isP256DIDKey(didKey string) bool {
	pub, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return false
	}
	_, ok := pub.(*atcrypto.PublicKeyP256)
	return ok
}

// CreateSpaceSig signs the authorization value and, when audience is set, the
// audience. It returns the signature-input inner list and the compact
// signature.
func CreateSpaceSig(key atcrypto.PrivateKey, authorization, audience string) (string, []byte, error) {
	if _, ok := key.(*atcrypto.PrivateKeyP256); !ok {
		return "", nil, sigErr("signature key must be a P-256 did:key")
	}
	pub, err := key.PublicKey()
	if err != nil {
		return "", nil, err
	}
	var input string
	if audience == "" {
		input = `("authorization");keyid="` + pub.DIDKey() + `"`
	} else {
		input = `("authorization" "atproto-space-audience")`
	}
	sig, err := key.HashAndSign(signatureBase(authorization, input, audience, audience != ""))
	if err != nil {
		return "", nil, err
	}
	return input, sig, nil
}

// CreateSpaceSigHeaders returns the authorization, audience and signature
// headers for a space request, keyed by lowercase header name.
func CreateSpaceSigHeaders(key atcrypto.PrivateKey, authorization, audience string) (map[string]string, error) {
	input, sig, err := CreateSpaceSig(key, authorization, audience)
	if err != nil {
		return nil, err
	}
	out := map[string]string{
		"authorization":   authorization,
		"signature-input": sigLabel + "=" + input,
		"signature":       sigLabel + "=:" + base64.StdEncoding.EncodeToString(sig) + ":",
	}
	if audience != "" {
		out["atproto-space-audience"] = audience
	}
	return out, nil
}

// VerifySpaceSignature verifies a space request signature. keyID is the
// credential's bound did:key; empty means a delegation exchange, where the
// signature names its own key and covers only the authorization. It returns
// the did:key that signed.
func VerifySpaceSignature(h http.Header, keyID string) (string, error) {
	got, err := verifySpaceSignature(h, keyID)
	if err != nil {
		if se, ok := err.(*SignatureError); ok {
			return "", se
		}
		return "", &SignatureError{Message: "invalid HTTP message signature", Cause: err}
	}
	return got, nil
}

func verifySpaceSignature(h http.Header, keyID string) (string, error) {
	inputs, sigs := h.Values("Signature-Input"), h.Values("Signature")
	if len(inputs) == 0 || len(sigs) == 0 {
		return "", sigErr("missing or malformed signature headers")
	}
	// Repeated fields of a list-valued header combine, as an HTTP stack does.
	inputDict, err1 := parseSFDictionary(strings.Join(inputs, ", "))
	sigDict, err2 := parseSFDictionary(strings.Join(sigs, ", "))
	if err1 != nil || err2 != nil {
		return "", sigErr("missing or malformed atproto-space signature")
	}
	input, ok := inputDict[sigLabel].(sfInnerList)
	if !ok {
		return "", sigErr("missing or malformed atproto-space signature")
	}
	sigItem, ok := sigDict[sigLabel].(sfItem)
	if !ok {
		return "", sigErr("missing or malformed atproto-space signature")
	}
	sigBytes, ok := sigItem.Value.(sfBytes)
	if !ok || len(sigItem.Params) != 0 {
		return "", sigErr("missing or malformed atproto-space signature")
	}

	expected := []string{"authorization"}
	expectedStr := `"authorization"`
	if keyID != "" {
		expected = append(expected, "atproto-space-audience")
		expectedStr = `"authorization", "atproto-space-audience"`
	}
	if len(input.Items) != len(expected) {
		return "", sigErr("signature must cover exactly %s, in order", expectedStr)
	}
	for i, it := range input.Items {
		s, ok := it.Value.(string)
		if !ok || len(it.Params) != 0 || s != expected[i] {
			return "", sigErr("signature must cover exactly %s, in order", expectedStr)
		}
	}
	if alg, ok := input.Params.get("alg"); ok && alg != sigAlg {
		return "", sigErr("signature algorithm must be %s", sigAlg)
	}
	signingKey := keyID
	paramKid, hasKid := input.Params.get("keyid")
	if signingKey == "" {
		s, ok := paramKid.(string)
		if !hasKid || !ok {
			return "", sigErr("signature key must be a P-256 did:key")
		}
		signingKey = s
	}
	if !isP256DIDKey(signingKey) {
		return "", sigErr("signature key must be a P-256 did:key")
	}
	if keyID != "" && hasKid && paramKid != keyID {
		return "", sigErr("signature keyid does not match the credential key")
	}

	auths := h.Values("Authorization")
	if len(auths) != 1 || auths[0] == "" {
		return "", sigErr(`request requires exactly one "authorization" field`)
	}
	var audience string
	if keyID != "" {
		auds := h.Values(HeaderSpaceAudience)
		if len(auds) != 1 || auds[0] == "" {
			return "", sigErr(`request requires exactly one "atproto-space-audience" field`)
		}
		audience = auds[0]
	}

	base := signatureBase(auths[0], serializeSFInnerList(input), audience, keyID != "")
	pub, err := atcrypto.ParsePublicDIDKey(signingKey)
	if err != nil {
		return "", sigErr("signature key must be a P-256 did:key")
	}
	if len(sigBytes) != 64 || pub.HashAndVerifyLenient(base, sigBytes) != nil {
		return "", sigErr("invalid HTTP message signature")
	}
	return signingKey, nil
}

func signatureBase(authorization, input, audience string, withAudience bool) []byte {
	lines := []string{`"authorization": ` + strings.TrimSpace(authorization)}
	if withAudience {
		lines = append(lines, `"atproto-space-audience": `+strings.TrimSpace(audience))
	}
	lines = append(lines, `"@signature-params": `+input)
	return []byte(strings.Join(lines, "\n"))
}
