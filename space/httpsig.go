package space

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// HTTP message signatures (RFC 9421) as requests authorized by a space
// credential use them: a signature over the authorization header and the
// audience DID, labeled and tagged atproto-space-credential. Follows
// @atproto/space's http-signature.ts.

const (
	sigLabel = "atproto-space-credential"
	sigTag   = "atproto-space-credential"
	sigAlg   = "ecdsa-p256-sha256"
	// CredentialScheme is the Authorization scheme a space credential is
	// presented with.
	CredentialScheme = "Atproto-Space-Credential"
	// HeaderSpaceAudience names the audience DID a credential request is for.
	HeaderSpaceAudience = "Atproto-Space-Audience"
)

// sigCovered is what a credential use covers, in order.
const sigCovered = `("authorization" "atproto-space-audience")`

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

// IsP256DIDKey reports whether didKey is a P-256 did:key, the only kind a
// space credential can be bound to.
func IsP256DIDKey(didKey string) bool {
	pub, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return false
	}
	_, ok := pub.(*atcrypto.PublicKeyP256)
	return ok
}

// CreateSpaceSig signs a request authorized by a space credential, covering
// the credential (authorization, which must use the Atproto-Space-Credential
// scheme) and its audience DID. It returns the signature-input inner list and
// the compact signature.
func CreateSpaceSig(key atcrypto.PrivateKey, authorization, audience string) (string, []byte, error) {
	if _, ok := key.(*atcrypto.PrivateKeyP256); !ok {
		return "", nil, sigErr("signature key must be a P-256 did:key")
	}
	if audience == "" {
		return "", nil, sigErr("a space credential signature requires an audience")
	}
	input := sigCovered + `;tag="` + sigTag + `"`
	sig, err := key.HashAndSign(signatureBase(authorization, audience, input))
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
	return map[string]string{
		"authorization":          authorization,
		"atproto-space-audience": audience,
		"signature-input":        sigLabel + "=" + input,
		"signature":              sigLabel + "=:" + base64.StdEncoding.EncodeToString(sig) + ":",
	}, nil
}

// VerifyCredentialSig verifies the signature on a request authorized by a
// space credential, against the key the credential is bound to (its cnf.kid).
func VerifyCredentialSig(h http.Header, keyID string) error {
	if err := verifyCredentialSig(h, keyID); err != nil {
		if se, ok := err.(*SignatureError); ok {
			return se
		}
		return &SignatureError{Message: "invalid HTTP message signature", Cause: err}
	}
	return nil
}

func verifyCredentialSig(h http.Header, keyID string) error {
	auths := h.Values("Authorization")
	if len(auths) != 1 || auths[0] == "" {
		return sigErr(`missing or malformed "authorization" field`)
	}
	auds := h.Values(HeaderSpaceAudience)
	if len(auds) != 1 || auds[0] == "" {
		return sigErr(`missing or malformed "atproto-space-audience" field`)
	}

	inputs, sigs := h.Values("Signature-Input"), h.Values("Signature")
	if len(inputs) == 0 || len(sigs) == 0 {
		return sigErr("missing or malformed signature headers")
	}
	// Repeated fields of a list-valued header combine, as an HTTP stack does.
	inputDict, err1 := parseSFDictionary(strings.Join(inputs, ", "))
	sigDict, err2 := parseSFDictionary(strings.Join(sigs, ", "))
	if err1 != nil || err2 != nil {
		return sigErr("missing or malformed signature headers")
	}
	input, ok := inputDict[sigLabel].(sfInnerList)
	if !ok {
		return sigErr("missing or malformed %s signature", sigLabel)
	}
	sigItem, ok := sigDict[sigLabel].(sfItem)
	if !ok {
		return sigErr("missing or malformed %s signature", sigLabel)
	}
	sigBytes, ok := sigItem.Value.(sfBytes)
	if !ok || len(sigItem.Params) != 0 {
		return sigErr("missing or malformed %s signature", sigLabel)
	}

	if serializeSFInnerList(sfInnerList{Items: input.Items}) != sigCovered {
		return sigErr("signature must cover exactly %s, in order", sigCovered)
	}
	if tag, ok := input.Params.get("tag"); !ok || tag != sigTag {
		return sigErr(`signature tag must be "%s"`, sigTag)
	}
	if alg, ok := input.Params.get("alg"); ok && alg != sigAlg {
		return sigErr("signature algorithm must be %s", sigAlg)
	}
	if kid, ok := input.Params.get("keyid"); ok && kid != keyID {
		return sigErr("signature keyid does not match the credential key")
	}
	if !IsP256DIDKey(keyID) {
		return sigErr("signature key must be a P-256 did:key")
	}

	base := signatureBase(auths[0], auds[0], serializeSFInnerList(input))
	pub, err := atcrypto.ParsePublicDIDKey(keyID)
	if err != nil {
		return sigErr("signature key must be a P-256 did:key")
	}
	if len(sigBytes) != 64 || pub.HashAndVerifyLenient(base, sigBytes) != nil {
		return sigErr("invalid HTTP message signature")
	}
	return nil
}

func signatureBase(authorization, audience, input string) []byte {
	return []byte(strings.Join([]string{
		`"authorization": ` + strings.TrimSpace(authorization),
		`"atproto-space-audience": ` + strings.TrimSpace(audience),
		`"@signature-params": ` + input,
	}, "\n"))
}
