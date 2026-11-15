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
// audience DID, tagged atproto-space-credential. Verifiers find the signature
// by its tag, under any label. Follows @atproto/space's http-signature.ts.

const (
	// sigLabel is the label signers use. Labels carry no meaning (RFC 9421
	// §7.2.5), so verifiers look at the tag instead.
	sigLabel = "sig"
	sigTag   = "atproto-space-credential"
	sigAlg   = "ecdsa-p256-sha256"
	// CredentialScheme is the Authorization scheme a space credential is
	// presented with.
	CredentialScheme = "Atproto-Space-Credential"
	// HeaderSpaceAudience names the audience DID a credential request is for.
	HeaderSpaceAudience = "Atproto-Space-Audience"
)

// credentialComponents is what a credential use covers, in order.
var credentialComponents = []sfItem{{Value: "authorization"}, {Value: "atproto-space-audience"}}

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
	input := serializeSFInnerList(sfInnerList{
		Items:  credentialComponents,
		Params: sfParams{{Key: "tag", Value: sigTag}},
	})
	sig, err := key.HashAndSign(signatureBase(credentialComponents, []string{authorization, audience}, input))
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

	found, err := findSignature(h.Values("Signature-Input"), h.Values("Signature"), signatureRequirements{
		tag: sigTag, components: credentialComponents, alg: sigAlg, keyID: keyID,
	}, func(format string, args ...any) error { return sigErr(format, args...) })
	if err != nil {
		return err
	}
	if !IsP256DIDKey(keyID) {
		return sigErr("signature key must be a P-256 did:key")
	}
	base := signatureBase(credentialComponents, []string{auths[0], auds[0]}, found.signatureParams)
	pub, err := atcrypto.ParsePublicDIDKey(keyID)
	if err != nil {
		return sigErr("signature key must be a P-256 did:key")
	}
	if len(found.signature) != 64 || pub.HashAndVerifyLenient(base, found.signature) != nil {
		return sigErr("invalid HTTP message signature")
	}
	return nil
}

// RFC 9421 helpers, shared with MACs (mac.go).

// signatureRequirements is what an application requires of the signature it
// verifies (RFC 9421 §3.2.1).
type signatureRequirements struct {
	// tag identifies the signature among any others on the message.
	tag string
	// components are exactly what it must cover, in order.
	components []sfItem
	// alg and keyID are the algorithm and key it must use, if its alg and
	// keyid parameters name them.
	alg   string
	keyID string
}

type foundSignature struct {
	signatureParams string
	signature       []byte
}

// findSignature finds the one signature tagged required.tag in a message's
// Signature-Input and Signature fields, and checks it meets the requirements.
// Labels carry no meaning, so the tag is what identifies it. Other
// parameters, like created, are covered by the signature but not interpreted.
// Repeated fields of a list-valued header combine, as an HTTP stack does.
func findSignature(inputs, sigs []string, required signatureRequirements, mkErr func(format string, args ...any) error) (*foundSignature, error) {
	if len(inputs) == 0 || len(sigs) == 0 {
		return nil, mkErr("missing or malformed signature headers")
	}
	inputDict, err1 := parseSFDictionary(strings.Join(inputs, ", "))
	sigDict, err2 := parseSFDictionary(strings.Join(sigs, ", "))
	if err1 != nil || err2 != nil {
		return nil, mkErr("missing or malformed signature headers")
	}

	tagged := membersWithTag(inputDict, required.tag)
	if len(tagged) > 1 {
		return nil, mkErr(`more than one signature with tag "%s"`, required.tag)
	}
	var sig []byte
	if len(tagged) == 1 {
		sig = getSignature(sigDict, tagged[0].label)
	}
	if sig == nil {
		return nil, mkErr(`missing or malformed signature with tag "%s"`, required.tag)
	}

	list := tagged[0].list
	expected := formatComponents(required.components)
	if formatComponents(list.Items) != expected {
		return nil, mkErr("signature must cover exactly %s, in order", expected)
	}
	if alg, ok := list.Params.get("alg"); ok && alg != required.alg {
		return nil, mkErr("signature algorithm must be %s", required.alg)
	}
	if kid, ok := list.Params.get("keyid"); ok && kid != required.keyID {
		return nil, mkErr("signature keyid does not match the expected key")
	}
	return &foundSignature{signatureParams: serializeSFInnerList(list), signature: sig}, nil
}

type labeledList struct {
	label string
	list  sfInnerList
}

// membersWithTag returns the members of a Signature-Input or Accept-Signature
// field tagged tag.
func membersWithTag(d *sfDict, tag string) []labeledList {
	var out []labeledList
	for _, label := range d.keys {
		l, ok := d.members[label].(sfInnerList)
		if !ok {
			continue
		}
		if t, ok := l.Params.get("tag"); ok && t == tag {
			out = append(out, labeledList{label: label, list: l})
		}
	}
	return out
}

// getSignature returns the signature bytes under label in a Signature field,
// or nil if it is not well formed.
func getSignature(d *sfDict, label string) []byte {
	it, ok := d.members[label].(sfItem)
	if !ok {
		return nil
	}
	b, ok := it.Value.(sfBytes)
	if !ok || len(it.Params) != 0 {
		return nil
	}
	return []byte(b)
}

// formatComponents is a covered component list without its parameters, e.g.
// ("authorization" "atproto-space-audience").
func formatComponents(components []sfItem) string {
	return serializeSFInnerList(sfInnerList{Items: components})
}

// signatureBase is the signature base (RFC 9421 §2.5) for a signature
// covering components, whose values are given in order, under the serialized
// signatureParams.
func signatureBase(components []sfItem, values []string, signatureParams string) []byte {
	lines := make([]string, 0, len(components)+1)
	for i, c := range components {
		lines = append(lines, serializeSFItem(c)+": "+strings.TrimSpace(values[i]))
	}
	lines = append(lines, `"@signature-params": `+signatureParams)
	return []byte(strings.Join(lines, "\n"))
}
