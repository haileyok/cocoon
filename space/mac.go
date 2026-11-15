package space

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
)

// Space repos authenticate commits and records with a MAC rather than a
// signature, so a leaked response proves nothing to a third party. A MAC is
// an HTTP message signature (RFC 9421) using hmac-sha256, keyed by a
// per-request shared secret (kem.go).
//
// The syncer requests a MAC with an Accept-Signature header, whose tag names a
// profile. The host responds with a header describing the commit or record it
// returned, and a MAC covering that header. Follows @atproto/space's mac.ts.

const (
	CommitMacProfile = "atproto-space-commit"
	RecordMacProfile = "atproto-space-record"

	// HeaderCommit and HeaderRecord are the response headers each profile's
	// MAC covers.
	HeaderCommit = "Atproto-Space-Commit"
	HeaderRecord = "Atproto-Space-Record"

	// HeaderAcceptSignature is the request header asking for a MAC.
	HeaderAcceptSignature = "Accept-Signature"

	macAlg = "hmac-sha256"
	// macLabel is the label this syncer requests its MAC under. A host
	// answers under the label that was requested, though a syncer finds the
	// MAC by its tag.
	macLabel = "mac"
)

// MacError is a missing or malformed MAC request or response, or a MAC that
// does not match (InvalidSpaceMac).
type MacError struct {
	Message string
	Cause   error
}

func (e *MacError) Error() string { return e.Message }
func (e *MacError) Unwrap() error { return e.Cause }

func macErr(format string, args ...any) error {
	return &MacError{Message: fmt.Sprintf(format, args...)}
}

// coveredHeader is the header a profile's MAC covers.
func coveredHeader(profile string) string {
	if profile == CommitMacProfile {
		return HeaderCommit
	}
	return HeaderRecord
}

// macComponents is what a MAC covers: its profile's header, flagged sf as a
// structured field.
func macComponents(profile string) []sfItem {
	return []sfItem{{Value: strings.ToLower(coveredHeader(profile)), Params: sfParams{{Key: "sf", Value: true}}}}
}

// The parameters a host fulfills: the key share to use, the profile's tag,
// and optionally the algorithm. A syncer uses a new key share for each
// request, so created, expires and nonce would add nothing.
var macRequestParams = []string{"keyid", "tag", "alg"}

// FormatMacRequest is the Accept-Signature request header asking for a MAC
// keyed by the shared secret for keyShare (see Encapsulate), e.g.
//
//	mac=("atproto-space-commit";sf);keyid="did:key:zDna...";tag="atproto-space-commit"
func FormatMacRequest(profile, keyShare string) string {
	return macLabel + "=" + serializeSFInnerList(sfInnerList{
		Items:  macComponents(profile),
		Params: sfParams{{Key: "keyid", Value: keyShare}, {Key: "tag", Value: profile}},
	})
}

// MacRequest is a MAC request, as the host reads it from Accept-Signature.
type MacRequest struct {
	Label    string
	KeyShare string
	// SignatureParams are the requested signature parameters, serialized. The
	// host's MAC uses them as given.
	SignatureParams string
}

// ParseMacRequest finds the MAC requested for profile in the Accept-Signature
// field lines, checking that the host can fulfill it. Requests with other
// tags are ignored, so it returns nil when none is for profile.
func ParseMacRequest(values []string, profile string) (*MacRequest, error) {
	if len(values) == 0 {
		return nil, nil
	}
	requests, err := parseSFDictionary(strings.Join(values, ", "))
	if err != nil {
		return nil, &MacError{Message: "malformed Accept-Signature header", Cause: err}
	}
	tagged := membersWithTag(requests, profile)
	if len(tagged) == 0 {
		return nil, nil
	}
	if len(tagged) > 1 {
		return nil, macErr(`more than one MAC requested with tag "%s"`, profile)
	}
	label, list := tagged[0].label, tagged[0].list
	expected := formatComponents(macComponents(profile))
	if formatComponents(list.Items) != expected {
		return nil, macErr("MAC must cover exactly %s", expected)
	}
	for _, p := range list.Params {
		if !slices.Contains(macRequestParams, p.Key) {
			return nil, macErr("unsupported MAC parameter: %s", p.Key)
		}
	}
	if alg, ok := list.Params.get("alg"); ok && alg != macAlg {
		return nil, macErr("MAC algorithm must be %s", macAlg)
	}
	keyShare, _ := list.Params.get("keyid")
	ks, ok := keyShare.(string)
	if !ok {
		return nil, macErr("missing or malformed keyid")
	}
	if _, err := syntax.ParseDID(ks); err != nil {
		return nil, macErr("missing or malformed keyid")
	}
	return &MacRequest{Label: label, KeyShare: ks, SignatureParams: serializeSFInnerList(list)}, nil
}

// CreateMacParams is what a host answers a MAC request with: the request, and
// the shared secret decapsulated from its key share.
type CreateMacParams struct {
	MacRequest
	SharedSecret []byte
}

// CreateCommitMacHeaders returns the response headers for a commit: an
// Atproto-Space-Commit header describing it, and a MAC covering that header,
// keyed by lowercase header name. The header holds the commit's fields, e.g.
//
//	ver=1, repo="did:example:alice", space="at://...", rev="3mwcj3b6uak2f", data=:q3J0...=:
func CreateCommitMacHeaders(c Commit, p CreateMacParams) map[string]string {
	header := serializeSFDictionary([]sfDictEntry{
		{"ver", sfItem{Value: c.Ver}},
		{"repo", sfItem{Value: c.Repo}},
		{"space", sfItem{Value: c.Space}},
		{"rev", sfItem{Value: c.Rev}},
		{"data", sfItem{Value: sfBytes(c.Data)}},
	})
	return createMacHeaders(CommitMacProfile, header, p)
}

// CreateRecordMacHeaders returns the response headers for a record: an
// Atproto-Space-Record header naming it, and a MAC covering that header, keyed
// by lowercase header name. The header holds the record's uri and cid, e.g.
//
//	uri="at://...", cid="bafyrei..."
func CreateRecordMacHeaders(uri string, c cid.Cid, p CreateMacParams) map[string]string {
	header := serializeSFDictionary([]sfDictEntry{
		{"uri", sfItem{Value: uri}},
		{"cid", sfItem{Value: c.String()}},
	})
	return createMacHeaders(RecordMacProfile, header, p)
}

func createMacHeaders(profile, covered string, p CreateMacParams) map[string]string {
	base := signatureBase(macComponents(profile), []string{covered}, p.SignatureParams)
	m := hmac.New(sha256.New, p.SharedSecret)
	m.Write(base)
	return map[string]string{
		strings.ToLower(coveredHeader(profile)): covered,
		"signature-input":                       p.Label + "=" + p.SignatureParams,
		"signature":                             p.Label + "=:" + base64.StdEncoding.EncodeToString(m.Sum(nil)) + ":",
	}
}

// VerifyMacParams is what a syncer checks a response's MAC with: the
// encapsulation the MAC was requested with, and the response's headers.
type VerifyMacParams struct {
	Encapsulation
	Headers http.Header
}

// VerifyCommitMac verifies a response's MAC, and that the Atproto-Space-Commit
// header it covers describes c.
func VerifyCommitMac(c Commit, p VerifyMacParams) error {
	fields, err := verifyMac(CommitMacProfile, p)
	if err != nil {
		return err
	}
	data, _ := bareItem(fields, "data").(sfBytes)
	ver, _ := bareItem(fields, "ver").(int64)
	if ver != c.Ver ||
		bareItem(fields, "repo") != c.Repo ||
		bareItem(fields, "space") != c.Space ||
		bareItem(fields, "rev") != c.Rev ||
		!hmac.Equal(data, c.Data) {
		return macErr("commit does not match its MAC")
	}
	return nil
}

// VerifyRecordMac verifies a response's MAC, and that the Atproto-Space-Record
// header it covers names uri and c.
func VerifyRecordMac(uri string, c cid.Cid, p VerifyMacParams) error {
	fields, err := verifyMac(RecordMacProfile, p)
	if err != nil {
		return err
	}
	if bareItem(fields, "uri") != uri || bareItem(fields, "cid") != c.String() {
		return macErr("record does not match its MAC")
	}
	return nil
}

// verifyMac checks the MAC requested for profile, returning the fields of the
// header it covers.
func verifyMac(profile string, p VerifyMacParams) (*sfDict, error) {
	components := macComponents(profile)
	found, err := findSignature(p.Headers.Values("Signature-Input"), p.Headers.Values("Signature"), signatureRequirements{
		tag: profile, components: components, alg: macAlg, keyID: p.KeyShare,
	}, macErr)
	if err != nil {
		return nil, err
	}
	header := coveredHeader(profile)
	values := p.Headers.Values(header)
	if len(values) == 0 {
		return nil, macErr("missing or malformed %s header", header)
	}
	fields, err := parseSFDictionary(strings.Join(values, ", "))
	if err != nil {
		return nil, &MacError{Message: fmt.Sprintf("malformed %s header", header), Cause: err}
	}
	// The sf flag covers the header as re-serialized from its parsed form.
	base := signatureBase(components, []string{fields.serialize()}, found.signatureParams)
	m := hmac.New(sha256.New, p.SharedSecret)
	m.Write(base)
	if !hmac.Equal(m.Sum(nil), found.signature) {
		return nil, macErr("MAC does not match")
	}
	return fields, nil
}

// bareItem is a dictionary member's value, ignoring any parameters.
func bareItem(d *sfDict, key string) any {
	if it, ok := d.members[key].(sfItem); ok {
		return it.Value
	}
	return nil
}
