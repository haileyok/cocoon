package space

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/ipfs/go-cid"
)

// Space repos authenticate commits and records with a MAC rather than a
// signature, so a leaked response proves nothing to a third party. The MAC is
// keyed by a per-request shared secret (kem.go) and carried in HTTP headers
// rather than in the repo data. Follows @atproto/space's mac.ts.

const (
	CommitMacType    = "atproto-space-repo"
	RecordMacType    = "atproto-space-record"
	RecordMacVersion = 1

	// HeaderWantMac is the request header asking for a MAC.
	HeaderWantMac = "Atproto-Space-Want-Mac"
	// HeaderMac is the response header carrying it.
	HeaderMac = "Atproto-Space-Mac"
)

// MacError is a missing or malformed MAC header, an unsupported MAC type or
// version, or an invalid key (BadSpaceMac).
type MacError struct {
	Message string
	Cause   error
}

func (e *MacError) Error() string { return e.Message }
func (e *MacError) Unwrap() error { return e.Cause }

func macErr(format string, args ...any) *MacError {
	return &MacError{Message: fmt.Sprintf(format, args...)}
}

// macVersion is the version a MAC type is on. Commits share theirs with the
// commit format.
func macVersion(typ string) int64 {
	if typ == CommitMacType {
		return CommitVersion
	}
	return RecordMacVersion
}

// ComputeCommitMac is
//
//	context = "atproto-space-repo-v1"
//	   || uint16be(len(space)) || space
//	   || uint16be(len(repo))  || repo
//	   || uint16be(len(rev))   || rev
//	mac = HMAC-SHA256(shared_secret, context || data)
func ComputeCommitMac(sharedSecret []byte, c Commit) []byte {
	m := hmac.New(sha256.New, sharedSecret)
	m.Write([]byte(fmt.Sprintf("%s-v%d", CommitMacType, CommitVersion)))
	m.Write(lengthPrefixed(c.Space))
	m.Write(lengthPrefixed(c.Repo))
	m.Write(lengthPrefixed(c.Rev))
	m.Write(c.Data)
	return m.Sum(nil)
}

// VerifyCommitMac checks a commit MAC in constant time.
func VerifyCommitMac(sharedSecret []byte, c Commit, mac []byte) bool {
	return hmac.Equal(ComputeCommitMac(sharedSecret, c), mac)
}

// ComputeRecordMac is
//
//	context = "atproto-space-record-v1" || uint16be(len(uri)) || uri
//	mac = HMAC-SHA256(shared_secret, context || record_cid_bytes)
func ComputeRecordMac(sharedSecret []byte, uri string, c cid.Cid) []byte {
	m := hmac.New(sha256.New, sharedSecret)
	m.Write([]byte(fmt.Sprintf("%s-v%d", RecordMacType, RecordMacVersion)))
	m.Write(lengthPrefixed(uri))
	m.Write(c.Bytes())
	return m.Sum(nil)
}

// VerifyRecordMac checks a record MAC in constant time.
func VerifyRecordMac(sharedSecret []byte, uri string, c cid.Cid, mac []byte) bool {
	return hmac.Equal(ComputeRecordMac(sharedSecret, uri, c), mac)
}

func lengthPrefixed(s string) []byte {
	if len(s) > 0xffff {
		panic("MAC context field exceeds uint16 length prefix")
	}
	return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...)
}

// FormatWantMacHeader is the Atproto-Space-Want-Mac request header, e.g.
// type="atproto-space-repo", ver=1, key_share="did:key:zDna...".
func FormatWantMacHeader(typ, keyShare string) string {
	return serializeSFDictionary([]sfDictMember{
		{"type", typ}, {"ver", macVersion(typ)}, {"key_share", keyShare},
	})
}

// ParseWantMacHeader parses a request header of the given type, returning its
// key_share. values are every field line of the header.
func ParseWantMacHeader(values []string, typ string) (string, error) {
	fields, err := parseMacDictionary(values, typ)
	if err != nil {
		return "", err
	}
	ks, ok := fields["key_share"].(string)
	if !ok {
		return "", macErr("missing or malformed key_share")
	}
	return ks, nil
}

// FormatMacHeader is the Atproto-Space-Mac response header, e.g.
// type="atproto-space-repo", ver=1, mac=:AAECAwQF...:.
func FormatMacHeader(typ string, mac []byte) string {
	return serializeSFDictionary([]sfDictMember{
		{"type", typ}, {"ver", macVersion(typ)}, {"mac", sfBytes(mac)},
	})
}

// ParseMacHeader parses a response header of the given type, returning its
// MAC.
func ParseMacHeader(values []string, typ string) ([]byte, error) {
	fields, err := parseMacDictionary(values, typ)
	if err != nil {
		return nil, err
	}
	mac, ok := fields["mac"].(sfBytes)
	if !ok {
		return nil, macErr("missing or malformed mac")
	}
	return []byte(mac), nil
}

// parseMacDictionary parses either header and checks its type and ver,
// flattening it to bare values.
func parseMacDictionary(values []string, typ string) (map[string]any, error) {
	if len(values) == 0 {
		return nil, macErr("missing or malformed MAC header")
	}
	dict, err := parseSFDictionary(strings.Join(values, ", "))
	if err != nil {
		return nil, &MacError{Message: "malformed MAC header", Cause: err}
	}
	fields := make(map[string]any, len(dict))
	for k, m := range dict {
		it, ok := m.(sfItem)
		if !ok {
			return nil, macErr("malformed MAC header field: %s", k)
		}
		fields[k] = it.Value
	}
	if fields["type"] != typ {
		return nil, macErr("unsupported MAC type, expected %s", typ)
	}
	if v, ok := fields["ver"].(int64); !ok || v != macVersion(typ) {
		return nil, macErr("unsupported MAC version for %s", typ)
	}
	return fields, nil
}
