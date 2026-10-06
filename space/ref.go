package space

import (
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// Ref names a space: at://{authority}/space/{spaceType}/{skey}.
type Ref struct {
	Authority string
	Type      string
	Skey      string
}

// ParseRef parses a space URI (the lexicon's space-ref format).
func ParseRef(s string) (Ref, error) {
	rest, ok := strings.CutPrefix(s, "at://")
	if !ok {
		return Ref{}, fmt.Errorf("not a space uri: %s", s)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 4 || parts[1] != "space" {
		return Ref{}, fmt.Errorf("not a space uri: %s", s)
	}
	r := Ref{Authority: parts[0], Type: parts[2], Skey: parts[3]}
	if _, err := syntax.ParseDID(r.Authority); err != nil {
		return Ref{}, fmt.Errorf("not a space uri: %s", s)
	}
	if _, err := syntax.ParseNSID(r.Type); err != nil {
		return Ref{}, fmt.Errorf("not a space uri: %s", s)
	}
	if _, err := syntax.ParseRecordKey(r.Skey); err != nil {
		return Ref{}, fmt.Errorf("not a space uri: %s", s)
	}
	return r, nil
}

func (r Ref) String() string {
	return "at://" + r.Authority + "/space/" + r.Type + "/" + r.Skey
}

// RecordURI is a record's URI within the space:
// at://{authority}/space/{spaceType}/{skey}/{author}/{collection}/{rkey}.
func (r Ref) RecordURI(author, collection, rkey string) string {
	return r.String() + "/" + author + "/" + collection + "/" + rkey
}

// HostAud is the audience the authority answers to as space host.
func (r Ref) HostAud() string { return SpaceHostAud(r.Authority) }
