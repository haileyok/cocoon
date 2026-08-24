// Package space provides pure value types and cryptographic primitives for
// atproto Spaces.
package space

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

const atprotoScheme = "at://"

// SpaceURI identifies a space hosted by an authority.
//
// Its canonical form is
// at://{authorityDid}/space/{spaceType}/{skey}.
type SpaceURI struct {
	AuthorityDID syntax.DID
	SpaceType    syntax.NSID
	SKey         syntax.RecordKey
}

// RecordURI identifies a record in a space.
//
// Its canonical form is
// at://{authorityDid}/space/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}.
type RecordURI struct {
	AuthorityDID syntax.DID
	SpaceType    syntax.NSID
	SKey         syntax.RecordKey
	AuthorDID    syntax.DID
	Collection   syntax.NSID
	RKey         syntax.RecordKey
}

// SpaceRef and RecordRef are descriptive aliases for the URI value types.
type SpaceRef = SpaceURI
type RecordRef = RecordURI

// NewSpaceURI validates components and returns a canonical space URI value.
func NewSpaceURI(authorityDID, spaceType, skey string) (SpaceURI, error) {
	authority, err := syntax.ParseDID(authorityDID)
	if err != nil {
		return SpaceURI{}, fmt.Errorf("authority DID: %w", err)
	}
	typeValue, err := syntax.ParseNSID(spaceType)
	if err != nil {
		return SpaceURI{}, fmt.Errorf("space type: %w", err)
	}
	key, err := syntax.ParseRecordKey(skey)
	if err != nil {
		return SpaceURI{}, fmt.Errorf("space key: %w", err)
	}
	return SpaceURI{AuthorityDID: authority, SpaceType: typeValue, SKey: key}, nil
}

// NewRecordURI validates components and returns a canonical record URI value.
func NewRecordURI(authorityDID, spaceType, skey, authorDID, collection, rkey string) (RecordURI, error) {
	spaceURI, err := NewSpaceURI(authorityDID, spaceType, skey)
	if err != nil {
		return RecordURI{}, err
	}
	author, err := syntax.ParseDID(authorDID)
	if err != nil {
		return RecordURI{}, fmt.Errorf("author DID: %w", err)
	}
	collectionValue, err := syntax.ParseNSID(collection)
	if err != nil {
		return RecordURI{}, fmt.Errorf("collection: %w", err)
	}
	recordKey, err := syntax.ParseRecordKey(rkey)
	if err != nil {
		return RecordURI{}, fmt.Errorf("record key: %w", err)
	}
	return RecordURI{
		AuthorityDID: spaceURI.AuthorityDID,
		SpaceType:    spaceURI.SpaceType,
		SKey:         spaceURI.SKey,
		AuthorDID:    author,
		Collection:   collectionValue,
		RKey:         recordKey,
	}, nil
}

// ParseSpaceURI parses exactly the canonical space URI grammar.
func ParseSpaceURI(raw string) (SpaceURI, error) {
	parts, err := splitURI(raw, 6)
	if err != nil {
		return SpaceURI{}, err
	}
	if parts[3] != "space" {
		return SpaceURI{}, errors.New("space URI must contain the literal /space/ segment")
	}
	value, err := NewSpaceURI(parts[2], parts[4], parts[5])
	if err != nil {
		return SpaceURI{}, err
	}
	if value.String() != raw {
		return SpaceURI{}, errors.New("space URI is not canonical")
	}
	return value, nil
}

// ParseRecordURI parses exactly the canonical space record URI grammar.
func ParseRecordURI(raw string) (RecordURI, error) {
	parts, err := splitURI(raw, 9)
	if err != nil {
		return RecordURI{}, err
	}
	if parts[3] != "space" {
		return RecordURI{}, errors.New("record URI must contain the literal /space/ segment")
	}
	value, err := NewRecordURI(parts[2], parts[4], parts[5], parts[6], parts[7], parts[8])
	if err != nil {
		return RecordURI{}, err
	}
	if value.String() != raw {
		return RecordURI{}, errors.New("record URI is not canonical")
	}
	return value, nil
}

// ParseSpaceRef is an alias for ParseSpaceURI.
func ParseSpaceRef(raw string) (SpaceRef, error) { return ParseSpaceURI(raw) }

// ParseRecordRef is an alias for ParseRecordURI.
func ParseRecordRef(raw string) (RecordRef, error) { return ParseRecordURI(raw) }

// ParseSpace is an alias for ParseSpaceURI.
func ParseSpace(raw string) (SpaceURI, error) { return ParseSpaceURI(raw) }

// ParseRecord is an alias for ParseRecordURI.
func ParseRecord(raw string) (RecordURI, error) { return ParseRecordURI(raw) }

func splitURI(raw string, want int) ([]string, error) {
	if raw == "" {
		return nil, errors.New("space URI is empty")
	}
	// Space components are emitted literally. Accepting URI escapes would allow
	// multiple textual forms for the same path (and encoded slashes could alter
	// segment boundaries), so escaped/noncanonical forms are not valid here.
	if strings.ContainsAny(raw, "?#%") {
		return nil, errors.New("space URI must not contain query, fragment, or percent encoding")
	}
	if !strings.HasPrefix(raw, atprotoScheme) {
		return nil, errors.New("space URI must start with at://")
	}
	parts := strings.Split(raw, "/")
	if len(parts) != want {
		return nil, fmt.Errorf("space URI has %d path segments, want %d", len(parts), want)
	}
	if parts[0] != "at:" || parts[1] != "" {
		return nil, errors.New("space URI must use the at:// scheme")
	}
	return parts, nil
}

// SpaceScopeComponents returns the authority, space type, and space key used
// by OAuth space-scope matching.
func (u SpaceURI) SpaceScopeComponents() (authority, spaceType, skey string) {
	return string(u.AuthorityDID), string(u.SpaceType), string(u.SKey)
}

// String returns the canonical textual representation.
func (u SpaceURI) String() string {
	return atprotoScheme + string(u.AuthorityDID) + "/space/" + string(u.SpaceType) + "/" + string(u.SKey)
}

// String returns the canonical textual representation.
func (u RecordURI) String() string {
	return atprotoScheme + string(u.AuthorityDID) + "/space/" + string(u.SpaceType) + "/" + string(u.SKey) + "/" + string(u.AuthorDID) + "/" + string(u.Collection) + "/" + string(u.RKey)
}

// MarshalText implements encoding.TextMarshaler.
func (u SpaceURI) MarshalText() ([]byte, error) { return []byte(u.String()), nil }

// MarshalText implements encoding.TextMarshaler.
func (u RecordURI) MarshalText() ([]byte, error) { return []byte(u.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (u *SpaceURI) UnmarshalText(text []byte) error {
	value, err := ParseSpaceURI(string(text))
	if err != nil {
		return err
	}
	*u = value
	return nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (u *RecordURI) UnmarshalText(text []byte) error {
	value, err := ParseRecordURI(string(text))
	if err != nil {
		return err
	}
	*u = value
	return nil
}

// Space returns the space portion of a record URI.
func (u RecordURI) Space() SpaceURI {
	return SpaceURI{AuthorityDID: u.AuthorityDID, SpaceType: u.SpaceType, SKey: u.SKey}
}
