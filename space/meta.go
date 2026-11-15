package space

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// A space authority's host-side state for one space, carried between hosts
// when the authority's account migrates. Follows @atproto/space's
// space-meta-archive.ts.
//
// Serialized as a STAR archive with the atproto-space-meta profile. After the
// metadata come three sections, in this order, each in strict key order:
//
//  1. policy: the space's policy object.
//  2. Policy state: anything else the policy keeps (e.g. a member list), keyed
//     like record paths ({nsid}/{rkey}), with values the policy defines.
//  3. writer/{did}: one entry per repo in the writer set.

const (
	SpaceMetaStarType = "atproto-space-meta"
	SpaceMetaVersion  = 1

	metaPolicyKey       = "policy"
	metaWriterKeyPrefix = "writer/"
)

// SpaceMetaStarLimits are the lengths a space meta archive reader accepts.
var SpaceMetaStarLimits = StarLimits{MaxMetaLen: 64 * 1024, MaxKeyLen: 4 * 1024, MaxValueLen: 1024 * 1024}

// SpaceMetaArchiveError is a space meta archive that is malformed.
type SpaceMetaArchiveError struct{ Message string }

func (e *SpaceMetaArchiveError) Error() string { return e.Message }

func metaErr(format string, args ...any) error {
	return &SpaceMetaArchiveError{Message: fmt.Sprintf(format, args...)}
}

type SpaceMetaArchive struct {
	Space       string
	Policy      map[string]any
	PolicyState []PolicyStateEntry
	Writers     []SpaceMetaWriter
}

type PolicyStateEntry struct {
	Key   string
	Value map[string]any
}

// SpaceMetaWriter is a repo in the writer set, as listWriters reports it.
type SpaceMetaWriter struct {
	Did      string
	RepoRev  string
	Data     []byte
	SpaceRev string
}

// WriteSpaceMetaStar serializes a space meta archive, putting each section
// into key order.
func WriteSpaceMetaStar(w io.Writer, a SpaceMetaArchive) error {
	sw, err := WriteStar(w, map[string]any{
		"$type": SpaceMetaStarType,
		"ver":   int64(SpaceMetaVersion),
		"space": a.Space,
	})
	if err != nil {
		return err
	}
	type pair struct{ key, value []byte }
	toPair := func(key string, value map[string]any) (pair, error) {
		b, err := atdata.MarshalCBOR(value)
		return pair{[]byte(key), b}, err
	}
	var state, writers []pair
	for _, e := range a.PolicyState {
		p, err := toPair(e.Key, e.Value)
		if err != nil {
			return err
		}
		state = append(state, p)
	}
	for _, wr := range a.Writers {
		p, err := toPair(metaWriterKeyPrefix+wr.Did, map[string]any{
			"repoRev": wr.RepoRev, "data": atdata.Bytes(wr.Data), "spaceRev": wr.SpaceRev,
		})
		if err != nil {
			return err
		}
		writers = append(writers, p)
	}
	byKey := func(ps []pair) {
		sort.Slice(ps, func(i, j int) bool { return bytes.Compare(ps[i].key, ps[j].key) < 0 })
	}
	byKey(state)
	byKey(writers)
	policy, err := toPair(metaPolicyKey, a.Policy)
	if err != nil {
		return err
	}
	for _, p := range append(append([]pair{policy}, state...), writers...) {
		if err := sw.WritePair(p.key, p.value); err != nil {
			return err
		}
	}
	return sw.Close()
}

type metaSection int

const (
	sectionPolicy metaSection = iota
	sectionState
	sectionWriters
)

func sectionOf(key string) metaSection {
	switch {
	case key == metaPolicyKey:
		return sectionPolicy
	case strings.HasPrefix(key, metaWriterKeyPrefix):
		return sectionWriters
	}
	return sectionState
}

// ReadSpaceMetaStar reads a space meta archive, rejecting it if a length
// limit is exceeded, a section is missing or out of place, or a key is
// duplicated or out of order. Read whole, since it holds a space's
// configuration and writer set rather than its records.
func ReadSpaceMetaStar(r io.Reader) (*SpaceMetaArchive, error) {
	sr, err := ReadStar(r, SpaceMetaStarLimits)
	if err != nil {
		return nil, err
	}
	if sr.Meta["$type"] != SpaceMetaStarType {
		return nil, metaErr("invalid space meta archive metadata: $type must be %s", SpaceMetaStarType)
	}
	if ver, ok := sr.Meta["ver"].(int64); !ok || ver != SpaceMetaVersion {
		return nil, metaErr("invalid space meta archive metadata: ver must be %d", SpaceMetaVersion)
	}
	spaceURI, _ := sr.Meta["space"].(string)
	if _, err := ParseRef(spaceURI); err != nil {
		return nil, metaErr("invalid space meta archive metadata: space must be a space reference")
	}
	out := &SpaceMetaArchive{Space: spaceURI}
	var (
		policy  map[string]any
		section = metaSection(-1)
		prevKey []byte
	)
	for {
		key, value, err := sr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		keyStr := string(key)
		ks := sectionOf(keyStr)
		if ks != section {
			if section >= 0 && ks < section {
				return nil, metaErr("section out of order at %s", keyStr)
			}
			section, prevKey = ks, nil
		}
		if prevKey != nil && bytes.Compare(key, prevKey) <= 0 {
			return nil, metaErr("duplicate or out-of-order key: %s", keyStr)
		}
		prevKey = key

		m, err := atdata.UnmarshalCBOR(value)
		if err != nil {
			return nil, metaErr("invalid cbor at %s", keyStr)
		}
		switch ks {
		case sectionPolicy:
			policy = m
		case sectionState:
			out.PolicyState = append(out.PolicyState, PolicyStateEntry{Key: keyStr, Value: m})
		case sectionWriters:
			w, err := parseMetaWriter(keyStr, m)
			if err != nil {
				return nil, err
			}
			out.Writers = append(out.Writers, w)
		}
	}
	if policy == nil {
		return nil, metaErr("missing policy")
	}
	out.Policy = policy
	return out, nil
}

func parseMetaWriter(key string, m map[string]any) (SpaceMetaWriter, error) {
	did := strings.TrimPrefix(key, metaWriterKeyPrefix)
	if _, err := syntax.ParseDID(did); err != nil {
		return SpaceMetaWriter{}, metaErr("invalid DID in writer key: %s", key)
	}
	for k := range m {
		switch k {
		case "repoRev", "data", "spaceRev":
		default:
			return SpaceMetaWriter{}, metaErr("invalid writer at %s: unexpected property %q", key, k)
		}
	}
	w := SpaceMetaWriter{Did: did}
	var ok bool
	if w.RepoRev, ok = m["repoRev"].(string); !ok {
		return w, metaErr("invalid writer at %s: repoRev must be a TID", key)
	}
	if w.SpaceRev, ok = m["spaceRev"].(string); !ok {
		return w, metaErr("invalid writer at %s: spaceRev must be a TID", key)
	}
	for _, rev := range []string{w.RepoRev, w.SpaceRev} {
		if _, err := syntax.ParseTID(rev); err != nil {
			return w, metaErr("invalid writer at %s: %q is not a TID", key, rev)
		}
	}
	data, ok := m["data"].(atdata.Bytes)
	if !ok {
		return w, metaErr("invalid writer at %s: data must be bytes", key)
	}
	w.Data = []byte(data)
	return w, nil
}
