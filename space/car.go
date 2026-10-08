package space

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	car "github.com/ipld/go-car"
	carutil "github.com/ipld/go-car/util"
	"github.com/multiformats/go-multihash"
	cbg "github.com/whyrusleeping/cbor-gen"
)

// RepoVerificationError is a space repo CAR that does not verify.
type RepoVerificationError struct{ Message string }

func (e *RepoVerificationError) Error() string { return e.Message }

func verr(format string, args ...any) error {
	return &RepoVerificationError{Message: fmt.Sprintf(format, args...)}
}

var cborPrefix = cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)

func cidForCBOR(b []byte) cid.Cid {
	c, err := cborPrefix.Sum(b)
	if err != nil {
		panic(err)
	}
	return c
}

// SerializedRecord is a record's DAG-CBOR block.
type SerializedRecord struct {
	Collection string
	Rkey       string
	Cid        cid.Cid
	Bytes      []byte
}

// SerializeRecord encodes a record (atproto data model) as DAG-CBOR.
func SerializeRecord(collection, rkey string, record map[string]any) (SerializedRecord, error) {
	b, err := atdata.MarshalCBOR(record)
	if err != nil {
		return SerializedRecord{}, err
	}
	return SerializedRecord{Collection: collection, Rkey: rkey, Cid: cidForCBOR(b), Bytes: b}, nil
}

// EncodeCommit encodes a signed commit as its DAG-CBOR block.
func EncodeCommit(c SignedCommit) ([]byte, error) {
	return atdata.MarshalCBOR(map[string]any{
		"ver":  c.Ver,
		"hash": atdata.Bytes(c.Hash),
		"ikm":  atdata.Bytes(c.Ikm),
		"sig":  atdata.Bytes(c.Sig),
		"mac":  atdata.Bytes(c.Mac),
		"rev":  c.Rev,
	})
}

// DecodeCommit parses a signed commit block.
func DecodeCommit(b []byte) (SignedCommit, error) {
	m, err := atdata.UnmarshalCBOR(b)
	if err != nil {
		return SignedCommit{}, err
	}
	var c SignedCommit
	ver, ok := m["ver"].(int64)
	if !ok || ver != CommitVersion {
		return c, errors.New("ver: expected 1")
	}
	c.Ver = ver
	for k, dst := range map[string]*[]byte{"hash": &c.Hash, "ikm": &c.Ikm, "sig": &c.Sig, "mac": &c.Mac} {
		v, ok := m[k].(atdata.Bytes)
		if !ok {
			return c, fmt.Errorf("%s: expected bytes", k)
		}
		*dst = []byte(v)
	}
	if c.Rev, ok = m["rev"].(string); !ok {
		return c, errors.New("rev: expected a string")
	}
	return c, nil
}

// canonicalLess is DAG-CBOR map key order: shorter first, then bytewise.
func canonicalLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// SerializeRepo writes a space repo CAR: two roots in order (the signed commit,
// then the index of path -> CID), then one block per index entry in the
// index's order. With excludeValues only the two roots are written; the index
// still authenticates against the commit.
func SerializeRepo(w io.Writer, commit SignedCommit, records []SerializedRecord, excludeValues bool) error {
	byPath := make(map[string]SerializedRecord, len(records))
	for _, r := range records {
		byPath[FormatRecordPath(r.Collection, r.Rkey)] = r
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return canonicalLess(paths[i], paths[j]) })

	index := make(map[string]any, len(paths))
	for _, p := range paths {
		index[p] = atdata.CIDLink(byPath[p].Cid)
	}
	commitBytes, err := EncodeCommit(commit)
	if err != nil {
		return err
	}
	indexBytes, err := atdata.MarshalCBOR(index)
	if err != nil {
		return err
	}
	cc, ic := cidForCBOR(commitBytes), cidForCBOR(indexBytes)
	if err := car.WriteHeader(&car.CarHeader{Roots: []cid.Cid{cc, ic}, Version: 1}, w); err != nil {
		return err
	}
	if err := carutil.LdWrite(w, cc.Bytes(), commitBytes); err != nil {
		return err
	}
	if err := carutil.LdWrite(w, ic.Bytes(), indexBytes); err != nil {
		return err
	}
	if excludeValues {
		return nil
	}
	for _, p := range paths {
		r := byPath[p]
		if err := carutil.LdWrite(w, r.Cid.Bytes(), r.Bytes); err != nil {
			return err
		}
	}
	return nil
}

type VerifyRepoParams struct {
	Space  string
	Author string
	DidKey string
	// IndexOnly accepts a CAR with no record blocks (an excludeValues export).
	IndexOnly bool
}

type VerifiedRecord struct {
	Collection string
	Rkey       string
	Cid        cid.Cid
	Record     map[string]any
}

// RepoCarReader is a CAR whose commit and index have verified; Next streams
// and verifies its records.
type RepoCarReader struct {
	Commit     SignedCommit
	Index      map[string]cid.Cid
	IndexOrder []string
	Repo       *RepoCommit

	br     *bufio.Reader
	params VerifyRepoParams
	i      int
	done   bool
}

// VerifyRepoCar verifies a CAR's commit, and its index against the commit's
// hash, which authenticates every path/CID pair without reading a record.
// Records verify as Next is called, so drain it to know the repo is complete.
func VerifyRepoCar(r io.Reader, params VerifyRepoParams) (*RepoCarReader, error) {
	br := bufio.NewReader(r)
	h, err := car.ReadHeader(br)
	if err != nil {
		return nil, fmt.Errorf("invalid car header: %w", err)
	}
	if h.Version != 1 {
		return nil, fmt.Errorf("unsupported car version %d", h.Version)
	}
	if len(h.Roots) != 2 {
		return nil, verr("expected 2 car roots (commit, index), got %d", len(h.Roots))
	}
	cc, cb, err := readBlock(br)
	if err != nil || !cc.Equals(h.Roots[0]) {
		return nil, verr("expected the commit block to lead the car")
	}
	commit, err := DecodeCommit(cb)
	if err != nil {
		return nil, verr("invalid signed commit: %v", err)
	}
	ctx := CommitCtx{Space: params.Space, Author: params.Author, Rev: commit.Rev}
	if !VerifyCommit(commit, ctx, params.DidKey) {
		return nil, verr("commit failed verification")
	}
	ic, ib, err := readBlock(br)
	if err != nil || !ic.Equals(h.Roots[1]) {
		return nil, verr("expected the index block to follow the commit")
	}
	index, order, err := decodeIndex(ib)
	if err != nil {
		return nil, verr("invalid repo index: %v", err)
	}
	repo := RepoCommitFromIndex(index)
	if !repo.Matches(commit) {
		return nil, verr("index does not match the commit hash")
	}
	return &RepoCarReader{Commit: commit, Index: index, IndexOrder: order, Repo: repo, br: br, params: params}, nil
}

// readBlock reads one section and checks its bytes against its CID.
func readBlock(br *bufio.Reader) (cid.Cid, []byte, error) {
	c, data, err := carutil.ReadNode(br)
	if err != nil {
		return cid.Undef, nil, err
	}
	got, err := c.Prefix().Sum(data)
	if err != nil || !got.Equals(c) {
		return cid.Undef, nil, fmt.Errorf("not a valid CID for bytes (%s)", c)
	}
	return c, data, nil
}

// decodeIndex reads the index map, keeping its encoded key order.
func decodeIndex(b []byte) (map[string]cid.Cid, []string, error) {
	cr := cbg.NewCborReader(bytes.NewReader(b))
	maj, n, err := cr.ReadHeader()
	if err != nil {
		return nil, nil, err
	}
	if maj != cbg.MajMap {
		return nil, nil, errors.New("expected a map")
	}
	index := make(map[string]cid.Cid, n)
	order := make([]string, 0, n)
	for i := uint64(0); i < n; i++ {
		key, err := cbg.ReadStringWithMax(cr, 1<<16)
		if err != nil {
			return nil, nil, err
		}
		if !isRecordPath(key) {
			return nil, nil, fmt.Errorf("%q is not a record path", key)
		}
		c, err := cbg.ReadCid(cr)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: Not a valid CID", key)
		}
		if _, dup := index[key]; dup {
			return nil, nil, fmt.Errorf("duplicate key %q", key)
		}
		index[key] = c
		order = append(order, key)
	}
	return index, order, nil
}

func isRecordPath(s string) bool {
	i := strings.IndexByte(s, '/')
	return i > 0 && i < len(s)-1 && strings.IndexByte(s[i+1:], '/') == -1
}

// ParseRecordPath splits "{collection}/{rkey}".
func ParseRecordPath(p string) (string, string, error) {
	parts := strings.Split(p, "/")
	if len(parts) != 2 {
		return "", "", verr("invalid record path: %s", p)
	}
	return parts[0], parts[1], nil
}

// Next returns the next verified record, or io.EOF once every index entry has
// been read.
func (r *RepoCarReader) Next() (*VerifiedRecord, error) {
	if r.done {
		return nil, io.EOF
	}
	c, data, err := readBlock(r.br)
	if err == io.EOF {
		r.done = true
		indexOnly := r.params.IndexOnly && r.i == 0
		if r.i < len(r.IndexOrder) && !indexOnly {
			return nil, verr("car is missing %d record(s) named in the index", len(r.IndexOrder)-r.i)
		}
		return nil, io.EOF
	}
	if err != nil {
		return nil, err
	}
	if r.i >= len(r.IndexOrder) {
		return nil, verr("car has more blocks than index entries")
	}
	path := r.IndexOrder[r.i]
	want := r.Index[path]
	r.i++
	if !c.Equals(want) {
		return nil, verr("expected block %s at %s, got %s", want, path, c)
	}
	collection, rkey, err := ParseRecordPath(path)
	if err != nil {
		return nil, err
	}
	rec, err := atdata.UnmarshalCBOR(data)
	if err != nil {
		return nil, verr("invalid record cbor at %s", path)
	}
	return &VerifiedRecord{Collection: collection, Rkey: rkey, Cid: c, Record: rec}, nil
}

// VerifiedRepo is a fully read and verified repo CAR.
type VerifiedRepo struct {
	Commit     SignedCommit
	Index      map[string]cid.Cid
	IndexOrder []string
	Repo       *RepoCommit
	Records    []VerifiedRecord
}

// VerifyRepoCarFull verifies a CAR and collects its records.
func VerifyRepoCarFull(r io.Reader, params VerifyRepoParams) (*VerifiedRepo, error) {
	cr, err := VerifyRepoCar(r, params)
	if err != nil {
		return nil, err
	}
	out := &VerifiedRepo{Commit: cr.Commit, Index: cr.Index, IndexOrder: cr.IndexOrder, Repo: cr.Repo}
	for {
		rec, err := cr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out.Records = append(out.Records, *rec)
	}
	if !params.IndexOnly && len(out.Records) != len(out.IndexOrder) {
		return nil, verr("car is missing %d record(s) named in the index", len(out.IndexOrder)-len(out.Records))
	}
	return out, nil
}
