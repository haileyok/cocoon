package space

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// Space repos serialized as STAR archives with the atproto-space-repo
// profile: the commit as the metadata, then one path/record pair per record
// in strict path order. Follows @atproto/space's sync/provider.ts and
// sync/consumer.ts.

// RepoStarType is the $type of a space repo archive's metadata.
const RepoStarType = "atproto-space-repo"

// RepoStarLimits are the lengths a repo archive reader accepts: 64 KiB of
// metadata, 4 KiB keys and records up to MaxRecordSize.
var RepoStarLimits = StarLimits{MaxMetaLen: 64 * 1024, MaxKeyLen: 4 * 1024, MaxValueLen: MaxRecordSize}

// RepoVerificationError is a space repo or record that does not verify.
type RepoVerificationError struct{ Message string }

func (e *RepoVerificationError) Error() string { return e.Message }

func verr(format string, args ...any) error {
	return &RepoVerificationError{Message: fmt.Sprintf(format, args...)}
}

var cborPrefix = cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)

// CidForCBOR is the CID of DRISL-encoded bytes.
func CidForCBOR(b []byte) cid.Cid { return cidForCBOR(b) }

func cidForCBOR(b []byte) cid.Cid {
	c, err := cborPrefix.Sum(b)
	if err != nil {
		panic(err)
	}
	return c
}

// SerializedRecord is a record's DRISL encoding.
type SerializedRecord struct {
	Collection string
	Rkey       string
	Cid        cid.Cid
	Bytes      []byte
}

// SerializeRecord encodes a record (atproto data model) as DRISL.
func SerializeRecord(collection, rkey string, record map[string]any) (SerializedRecord, error) {
	b, err := atdata.MarshalCBOR(record)
	if err != nil {
		return SerializedRecord{}, err
	}
	return SerializedRecord{Collection: collection, Rkey: rkey, Cid: cidForCBOR(b), Bytes: b}, nil
}

// RepoStarMeta is a commit as a repo archive's metadata.
func RepoStarMeta(c Commit) map[string]any {
	return map[string]any{
		"$type": RepoStarType,
		"ver":   c.Ver,
		"repo":  c.Repo,
		"space": c.Space,
		"rev":   c.Rev,
		"data":  atdata.Bytes(c.Data),
	}
}

// ParseRepoStarMeta reads a commit from a repo archive's metadata.
func ParseRepoStarMeta(m map[string]any) (Commit, error) {
	var c Commit
	if m["$type"] != RepoStarType {
		return c, errors.New("$type: expected " + RepoStarType)
	}
	ver, ok := m["ver"].(int64)
	if !ok {
		return c, errors.New("ver: expected an integer")
	}
	c.Ver = ver
	if c.Repo, ok = m["repo"].(string); !ok {
		return c, errors.New("repo: expected a DID")
	}
	if _, err := syntax.ParseDID(c.Repo); err != nil {
		return c, errors.New("repo: expected a DID")
	}
	if c.Space, ok = m["space"].(string); !ok {
		return c, errors.New("space: expected a space reference")
	}
	if _, err := ParseRef(c.Space); err != nil {
		return c, errors.New("space: expected a space reference")
	}
	if c.Rev, ok = m["rev"].(string); !ok {
		return c, errors.New("rev: expected a TID")
	}
	if _, err := syntax.ParseTID(c.Rev); err != nil {
		return c, errors.New("rev: expected a TID")
	}
	data, ok := m["data"].(atdata.Bytes)
	if !ok {
		return c, errors.New("data: expected bytes")
	}
	c.Data = []byte(data)
	return c, nil
}

// SerializeRepo writes a space repo archive. Records must be in strict path
// order, as the archive requires; it fails at the first that isn't.
func SerializeRepo(w io.Writer, commit Commit, records []SerializedRecord) error {
	sw, err := WriteStar(w, RepoStarMeta(commit))
	if err != nil {
		return err
	}
	var prev []byte
	for _, r := range records {
		key := []byte(FormatRecordPath(r.Collection, r.Rkey))
		if prev != nil && bytes.Compare(key, prev) <= 0 {
			return fmt.Errorf("records out of order at %s", key)
		}
		prev = key
		if err := sw.WritePair(key, r.Bytes); err != nil {
			return err
		}
	}
	return sw.Close()
}

// VerifyRepoParams is VerifyCommitParams for a repo archive.
type VerifyRepoParams = VerifyCommitParams

type VerifiedRecord struct {
	Collection string
	Rkey       string
	Cid        cid.Cid
	Record     map[string]any
}

// RepoStarReader is an archive whose commit has verified against the
// response's MAC. Next streams its records, folding each into a running set
// hash, and only the io.EOF that ends a fully read archive shows the records
// match the commit, so drain it before trusting what it returned.
type RepoStarReader struct {
	Commit Commit

	sr   *StarReader
	repo *RepoCommit
	prev []byte
	done bool
}

// ReadRepoStar reads an archive without authenticating its commit. The
// records are checked against the commit's data as Next drains the reader, but
// nothing vouches for the commit itself. This suits a repo host importing an
// account's own repo, which comes with no MAC to check.
func ReadRepoStar(r io.Reader) (*RepoStarReader, error) {
	sr, err := ReadStar(r, RepoStarLimits)
	if err != nil {
		return nil, err
	}
	commit, err := ParseRepoStarMeta(sr.Meta)
	if err != nil {
		return nil, verr("invalid repo metadata: %v", err)
	}
	if commit.Ver != CommitVersion {
		return nil, verr("unsupported commit version: %d", commit.Ver)
	}
	return &RepoStarReader{Commit: commit, sr: sr, repo: NewRepoCommit()}, nil
}

// VerifyRepoStar verifies an archive's commit against the response's MAC and
// returns a reader for its records.
func VerifyRepoStar(r io.Reader, params VerifyRepoParams) (*RepoStarReader, error) {
	rr, err := ReadRepoStar(r)
	if err != nil {
		return nil, err
	}
	if err := VerifyCommit(rr.Commit, params); err != nil {
		return nil, err
	}
	return rr, nil
}

// Next returns the next record, or io.EOF once the archive has ended and its
// records match the commit.
func (r *RepoStarReader) Next() (*VerifiedRecord, error) {
	if r.done {
		return nil, io.EOF
	}
	key, value, err := r.sr.Next()
	if err == io.EOF {
		r.done = true
		if !r.repo.Matches(r.Commit) {
			return nil, verr("records do not match the commit data")
		}
		return nil, io.EOF
	}
	if err != nil {
		return nil, err
	}
	path := string(key)
	collection, rkey, err := ParseRecordPath(path)
	if err != nil {
		return nil, err
	}
	if r.prev != nil && bytes.Compare(key, r.prev) <= 0 {
		return nil, verr("records out of order at %s", path)
	}
	r.prev = key
	rec, err := atdata.UnmarshalCBOR(value)
	if err != nil {
		return nil, verr("invalid record cbor at %s", path)
	}
	c := cidForCBOR(value)
	r.repo.Add(collection, rkey, c)
	return &VerifiedRecord{Collection: collection, Rkey: rkey, Cid: c, Record: rec}, nil
}

// VerifiedRepo is a fully read and verified repo archive.
type VerifiedRepo struct {
	Commit  Commit
	Records []VerifiedRecord
}

// VerifyRepoStarFull verifies an archive and collects its records.
func VerifyRepoStarFull(r io.Reader, params VerifyRepoParams) (*VerifiedRepo, error) {
	rr, err := VerifyRepoStar(r, params)
	if err != nil {
		return nil, err
	}
	out := &VerifiedRepo{Commit: rr.Commit}
	for {
		rec, err := rr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out.Records = append(out.Records, *rec)
	}
}

// ParseRecordPath splits "{collection}/{rkey}".
func ParseRecordPath(p string) (string, string, error) {
	parts := strings.Split(p, "/")
	if len(parts) != 2 {
		return "", "", verr("invalid record path: %s", p)
	}
	if _, err := syntax.ParseNSID(parts[0]); err != nil {
		return "", "", verr("invalid record path: %s", p)
	}
	if _, err := syntax.ParseRecordKey(parts[1]); err != nil {
		return "", "", verr("invalid record path: %s", p)
	}
	return parts[0], parts[1], nil
}

// VerifyRecordParams names the record that was requested, with the request's
// encapsulation and the response's headers.
type VerifyRecordParams struct {
	URI string
	VerifyMacParams
}

// VerifyRecord checks a getRecord response against the MAC it carried: it
// must be the record requested, the MAC must cover its uri and cid, and its
// value must encode to that cid.
func VerifyRecord(uri, cidStr string, value map[string]any, p VerifyRecordParams) error {
	if uri != p.URI {
		return verr("record is not the one requested: %s", uri)
	}
	c, err := cid.Decode(cidStr)
	if err != nil {
		return verr("invalid record cid: %s", cidStr)
	}
	if err := VerifyRecordMac(uri, c, p.VerifyMacParams); err != nil {
		return err
	}
	b, err := atdata.MarshalCBOR(value)
	if err != nil {
		return verr("record value does not match its cid")
	}
	if !cidForCBOR(b).Equals(c) {
		return verr("record value does not match its cid")
	}
	return nil
}
