package space

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	cid "github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	car "github.com/ipld/go-car"
	carutil "github.com/ipld/go-car/util"
	"github.com/multiformats/go-multihash"
)

// RepoIndex maps collection/rkey paths to record CIDs.
type RepoIndex map[string]cid.Cid

// SerializedRecord is one record block to be placed after the two CAR roots.
type SerializedRecord struct {
	Collection string
	RKey       string
	// Rkey is accepted as a compatibility spelling; RKey takes precedence.
	Rkey  string
	CID   cid.Cid
	Bytes []byte
}

// SerializeRepoOptions controls CAR serialization.
type SerializeRepoOptions struct {
	ExcludeValues bool
}

type CAROptions = SerializeRepoOptions

// VerifyRepoParams are the context values and public key needed to verify a
// repo CAR. ExpectValues may be bool, *bool, or nil: nil defaults to true,
// matching the reference verifier's optional expectValues parameter. A false
// value verifies an index-only CAR produced with ExcludeValues.
type VerifyRepoParams struct {
	Space        string
	Author       string
	DIDKey       string
	ExpectValues interface{}
}

// VerifiedRecord is a value block proven to match its index path and CID.
type VerifiedRecord struct {
	Collection string
	RKey       string
	CID        cid.Cid
	Bytes      []byte
}

// VerifiedRepo is the result of VerifyRepoCAR.
type VerifiedRepo struct {
	Roots   []cid.Cid
	Commit  SignedCommit
	Index   RepoIndex
	Records []VerifiedRecord
	Repo    *RepoCommit
}

var dagCBORPrefix = cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)

// CIDForCBOR computes the CID used for commit, index, and canonical DAG-CBOR
// record blocks.
func CIDForCBOR(data []byte) (cid.Cid, error) {
	return dagCBORPrefix.Sum(data)
}

// SerializeRecord canonicalizes a Go value as DAG-CBOR and computes its CID.
func SerializeRecord(collection, rkey string, record interface{}) (SerializedRecord, error) {
	if err := validateRecordPath(collection, rkey); err != nil {
		return SerializedRecord{}, err
	}
	data, err := cbor.Encode(record)
	if err != nil {
		return SerializedRecord{}, fmt.Errorf("encode record: %w", err)
	}
	recordCID, err := CIDForCBOR(data)
	if err != nil {
		return SerializedRecord{}, err
	}
	return SerializedRecord{Collection: collection, RKey: rkey, CID: recordCID, Bytes: data}, nil
}

// NewSerializedRecord is an alias for SerializeRecord.
func NewSerializedRecord(collection, rkey string, record interface{}) (SerializedRecord, error) {
	return SerializeRecord(collection, rkey, record)
}

// SerializeRecordBytes constructs a record from already canonical bytes. A
// supplied CID is checked against those bytes; an undefined CID is computed.
func SerializeRecordBytes(collection, rkey string, recordCID cid.Cid, data []byte) (SerializedRecord, error) {
	if err := validateRecordPath(collection, rkey); err != nil {
		return SerializedRecord{}, err
	}
	computed, err := CIDForCBOR(data)
	if err != nil {
		return SerializedRecord{}, err
	}
	if recordCID.Defined() && !recordCID.Equals(computed) {
		return SerializedRecord{}, fmt.Errorf("record CID %s does not match bytes CID %s", recordCID, computed)
	}
	if !recordCID.Defined() {
		recordCID = computed
	}
	return SerializedRecord{Collection: collection, RKey: rkey, CID: recordCID, Bytes: append([]byte(nil), data...)}, nil
}

// SerializeRepo emits a CAR whose roots are [signedCommit, index], followed by
// commit/index blocks and then one value block per index entry in canonical
// path order. Duplicate paths follow the reference provider's last-write-wins
// behavior. ExcludeValues emits only the two roots' blocks.
func SerializeRepo(commit SignedCommit, records []SerializedRecord, opts ...SerializeRepoOptions) ([]byte, error) {
	if err := commit.Validate(); err != nil {
		return nil, err
	}
	if len(opts) > 1 {
		return nil, errors.New("at most one CAR options value is allowed")
	}
	var options SerializeRepoOptions
	if len(opts) == 1 {
		options = opts[0]
	}
	byPath := make(map[string]SerializedRecord, len(records))
	for _, record := range records {
		rkey := record.RKey
		if rkey == "" {
			rkey = record.Rkey
		}
		if err := validateRecordPath(record.Collection, rkey); err != nil {
			return nil, err
		}
		if len(record.Bytes) == 0 {
			return nil, fmt.Errorf("record %s/%s has empty bytes", record.Collection, rkey)
		}
		computed, err := CIDForCBOR(record.Bytes)
		if err != nil {
			return nil, err
		}
		if !record.CID.Defined() {
			record.CID = computed
		} else if !record.CID.Equals(computed) {
			return nil, fmt.Errorf("record %s/%s CID does not match bytes", record.Collection, rkey)
		}
		record.RKey = rkey
		byPath[record.Collection+"/"+rkey] = record
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sortCanonicalPaths(paths)
	index := make(RepoIndex, len(paths))
	for _, path := range paths {
		index[path] = byPath[path].CID
	}
	commitBytes, err := EncodeSignedCommit(commit)
	if err != nil {
		return nil, err
	}
	indexBytes, err := EncodeRepoIndex(index)
	if err != nil {
		return nil, err
	}
	commitCID, err := CIDForCBOR(commitBytes)
	if err != nil {
		return nil, err
	}
	indexCID, err := CIDForCBOR(indexBytes)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := car.WriteHeader(&car.CarHeader{Roots: []cid.Cid{commitCID, indexCID}, Version: 1}, buf); err != nil {
		return nil, fmt.Errorf("write CAR header: %w", err)
	}
	if err := carutil.LdWrite(buf, commitCID.Bytes(), commitBytes); err != nil {
		return nil, err
	}
	if err := carutil.LdWrite(buf, indexCID.Bytes(), indexBytes); err != nil {
		return nil, err
	}
	if !options.ExcludeValues {
		for _, path := range paths {
			record := byPath[path]
			if err := carutil.LdWrite(buf, record.CID.Bytes(), record.Bytes); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

func SerializeRepoCAR(commit SignedCommit, records []SerializedRecord, opts ...SerializeRepoOptions) ([]byte, error) {
	return SerializeRepo(commit, records, opts...)
}

// WriteRepoCAR is the streaming form of SerializeRepo.
func WriteRepoCAR(w io.Writer, commit SignedCommit, records []SerializedRecord, opts ...SerializeRepoOptions) error {
	data, err := SerializeRepo(commit, records, opts...)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// EncodeRepoIndex returns canonical DAG-CBOR bytes for an index. The CBOR
// encoder emits CID values as IPLD link tag 42 and sorts text keys by the
// canonical shortest-then-bytewise order.
func EncodeRepoIndex(index RepoIndex) ([]byte, error) {
	for path, recordCID := range index {
		if err := validatePath(path); err != nil {
			return nil, err
		}
		if !recordCID.Defined() {
			return nil, fmt.Errorf("index path %q has undefined CID", path)
		}
	}
	return cbor.Encode(map[string]cid.Cid(index))
}

// DecodeRepoIndex parses a canonical DAG-CBOR index.
func DecodeRepoIndex(data []byte) (RepoIndex, error) {
	var index map[string]cid.Cid
	if err := cbor.DecodeInto(data, &index); err != nil {
		return nil, fmt.Errorf("decode repo index: %w", err)
	}
	for path, recordCID := range index {
		if err := validatePath(path); err != nil {
			return nil, err
		}
		if !recordCID.Defined() {
			return nil, fmt.Errorf("index path %q has undefined CID", path)
		}
	}
	canonical, err := EncodeRepoIndex(RepoIndex(index))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("repo index is not canonical DAG-CBOR")
	}
	return RepoIndex(index), nil
}

// RepoCommitFromIndex computes the LtHash represented by every index path/CID.
func RepoCommitFromIndex(index RepoIndex) (*RepoCommit, error) {
	commit := NewRepoCommit()
	for path, recordCID := range index {
		collection, rkey, err := splitPath(path)
		if err != nil {
			return nil, err
		}
		commit.Add(collection, rkey, recordCID)
	}
	return commit, nil
}

// RepoCommitFromRecords computes a set hash from serialized records.
func RepoCommitFromRecords(records []SerializedRecord) (*RepoCommit, error) {
	commit := NewRepoCommit()
	for _, record := range records {
		rkey := record.RKey
		if rkey == "" {
			rkey = record.Rkey
		}
		if err := validateRecordPath(record.Collection, rkey); err != nil {
			return nil, err
		}
		if !record.CID.Defined() {
			return nil, fmt.Errorf("record %s/%s has undefined CID", record.Collection, rkey)
		}
		commit.Add(record.Collection, rkey, record.CID)
	}
	return commit, nil
}

// VerifyRepoCAR verifies roots, block CIDs, commit signature/MAC, index hash,
// and (when ExpectValues is true) every value block in index order.
func VerifyRepoCAR(data []byte, params VerifyRepoParams) (VerifiedRepo, error) {
	expectValues, err := expectedValues(params.ExpectValues)
	if err != nil {
		return VerifiedRepo{}, err
	}
	reader, err := car.NewCarReader(bytes.NewReader(data))
	if err != nil {
		return VerifiedRepo{}, fmt.Errorf("read CAR header: %w", err)
	}
	if reader.Header.Version != 1 {
		return VerifiedRepo{}, fmt.Errorf("unsupported CAR version %d", reader.Header.Version)
	}
	if len(reader.Header.Roots) != 2 {
		return VerifiedRepo{}, fmt.Errorf("expected 2 CAR roots (commit, index), got %d", len(reader.Header.Roots))
	}
	roots := append([]cid.Cid(nil), reader.Header.Roots...)
	commitBlock, err := reader.Next()
	if err != nil {
		return VerifiedRepo{}, fmt.Errorf("read commit block: %w", err)
	}
	if !commitBlock.Cid().Equals(roots[0]) {
		return VerifiedRepo{}, errors.New("expected commit block to lead the CAR")
	}
	commit, err := DecodeSignedCommit(commitBlock.RawData())
	if err != nil {
		return VerifiedRepo{}, err
	}
	ctx := CommitContext{Space: params.Space, Author: params.Author, Rev: commit.Rev}
	if err := VerifyCommitError(commit, ctx, params.DIDKey); err != nil {
		return VerifiedRepo{}, fmt.Errorf("commit failed verification: %w", err)
	}

	indexBlock, err := reader.Next()
	if err != nil {
		return VerifiedRepo{}, fmt.Errorf("read index block: %w", err)
	}
	if !indexBlock.Cid().Equals(roots[1]) {
		return VerifiedRepo{}, errors.New("expected index block to follow commit")
	}
	index, err := DecodeRepoIndex(indexBlock.RawData())
	if err != nil {
		return VerifiedRepo{}, err
	}
	repo, err := RepoCommitFromIndex(index)
	if err != nil {
		return VerifiedRepo{}, err
	}
	if !repo.Matches(commit) {
		return VerifiedRepo{}, errors.New("index does not match commit hash")
	}

	paths := make([]string, 0, len(index))
	for path := range index {
		paths = append(paths, path)
	}
	sortCanonicalPaths(paths)
	verified := make([]VerifiedRecord, 0, len(paths))
	if !expectValues {
		if _, err := reader.Next(); !errors.Is(err, io.EOF) {
			if err == nil {
				return VerifiedRepo{}, errors.New("index-only CAR contains value blocks")
			}
			return VerifiedRepo{}, fmt.Errorf("read index-only CAR: %w", err)
		}
		return VerifiedRepo{Roots: roots, Commit: commit, Index: index, Records: verified, Repo: repo}, nil
	}
	for _, path := range paths {
		block, nextErr := reader.Next()
		if nextErr != nil {
			return VerifiedRepo{}, fmt.Errorf("CAR is missing value for %s: %w", path, nextErr)
		}
		if !block.Cid().Equals(index[path]) {
			return VerifiedRepo{}, fmt.Errorf("value block CID mismatch at %s", path)
		}
		collection, rkey, err := splitPath(path)
		if err != nil {
			return VerifiedRepo{}, err
		}
		var value interface{}
		if err := cbor.DecodeInto(block.RawData(), &value); err != nil {
			return VerifiedRepo{}, fmt.Errorf("decode value at %s: %w", path, err)
		}
		verified = append(verified, VerifiedRecord{Collection: collection, RKey: rkey, CID: block.Cid(), Bytes: append([]byte(nil), block.RawData()...)})
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			return VerifiedRepo{}, errors.New("CAR has more value blocks than index entries")
		}
		return VerifiedRepo{}, fmt.Errorf("read CAR trailer: %w", err)
	}
	return VerifiedRepo{Roots: roots, Commit: commit, Index: index, Records: verified, Repo: repo}, nil
}

func VerifyRepoCar(data []byte, params VerifyRepoParams) (VerifiedRepo, error) {
	return VerifyRepoCAR(data, params)
}

// ParseRepoCAR is a descriptive alias for VerifyRepoCAR.
func ParseRepoCAR(data []byte, params VerifyRepoParams) (VerifiedRepo, error) {
	return VerifyRepoCAR(data, params)
}

func VerifyRepoCARFull(data []byte, params VerifyRepoParams) (VerifiedRepo, error) {
	return VerifyRepoCAR(data, params)
}

func expectedValues(value interface{}) (bool, error) {
	switch value := value.(type) {
	case nil:
		return true, nil
	case bool:
		return value, nil
	case *bool:
		if value == nil {
			return true, nil
		}
		return *value, nil
	default:
		return false, fmt.Errorf("ExpectValues must be bool, *bool, or nil")
	}
}

func sortCanonicalPaths(paths []string) {
	sort.Slice(paths, func(i, j int) bool {
		a, b := []byte(paths[i]), []byte(paths[j])
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return bytes.Compare(a, b) < 0
	})
}

func validateRecordPath(collection, rkey string) error {
	if collection == "" || rkey == "" || strings.ContainsAny(collection, "/\x00") || strings.ContainsAny(rkey, "/\x00") {
		return fmt.Errorf("invalid record path %q/%q", collection, rkey)
	}
	return nil
}

func validatePath(path string) error {
	_, _, err := splitPath(path)
	return err
}

func splitPath(path string) (string, string, error) {
	if strings.Count(path, "/") != 1 {
		return "", "", fmt.Errorf("invalid repo index path %q", path)
	}
	parts := strings.SplitN(path, "/", 2)
	if err := validateRecordPath(parts[0], parts[1]); err != nil {
		return "", "", err
	}
	return parts[0], parts[1], nil
}
