package space

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/ipfs/go-cid"
	"golang.org/x/crypto/hkdf"
)

// CommitVersion is the only signed commit version this package understands.
const CommitVersion = 1

// CommitCtx is what a commit signature covers, together with a fresh ikm.
type CommitCtx struct {
	Space  string `json:"space"`
	Author string `json:"author"`
	Rev    string `json:"rev"`
}

// SignedCommit is a space repo commit. The signature covers only the ctx; the
// set hash digest is bound to it by an HMAC keyed from the per-commit ikm, so a
// leaked commit proves nothing to a third party about what the author wrote.
type SignedCommit struct {
	Ver  int64
	Hash []byte
	Ikm  []byte
	Sig  []byte
	Mac  []byte
	Rev  string
}

// RecordRef names a record at a CID.
type RecordRef struct {
	Collection string
	Rkey       string
	Cid        cid.Cid
}

// RepoOp is one oplog entry: a create has no Prev, a delete no Cid, an update
// both.
type RepoOp struct {
	Collection string
	Rkey       string
	Cid        *cid.Cid
	Prev       *cid.Cid
}

// FormatRecordPath is "{collection}/{rkey}".
func FormatRecordPath(collection, rkey string) string { return collection + "/" + rkey }

// FormatSetHashElement is the element a record contributes to its repo's set
// hash: "{collection}/{rkey}/{cid}". It stays injective because the outer two
// fields (an NSID and a base32 CID) never contain a slash.
func FormatSetHashElement(collection, rkey string, c cid.Cid) string {
	return FormatRecordPath(collection, rkey) + "/" + c.String()
}

// RepoCommit tracks a space repo's contents as a set hash.
type RepoCommit struct {
	SetHash *LtHash
}

// NewRepoCommit returns an empty repo.
func NewRepoCommit() *RepoCommit { return &RepoCommit{SetHash: NewLtHash()} }

// RepoCommitFromState resumes from a persisted set hash state (empty for nil).
func RepoCommitFromState(state []byte) (*RepoCommit, error) {
	h, err := LtHashFromState(state)
	if err != nil {
		return nil, err
	}
	return &RepoCommit{SetHash: h}, nil
}

// RepoCommitFromRecords folds in a set of records.
func RepoCommitFromRecords(records []RecordRef) *RepoCommit {
	r := NewRepoCommit()
	for _, rec := range records {
		r.Add(rec.Collection, rec.Rkey, rec.Cid)
	}
	return r
}

// RepoCommitFromIndex folds in every entry of a repo index (path -> CID).
func RepoCommitFromIndex(index map[string]cid.Cid) *RepoCommit {
	r := NewRepoCommit()
	for path, c := range index {
		r.SetHash.Add(path + "/" + c.String())
	}
	return r
}

func (r *RepoCommit) Add(collection, rkey string, c cid.Cid) *RepoCommit {
	r.SetHash.Add(FormatSetHashElement(collection, rkey, c))
	return r
}

func (r *RepoCommit) Remove(collection, rkey string, c cid.Cid) *RepoCommit {
	r.SetHash.Remove(FormatSetHashElement(collection, rkey, c))
	return r
}

func (r *RepoCommit) ApplyOp(op RepoOp) *RepoCommit {
	if op.Prev != nil {
		r.Remove(op.Collection, op.Rkey, *op.Prev)
	}
	if op.Cid != nil {
		r.Add(op.Collection, op.Rkey, *op.Cid)
	}
	return r
}

func (r *RepoCommit) ApplyOps(ops []RepoOp) *RepoCommit {
	for _, op := range ops {
		r.ApplyOp(op)
	}
	return r
}

// Matches reports whether this repo's contents match a commit. Verify the
// commit first: on its own this says nothing about authenticity.
func (r *RepoCommit) Matches(c SignedCommit) bool {
	d := r.SetHash.Digest()
	return hmac.Equal(d[:], c.Hash)
}

// Sign signs a commit over the current contents with a fresh ikm.
func (r *RepoCommit) Sign(ctx CommitCtx, key atcrypto.PrivateKey) (SignedCommit, error) {
	d := r.SetHash.Digest()
	ikm := make([]byte, 32)
	if _, err := rand.Read(ikm); err != nil {
		return SignedCommit{}, err
	}
	ctxBytes := EncodeCommitCtx(ctx, ikm)
	sig, err := key.HashAndSign(ctxBytes)
	if err != nil {
		return SignedCommit{}, err
	}
	return SignedCommit{
		Ver:  CommitVersion,
		Hash: d[:],
		Ikm:  ikm,
		Mac:  computeMac(ikm, ctxBytes, d[:]),
		Sig:  sig,
		Rev:  ctx.Rev,
	}, nil
}

// VerifyCommit checks a commit's signature (authenticity) and MAC (integrity)
// against a did:key.
func VerifyCommit(c SignedCommit, ctx CommitCtx, didKey string) bool {
	if c.Ver != CommitVersion || c.Rev != ctx.Rev {
		return false
	}
	ctxBytes := EncodeCommitCtx(ctx, c.Ikm)
	if !hmac.Equal(computeMac(c.Ikm, ctxBytes, c.Hash), c.Mac) {
		return false
	}
	pub, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return false
	}
	return pub.HashAndVerify(ctxBytes, c.Sig) == nil
}

func computeMac(ikm, ctxBytes, hash []byte) []byte {
	// @atproto/crypto's hkdfSha256 is HKDF-Expand alone, with ikm as the PRK.
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, ikm, ctxBytes), key); err != nil {
		panic(err)
	}
	m := hmac.New(sha256.New, key)
	m.Write(hash)
	return m.Sum(nil)
}

var errCtxField = errors.New("commit ctx field exceeds uint16 length prefix")

// EncodeCommitCtx is
//
//	"atproto-space-v1" || u16be(len(space)) || space || u16be(len(author)) ||
//	author || u16be(len(rev)) || rev || u16be(len(ikm)) || ikm
func EncodeCommitCtx(ctx CommitCtx, ikm []byte) []byte {
	fields := [][]byte{[]byte(ctx.Space), []byte(ctx.Author), []byte(ctx.Rev), ikm}
	out := []byte("atproto-space-v1")
	for _, f := range fields {
		if len(f) > 0xffff {
			panic(errCtxField)
		}
		out = append(out, byte(len(f)>>8), byte(len(f)))
		out = append(out, f...)
	}
	return out
}
