package space

import (
	"crypto/hmac"

	"github.com/ipfs/go-cid"
)

// CommitVersion is the only commit version this package understands.
const CommitVersion = 1

// MaxRecordSize is the largest DRISL encoding a space record may have.
const MaxRecordSize = 1024 * 1024

// CommitCtx is which repo, in which space, at which revision a commit
// describes.
type CommitCtx struct {
	Space string `json:"space"`
	Repo  string `json:"repo"`
	Rev   string `json:"rev"`
}

// Commit is a space repo commit (com.atproto.space.defs#commit). It carries
// no signature: the repo host authenticates it to each syncer with a MAC in
// the Atproto-Space-Mac response header, so a leaked commit proves nothing to
// a third party about what the author wrote.
type Commit struct {
	Ver   int64
	Repo  string
	Space string
	Rev   string
	// Data is the sha256 digest of the repo's LtHash state.
	Data []byte
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
func (r *RepoCommit) Matches(c Commit) bool {
	d := r.SetHash.Digest()
	return hmac.Equal(d[:], c.Data)
}

// ToCommit builds a commit over the current contents.
func (r *RepoCommit) ToCommit(ctx CommitCtx) Commit {
	d := r.SetHash.Digest()
	return Commit{Ver: CommitVersion, Repo: ctx.Repo, Space: ctx.Space, Rev: ctx.Rev, Data: d[:]}
}

// VerifyCommitParams names the space and repo that were requested, with the
// request's shared secret and the MAC from its response header.
type VerifyCommitParams struct {
	Space        string
	Repo         string
	SharedSecret []byte
	Mac          []byte
}

// VerifyCommit checks a commit against the MAC its response carried. Once it
// passes, Data is trusted as the author's claim about their repo, which is
// what makes Matches meaningful.
func VerifyCommit(c Commit, p VerifyCommitParams) bool {
	if c.Ver != CommitVersion || c.Repo != p.Repo || c.Space != p.Space {
		return false
	}
	return VerifyCommitMac(p.SharedSecret, c, p.Mac)
}
