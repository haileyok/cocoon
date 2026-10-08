package space

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/ipfs/go-cid"
)

// Ported from packages/space/tests/repo-commit.test.ts.

var (
	cidA = cid.MustParse("bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244")
	cidB = cid.MustParse("bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a")
)

var testCtx = CommitCtx{
	Space:  "at://did:example:space/space/app.bsky.group/test",
	Author: "did:example:alice",
	Rev:    "3kbcq3p7ad400",
}

func newK256(t *testing.T) *atcrypto.PrivateKeyK256 {
	t.Helper()
	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func didKeyOf(t *testing.T, k atcrypto.PrivateKey) string {
	t.Helper()
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub.DIDKey()
}

func same(a, b *RepoCommit) bool { return a.SetHash.Equal(b.SetHash) }

func TestRepoCommitContents(t *testing.T) {
	if !NewRepoCommit().SetHash.IsEmpty() || len(NewRepoCommit().SetHash.State()) != LtHashStateBytes {
		t.Fatal("does not start empty")
	}
	r := NewRepoCommit().Add("n.c.a", "1", cidA)
	if r.SetHash.IsEmpty() {
		t.Fatal("add left it empty")
	}
	r.Remove("n.c.a", "1", cidA)
	if !r.SetHash.IsEmpty() {
		t.Fatal("remove did not return to empty")
	}
	a := NewRepoCommit().Add("n.c.a", "1", cidA).Add("n.c.b", "2", cidB)
	b := NewRepoCommit().Add("n.c.b", "2", cidB).Add("n.c.a", "1", cidA)
	if !same(a, b) {
		t.Fatal("order dependent")
	}
	if same(NewRepoCommit().Add("n.c.a", "1", cidA), NewRepoCommit().Add("n.c.a", "2", cidA)) {
		t.Fatal("same cid, different paths collide")
	}
	if same(NewRepoCommit().Add("n.c.a", "1", cidA), NewRepoCommit().Add("n.c.a", "1", cidB)) {
		t.Fatal("same path, different cids collide")
	}
	resumed, err := RepoCommitFromState(a.SetHash.State())
	if err != nil || !same(resumed, a) {
		t.Fatal("state round trip")
	}
	empty, _ := RepoCommitFromState(nil)
	if !empty.SetHash.IsEmpty() {
		t.Fatal("nil state not empty")
	}
	recs := []RecordRef{{"n.c.a", "1", cidA}, {"n.c.b", "2", cidB}}
	if !same(RepoCommitFromRecords(recs), a) {
		t.Fatal("fromRecords != incremental")
	}
}

func TestRepoCommitApplyOp(t *testing.T) {
	if !same(NewRepoCommit().ApplyOp(RepoOp{Collection: "n.c.a", Rkey: "1", Cid: &cidA}), NewRepoCommit().Add("n.c.a", "1", cidA)) {
		t.Fatal("null prev is not a create")
	}
	r := NewRepoCommit().Add("n.c.a", "1", cidA)
	r.ApplyOp(RepoOp{Collection: "n.c.a", Rkey: "1", Prev: &cidA})
	if !r.SetHash.IsEmpty() {
		t.Fatal("null cid is not a delete")
	}
	r = NewRepoCommit().Add("n.c.a", "1", cidA)
	r.ApplyOp(RepoOp{Collection: "n.c.a", Rkey: "1", Cid: &cidB, Prev: &cidA})
	if !same(r, NewRepoCommit().Add("n.c.a", "1", cidB)) {
		t.Fatal("update did not swap")
	}
	r = NewRepoCommit().ApplyOps([]RepoOp{
		{Collection: "n.c.a", Rkey: "1", Cid: &cidA},
		{Collection: "n.c.a", Rkey: "1", Cid: &cidB, Prev: &cidA},
		{Collection: "n.c.a", Rkey: "1", Prev: &cidB},
	})
	if !r.SetHash.IsEmpty() {
		t.Fatal("batch replay")
	}
	ops := []RepoOp{{Collection: "n.c.a", Rkey: "1", Cid: &cidA}, {Collection: "n.c.b", Rkey: "2", Cid: &cidB}}
	if !same(NewRepoCommit().ApplyOps(ops), NewRepoCommit().ApplyOps([]RepoOp{ops[1], ops[0]})) {
		t.Fatal("op order matters")
	}
}

func TestRepoCommitSigning(t *testing.T) {
	key := newK256(t)
	didKey := didKeyOf(t, key)
	repo := NewRepoCommit().Add("app.bsky.feed.post", "1", cidA)

	c, err := repo.Sign(testCtx, key)
	if err != nil {
		t.Fatal(err)
	}
	d := repo.SetHash.Digest()
	if c.Ver != 1 || c.Rev != testCtx.Rev || !bytes.Equal(c.Hash, d[:]) || len(c.Ikm) != 32 || len(c.Mac) != 32 || len(c.Sig) == 0 {
		t.Fatalf("malformed commit %+v", c)
	}
	if !VerifyCommit(c, testCtx, didKey) || !repo.Matches(c) {
		t.Fatal("does not verify its own commit")
	}

	c2, _ := repo.Sign(testCtx, key)
	if bytes.Equal(c.Ikm, c2.Ikm) || bytes.Equal(c.Mac, c2.Mac) || bytes.Equal(c.Sig, c2.Sig) || !bytes.Equal(c.Hash, c2.Hash) {
		t.Fatal("ikm is not fresh per commit")
	}

	if VerifyCommit(c, testCtx, didKeyOf(t, newK256(t))) {
		t.Fatal("verified under another key")
	}
	for _, other := range []CommitCtx{
		{Space: "at://did:example:space/space/app.bsky.group/other", Author: testCtx.Author, Rev: testCtx.Rev},
		{Space: testCtx.Space, Author: "did:example:bob", Rev: testCtx.Rev},
		{Space: testCtx.Space, Author: testCtx.Author, Rev: "3kbcq3p7ad999"},
	} {
		if VerifyCommit(c, other, didKey) {
			t.Fatalf("verified under %+v", other)
		}
	}
	empty := NewRepoCommit().SetHash.Digest()
	tampered := c
	tampered.Hash = empty[:]
	if VerifyCommit(tampered, testCtx, didKey) {
		t.Fatal("tampered hash verified")
	}
	badRev := c
	badRev.Rev = "3kbcq3p7ad999"
	if VerifyCommit(badRev, testCtx, didKey) {
		t.Fatal("rev mismatch verified")
	}
	future := c
	future.Ver = 2
	if VerifyCommit(future, testCtx, didKey) {
		t.Fatal("future version verified")
	}
	advanced, _ := RepoCommitFromState(repo.SetHash.State())
	advanced.Add("app.bsky.feed.post", "2", cidB)
	if advanced.Matches(c) {
		t.Fatal("matches after change")
	}
}

func TestFormatSetHashElement(t *testing.T) {
	if FormatSetHashElement("n.c.a", "1", cidA) != "n.c.a/1/"+cidA.String() {
		t.Fatal("format")
	}
	if FormatSetHashElement("n.c.a", "b/1", cidA) == FormatSetHashElement("n.c.a", "b/2", cidA) {
		t.Fatal("rkey boundary ambiguous")
	}
}

func TestEncodeCommitCtx(t *testing.T) {
	ikm := bytes.Repeat([]byte{7}, 32)
	enc := EncodeCommitCtx(testCtx, ikm)
	if string(enc[:16]) != "atproto-space-v1" || int(enc[16])<<8|int(enc[17]) != len(testCtx.Space) {
		t.Fatal("prefix")
	}
	if bytes.Equal(EncodeCommitCtx(CommitCtx{"ab", "c", "d"}, ikm), EncodeCommitCtx(CommitCtx{"a", "bc", "d"}, ikm)) {
		t.Fatal("ambiguous")
	}
	if !bytes.Equal(enc, EncodeCommitCtx(testCtx, ikm)) {
		t.Fatal("non-deterministic")
	}
}

func TestCommitVectors(t *testing.T) {
	for i, v := range loadVectors(t).Commits {
		var recs []RecordRef
		for _, r := range v.Records {
			c := cid.MustParse(r.Cid)
			if FormatSetHashElement(r.Collection, r.Rkey, c) != r.Element {
				t.Errorf("vector %d element", i)
			}
			recs = append(recs, RecordRef{r.Collection, r.Rkey, c})
		}
		repo := RepoCommitFromRecords(recs)
		d := repo.SetHash.Digest()
		if hex.EncodeToString(d[:]) != v.Hash {
			t.Errorf("vector %d hash", i)
		}
		ikm := unhex(t, v.Ikm)
		if hex.EncodeToString(EncodeCommitCtx(v.Ctx, ikm)) != v.CtxBytes {
			t.Errorf("vector %d ctxBytes", i)
		}
		c := SignedCommit{Ver: 1, Hash: d[:], Ikm: ikm, Mac: unhex(t, v.Mac), Sig: unhex(t, v.Sig), Rev: v.Ctx.Rev}
		if !VerifyCommit(c, v.Ctx, v.DidKey) {
			t.Errorf("vector %d does not verify", i)
		}
		if !repo.Matches(c) {
			t.Errorf("vector %d does not match", i)
		}
	}
}
