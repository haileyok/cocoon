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
	Space: "at://did:example:space/space/app.bsky.group/test",
	Repo:  "did:example:alice",
	Rev:   "3kbcq3p7ad400",
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

func TestRepoCommitToCommit(t *testing.T) {
	repo := NewRepoCommit().Add("app.bsky.feed.post", "1", cidA)
	c := repo.ToCommit(testCtx)
	d := repo.SetHash.Digest()
	if c.Ver != 1 || c.Repo != testCtx.Repo || c.Space != testCtx.Space || c.Rev != testCtx.Rev || !bytes.Equal(c.Data, d[:]) {
		t.Fatalf("malformed commit %+v", c)
	}
	if !repo.Matches(c) {
		t.Fatal("does not match its own commit")
	}
	advanced, _ := RepoCommitFromState(repo.SetHash.State())
	advanced.Add("app.bsky.feed.post", "2", cidB)
	if advanced.Matches(c) {
		t.Fatal("matches after change")
	}
}

func TestVerifyCommit(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	c := NewRepoCommit().Add("app.bsky.feed.post", "1", cidA).ToCommit(testCtx)
	mac := ComputeCommitMac(secret, c)
	params := VerifyCommitParams{Space: testCtx.Space, Repo: testCtx.Repo, SharedSecret: secret, Mac: mac}
	if !VerifyCommit(c, params) {
		t.Fatal("does not verify its own commit")
	}
	for name, p := range map[string]VerifyCommitParams{
		"other secret": {Space: testCtx.Space, Repo: testCtx.Repo, SharedSecret: bytes.Repeat([]byte{8}, 32), Mac: mac},
		"other space":  {Space: "at://did:example:space/space/app.bsky.group/other", Repo: testCtx.Repo, SharedSecret: secret, Mac: mac},
		"other repo":   {Space: testCtx.Space, Repo: "did:example:bob", SharedSecret: secret, Mac: mac},
		"short mac":    {Space: testCtx.Space, Repo: testCtx.Repo, SharedSecret: secret, Mac: mac[:31]},
	} {
		if VerifyCommit(c, p) {
			t.Fatalf("verified with %s", name)
		}
	}
	for name, mod := range map[string]func(*Commit){
		"future version": func(c *Commit) { c.Ver = 2 },
		"other rev":      func(c *Commit) { c.Rev = "3kbcq3p7ad999" },
		"other data":     func(c *Commit) { d := NewLtHash().Digest(); c.Data = d[:] },
	} {
		tampered := c
		mod(&tampered)
		if VerifyCommit(tampered, params) {
			t.Fatalf("verified with %s", name)
		}
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

func TestCommitVectors(t *testing.T) {
	for i, v := range loadVectors(t).Commits {
		var recs []RecordRef
		for _, r := range v.Records {
			recs = append(recs, RecordRef{r.Collection, r.Rkey, cid.MustParse(r.Cid)})
		}
		repo := RepoCommitFromRecords(recs)
		c := repo.ToCommit(v.Ctx)
		if hex.EncodeToString(c.Data) != v.Data {
			t.Errorf("vector %d data", i)
		}
		secret := unhex(t, v.SharedSecret)
		if got := hex.EncodeToString(ComputeCommitMac(secret, c)); got != v.Mac {
			t.Errorf("vector %d mac %s", i, got)
		}
		if got := FormatMacHeader(CommitMacType, unhex(t, v.Mac)); got != v.MacHeader {
			t.Errorf("vector %d header %s", i, got)
		}
		mac, err := ParseMacHeader([]string{v.MacHeader}, CommitMacType)
		if err != nil || !VerifyCommit(c, VerifyCommitParams{Space: v.Ctx.Space, Repo: v.Ctx.Repo, SharedSecret: secret, Mac: mac}) {
			t.Errorf("vector %d does not verify: %v", i, err)
		}
	}
}
