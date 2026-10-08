package space

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	car "github.com/ipld/go-car"
	carutil "github.com/ipld/go-car/util"
)

// Ported from packages/space/tests/sync.test.ts.

const (
	carSpace  = "at://did:example:space/space/app.bsky.group/test"
	carAuthor = "did:example:alice"
)

func carRecords(t *testing.T) []SerializedRecord {
	t.Helper()
	var out []SerializedRecord
	for _, r := range []struct {
		c, k string
		v    map[string]any
	}{
		{"app.bsky.feed.post", "3kbcq3p7ad401", map[string]any{"text": "hello"}},
		{"app.bsky.feed.post", "3kbcq3p7ad402", map[string]any{"text": "world"}},
		{"app.bsky.feed.like", "3kbcq3p7ad403", map[string]any{"subject": "at://x"}},
	} {
		sr, err := SerializeRecord(r.c, r.k, r.v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sr)
	}
	return out
}

func refsOf(recs []SerializedRecord) []RecordRef {
	var out []RecordRef
	for _, r := range recs {
		out = append(out, RecordRef{r.Collection, r.Rkey, r.Cid})
	}
	return out
}

type carFixture struct {
	key  *atcrypto.PrivateKeyK256
	recs []SerializedRecord
	ctx  CommitCtx
}

func newCarFixture(t *testing.T) *carFixture {
	return &carFixture{key: newK256(t), recs: carRecords(t), ctx: CommitCtx{Space: carSpace, Author: carAuthor, Rev: "3kbcq3p7ad400"}}
}

func (f *carFixture) commitFor(t *testing.T, recs []SerializedRecord) SignedCommit {
	c, err := RepoCommitFromRecords(refsOf(recs)).Sign(f.ctx, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *carFixture) car(t *testing.T, recs []SerializedRecord) []byte {
	var buf bytes.Buffer
	if err := SerializeRepo(&buf, f.commitFor(t, recs), recs, false); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (f *carFixture) params(t *testing.T) VerifyRepoParams {
	return VerifyRepoParams{Space: carSpace, Author: carAuthor, DidKey: didKeyOf(t, f.key)}
}

func readBlocks(t *testing.T, b []byte) ([]cid.Cid, []cid.Cid, [][]byte) {
	t.Helper()
	br := bufio.NewReader(bytes.NewReader(b))
	h, err := car.ReadHeader(br)
	if err != nil {
		t.Fatal(err)
	}
	var cids []cid.Cid
	var datas [][]byte
	for {
		c, d, err := carutil.ReadNode(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		cids = append(cids, c)
		datas = append(datas, d)
	}
	return h.Roots, cids, datas
}

func rawCar(t *testing.T, roots []cid.Cid, blocks ...[2][]byte) []byte {
	var buf bytes.Buffer
	if err := car.WriteHeader(&car.CarHeader{Roots: roots, Version: 1}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		if err := carutil.LdWrite(&buf, b[0], b[1]); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestRepoCarLayoutAndRoundTrip(t *testing.T) {
	f := newCarFixture(t)
	b := f.car(t, f.recs)
	roots, cids, _ := readBlocks(t, b)
	if len(roots) != 2 || len(cids) != 2+len(f.recs) || !cids[0].Equals(roots[0]) || !cids[1].Equals(roots[1]) {
		t.Fatal("layout")
	}

	repo, err := VerifyRepoCarFull(bytes.NewReader(b), f.params(t))
	if err != nil {
		t.Fatal(err)
	}
	if repo.Commit.Rev != f.ctx.Rev || len(repo.Index) != 3 || len(repo.Records) != 3 || !repo.Repo.Matches(repo.Commit) {
		t.Fatal("round trip")
	}
	for _, o := range f.recs {
		found := false
		for _, r := range repo.Records {
			if r.Collection == o.Collection && r.Rkey == o.Rkey && r.Cid.Equals(o.Cid) {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s/%s", o.Collection, o.Rkey)
		}
	}
	for _, r := range repo.Records {
		if r.Rkey == "3kbcq3p7ad401" && r.Record["text"] != "hello" {
			t.Fatalf("value %v", r.Record)
		}
	}
	// blocks follow the index order
	var idx []string
	for _, p := range repo.IndexOrder {
		idx = append(idx, repo.Index[p].String())
	}
	var got []string
	for _, c := range cids[2:] {
		got = append(got, c.String())
	}
	if strings.Join(idx, ",") != strings.Join(got, ",") {
		t.Fatal("record blocks out of index order")
	}
	if !RepoCommitFromIndex(repo.Index).SetHash.Equal(RepoCommitFromRecords(refsOf(f.recs)).SetHash) {
		t.Fatal("index folds differently")
	}
}

func TestRepoCarEmptyAndIndexOnly(t *testing.T) {
	f := newCarFixture(t)
	repo, err := VerifyRepoCarFull(bytes.NewReader(f.car(t, nil)), f.params(t))
	if err != nil || len(repo.Index) != 0 || len(repo.Records) != 0 || !repo.Repo.SetHash.IsEmpty() {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := SerializeRepo(&buf, f.commitFor(t, f.recs), f.recs, true); err != nil {
		t.Fatal(err)
	}
	_, cids, _ := readBlocks(t, buf.Bytes())
	if len(cids) != 2 {
		t.Fatal("index-only car has record blocks")
	}
	p := f.params(t)
	p.IndexOnly = true
	repo, err = VerifyRepoCarFull(bytes.NewReader(buf.Bytes()), p)
	if err != nil || len(repo.Index) != 3 || len(repo.Records) != 0 {
		t.Fatal(err)
	}
	if _, err := VerifyRepoCarFull(bytes.NewReader(buf.Bytes()), f.params(t)); err == nil {
		t.Fatal("index-only car accepted where values are expected")
	}
}

func TestRepoCarAuthenticatesIndexWithoutRecords(t *testing.T) {
	f := newCarFixture(t)
	r, err := VerifyRepoCar(bytes.NewReader(f.car(t, f.recs)), f.params(t))
	if err != nil || !r.Repo.Matches(r.Commit) || len(r.Index) != 3 {
		t.Fatal(err)
	}
}

func TestRepoCarRejectsTampering(t *testing.T) {
	f := newCarFixture(t)
	b := f.car(t, f.recs)

	p := f.params(t)
	p.DidKey = didKeyOf(t, newK256(t))
	if _, err := VerifyRepoCarFull(bytes.NewReader(b), p); err == nil {
		t.Fatal("other key accepted")
	}
	p = f.params(t)
	p.Space = "at://did:example:space/space/app.bsky.group/other"
	if _, err := VerifyRepoCarFull(bytes.NewReader(b), p); err == nil || !strings.Contains(err.Error(), "commit failed verification") {
		t.Fatal(err)
	}
	p = f.params(t)
	p.Author = "did:example:bob"
	if _, err := VerifyRepoCarFull(bytes.NewReader(b), p); err == nil || !strings.Contains(err.Error(), "commit failed verification") {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	_ = SerializeRepo(&buf, f.commitFor(t, f.recs[:2]), f.recs, false)
	if _, err := VerifyRepoCarFull(bytes.NewReader(buf.Bytes()), f.params(t)); err == nil || !strings.Contains(err.Error(), "index does not match the commit hash") {
		t.Fatal(err)
	}

	// a record block whose bytes don't match its cid
	roots, cids, datas := readBlocks(t, b)
	tampered, _ := atdata.MarshalCBOR(map[string]any{"text": "tampered"})
	blocks := [][2][]byte{{cids[0].Bytes(), datas[0]}, {cids[1].Bytes(), datas[1]}, {cids[2].Bytes(), tampered}}
	for i := 3; i < len(cids); i++ {
		blocks = append(blocks, [2][]byte{cids[i].Bytes(), datas[i]})
	}
	r, err := VerifyRepoCar(bytes.NewReader(rawCar(t, roots, blocks...)), f.params(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := drain(r); err == nil || !strings.Contains(strings.ToLower(err.Error()), "not a valid cid for bytes") {
		t.Fatal(err)
	}

	// a car missing a record named in the index
	r, err = VerifyRepoCar(bytes.NewReader(rawCar(t, roots, blocks[:2]...)), f.params(t))
	if err != nil {
		t.Fatal(err)
	}
	blocks[2] = [2][]byte{cids[2].Bytes(), datas[2]}
	r, _ = VerifyRepoCar(bytes.NewReader(rawCar(t, roots, blocks[:len(blocks)-1]...)), f.params(t))
	if err := drain(r); err == nil || !strings.Contains(err.Error(), "missing 1 record(s) named in the index") {
		t.Fatal(err)
	}
}

func drain(r *RepoCarReader) error {
	for {
		_, err := r.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func TestRepoCarRejectsIndexWithNonCidValues(t *testing.T) {
	f := newCarFixture(t)
	commitBytes, err := EncodeCommit(f.commitFor(t, f.recs))
	if err != nil {
		t.Fatal(err)
	}
	indexBytes, _ := atdata.MarshalCBOR(map[string]any{"app.bsky.feed.post/1": "not-a-cid"})
	cc, ic := cidForCBOR(commitBytes), cidForCBOR(indexBytes)
	b := rawCar(t, []cid.Cid{cc, ic}, [2][]byte{cc.Bytes(), commitBytes}, [2][]byte{ic.Bytes(), indexBytes})
	if _, err := VerifyRepoCarFull(bytes.NewReader(b), f.params(t)); err == nil || !strings.Contains(err.Error(), "invalid repo index") {
		t.Fatal(err)
	}
}

func TestRepoCarIncrementalSync(t *testing.T) {
	f := newCarFixture(t)
	c := f.commitFor(t, f.recs)
	var ops []RepoOp
	for _, r := range f.recs {
		c := r.Cid
		ops = append(ops, RepoOp{Collection: r.Collection, Rkey: r.Rkey, Cid: &c})
	}
	if !VerifyCommit(c, f.ctx, didKeyOf(t, f.key)) || !NewRepoCommit().ApplyOps(ops).Matches(c) {
		t.Fatal("replay does not catch up")
	}
	if NewRepoCommit().ApplyOps(ops[:2]).Matches(c) {
		t.Fatal("missed op not detected")
	}
	a, b := f.recs[0], f.recs[1]
	local := RepoCommitFromRecords(refsOf(f.recs[:1])).ApplyOps([]RepoOp{
		{Collection: a.Collection, Rkey: a.Rkey, Cid: &b.Cid, Prev: &a.Cid},
		{Collection: a.Collection, Rkey: a.Rkey, Prev: &b.Cid},
	})
	if !local.SetHash.IsEmpty() {
		t.Fatal("deletes and updates")
	}
}

func TestRepoCarFraming(t *testing.T) {
	f := newCarFixture(t)
	b := f.car(t, f.recs)
	if _, err := VerifyRepoCar(bytes.NewReader(b[:3]), f.params(t)); err == nil {
		t.Fatal("truncated car accepted")
	}
	commitBytes, _ := EncodeCommit(f.commitFor(t, f.recs))
	cc := cidForCBOR(commitBytes)
	one := rawCar(t, []cid.Cid{cc}, [2][]byte{cc.Bytes(), commitBytes})
	if _, err := VerifyRepoCar(bytes.NewReader(one), f.params(t)); err == nil || !strings.Contains(err.Error(), "expected 2 car roots") {
		t.Fatal(err)
	}
	// one byte at a time
	repo, err := VerifyRepoCarFull(iotestOneByte(b), f.params(t))
	if err != nil || len(repo.Records) != 3 {
		t.Fatal(err)
	}
}

type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func iotestOneByte(b []byte) io.Reader { return oneByteReader{bytes.NewReader(b)} }

// The reference's serializeRepo output, verified and reproduced byte for byte.
func TestRepoCarReferenceExport(t *testing.T) {
	raw, err := os.ReadFile("testdata/export.car")
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Did, Space, Rev, DidKey, PrivateKeyHex, Hash string
		Records                                      []struct{ Collection, Rkey, Cid string }
	}
	jb, _ := os.ReadFile("testdata/export.json")
	if err := json.Unmarshal(jb, &meta); err != nil {
		t.Fatal(err)
	}
	repo, err := VerifyRepoCarFull(bytes.NewReader(raw), VerifyRepoParams{Space: meta.Space, Author: meta.Did, DidKey: meta.DidKey})
	if err != nil {
		t.Fatal(err)
	}
	if repo.Commit.Rev != meta.Rev || hex.EncodeToString(repo.Commit.Hash) != meta.Hash || len(repo.Records) != len(meta.Records) {
		t.Fatal("export metadata")
	}
	// The private key signs under the same did:key.
	k, err := atcrypto.ParsePrivateBytesK256(unhex(t, meta.PrivateKeyHex))
	if err != nil || didKeyOf(t, k) != meta.DidKey {
		t.Fatal("fixture key")
	}
	// Re-encoding the verified records with the same commit reproduces the CAR.
	var recs []SerializedRecord
	for _, r := range repo.Records {
		sr, err := SerializeRecord(r.Collection, r.Rkey, r.Record)
		if err != nil {
			t.Fatal(err)
		}
		if !sr.Cid.Equals(r.Cid) {
			t.Fatalf("re-encoded %s/%s to %s", r.Collection, r.Rkey, sr.Cid)
		}
		recs = append(recs, sr)
	}
	var buf bytes.Buffer
	if err := SerializeRepo(&buf, repo.Commit, recs, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), raw) {
		t.Fatal("re-serialized car differs from the reference's")
	}
}
