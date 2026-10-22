package space

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
)

// Ported from packages/space/src/star.test.ts and packages/space/tests/sync.test.ts.

const (
	repoSpace = "at://did:example:space/space/app.bsky.group/test"
	repoDid   = "did:example:alice"
)

var repoSecret = bytes.Repeat([]byte{9}, 32)

func starFrame(b []byte) []byte { return append(binary.AppendUvarint(nil, uint64(len(b))), b...) }

func mustCBOR(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := atdata.MarshalCBOR(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStar(t *testing.T) {
	t.Run("round-trips metadata and pairs", func(t *testing.T) {
		var buf bytes.Buffer
		sw, err := WriteStar(&buf, map[string]any{"$type": "test", "n": int64(1)})
		if err != nil {
			t.Fatal(err)
		}
		_ = sw.WritePair([]byte("a"), []byte{1})
		_ = sw.WritePair([]byte("b"), []byte{})
		sr, err := ReadStar(&buf, 0)
		if err != nil || sr.Meta["$type"] != "test" || sr.Meta["n"] != int64(1) {
			t.Fatalf("%v %v", err, sr)
		}
		k, v, err := sr.Next()
		if err != nil || string(k) != "a" || !bytes.Equal(v, []byte{1}) {
			t.Fatal(err)
		}
		k, v, err = sr.Next()
		if err != nil || string(k) != "b" || v == nil || len(v) != 0 {
			t.Fatal(err)
		}
		if _, _, err := sr.Next(); err != io.EOF {
			t.Fatal(err)
		}
	})
	meta := mustCBOR(t, map[string]any{"$type": "test"})
	bad := map[string][]byte{
		"wrong magic":              append([]byte{0x2a, 0x6c, 0x02, 0x00}, starFrame(meta)...),
		"non-canonical varint":     append(append(append([]byte{}, StarMagic...), byte(len(meta))|0x80, 0x00), meta...),
		"non-canonical metadata":   append(append([]byte{}, StarMagic...), starFrame([]byte{0xa2, 0x65, '$', 't', 'y', 'p', 'e', 0x61, 'x', 0x61, 'b', 0x01})...),
		"metadata without a $type": append(append([]byte{}, StarMagic...), starFrame(mustCBOR(t, map[string]any{"n": int64(1)}))...),
		"trailing metadata bytes":  append(append([]byte{}, StarMagic...), starFrame(append(append([]byte{}, meta...), 0))...),
		"missing metadata":         append([]byte{}, StarMagic...),
	}
	for name, b := range bad {
		var pe *StarParseError
		if _, err := ReadStar(bytes.NewReader(b), 0); !errors.As(err, &pe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	t.Run("rejects EOF inside a pair", func(t *testing.T) {
		b := append(append(append([]byte{}, StarMagic...), starFrame(meta)...), starFrame([]byte("key"))...)
		sr, err := ReadStar(bytes.NewReader(b), 0)
		if err != nil {
			t.Fatal(err)
		}
		var pe *StarParseError
		if _, _, err := sr.Next(); !errors.As(err, &pe) {
			t.Fatal(err)
		}
	})
}

type testRecord struct {
	collection, rkey string
	value            map[string]any
}

func serialize(t *testing.T, recs []testRecord) ([]SerializedRecord, Commit) {
	t.Helper()
	repo := NewRepoCommit()
	var out []SerializedRecord
	for _, r := range recs {
		s, err := SerializeRecord(r.collection, r.rkey, r.value)
		if err != nil {
			t.Fatal(err)
		}
		repo.Add(r.collection, r.rkey, s.Cid)
		out = append(out, s)
	}
	return out, repo.ToCommit(CommitCtx{Space: repoSpace, Repo: repoDid, Rev: "3kbcq3p7ad400"})
}

func repoParams(c Commit) VerifyRepoParams {
	return VerifyRepoParams{Space: repoSpace, Repo: repoDid, SharedSecret: repoSecret, Mac: ComputeCommitMac(repoSecret, c)}
}

func writeRepo(t *testing.T, c Commit, recs []SerializedRecord) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := SerializeRepo(&buf, c, recs); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// writeRawRepo writes an archive without SerializeRepo's ordering check.
func writeRawRepo(t *testing.T, meta map[string]any, pairs [][2][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	sw, err := WriteStar(&buf, meta)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pairs {
		_ = sw.WritePair(p[0], p[1])
	}
	return buf.Bytes()
}

func pairsOf(recs []SerializedRecord) [][2][]byte {
	var out [][2][]byte
	for _, r := range recs {
		out = append(out, [2][]byte{[]byte(FormatRecordPath(r.Collection, r.Rkey)), r.Bytes})
	}
	return out
}

func TestRepoStar(t *testing.T) {
	recs, commit := serialize(t, []testRecord{
		{"app.bsky.feed.like", "1", map[string]any{"$type": "app.bsky.feed.like", "n": int64(1)}},
		{"app.bsky.feed.post", "1", map[string]any{"$type": "app.bsky.feed.post", "text": "one"}},
		{"app.bsky.feed.post", "2", map[string]any{"$type": "app.bsky.feed.post", "text": "two"}},
	})
	archive := writeRepo(t, commit, recs)

	t.Run("writes the commit as metadata, then one pair per record", func(t *testing.T) {
		sr, err := ReadStar(bytes.NewReader(archive), 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseRepoStarMeta(sr.Meta)
		if err != nil || got.Repo != repoDid || got.Space != repoSpace || !bytes.Equal(got.Data, commit.Data) || sr.Meta["$type"] != RepoStarType {
			t.Fatalf("%v %+v", err, got)
		}
		n := 0
		for {
			_, _, err := sr.Next()
			if err == io.EOF {
				break
			}
			n++
		}
		if n != len(recs) {
			t.Fatal(n)
		}
	})
	t.Run("round-trips through verification, chunked arbitrarily", func(t *testing.T) {
		v, err := VerifyRepoStarFull(iotest.OneByteReader(bytes.NewReader(archive)), repoParams(commit))
		if err != nil || len(v.Records) != 3 || v.Records[1].Record["text"] != "one" || !v.Records[1].Cid.Equals(recs[1].Cid) {
			t.Fatalf("%v %+v", err, v)
		}
	})
	t.Run("serializes an empty repo", func(t *testing.T) {
		_, empty := serialize(t, nil)
		v, err := VerifyRepoStarFull(bytes.NewReader(writeRepo(t, empty, nil)), repoParams(empty))
		if err != nil || len(v.Records) != 0 {
			t.Fatal(err)
		}
	})
	t.Run("refuses to serialize records out of path order", func(t *testing.T) {
		var buf bytes.Buffer
		if err := SerializeRepo(&buf, commit, []SerializedRecord{recs[1], recs[0]}); err == nil {
			t.Fatal("serialized out of order")
		}
		if err := SerializeRepo(&buf, commit, []SerializedRecord{recs[0], recs[0]}); err == nil {
			t.Fatal("serialized a duplicate")
		}
	})

	expectVerr := func(t *testing.T, b []byte, p VerifyRepoParams, contains string) {
		t.Helper()
		_, err := VerifyRepoStarFull(bytes.NewReader(b), p)
		if err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("got %v, want %q", err, contains)
		}
	}
	meta := RepoStarMeta(commit)
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range meta {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	t.Run("verifies the commit before reading any record", func(t *testing.T) {
		p := repoParams(commit)
		p.Mac = bytes.Repeat([]byte{0}, 32)
		expectVerr(t, archive, p, "commit failed verification")
		p = repoParams(commit)
		p.Repo = "did:example:bob"
		expectVerr(t, archive, p, "commit failed verification")
		p = repoParams(commit)
		p.Space = "at://did:example:space/space/app.bsky.group/other"
		expectVerr(t, archive, p, "commit failed verification")
		expectVerr(t, writeRawRepo(t, with("repo", "did:example:bob"), pairsOf(recs)), repoParams(commit), "commit failed verification")
		expectVerr(t, writeRawRepo(t, with("$type", "other"), pairsOf(recs)), repoParams(commit), "invalid repo metadata")
		expectVerr(t, writeRawRepo(t, with("ver", int64(2)), pairsOf(recs)), repoParams(commit), "commit failed verification")
	})
	t.Run("rejects a repo missing a record", func(t *testing.T) {
		expectVerr(t, writeRawRepo(t, meta, pairsOf(recs[:2])), repoParams(commit), "do not match")
	})
	t.Run("rejects a repo with an extra record", func(t *testing.T) {
		extra, _ := serialize(t, []testRecord{{"app.bsky.feed.post", "3", map[string]any{"text": "three"}}})
		expectVerr(t, writeRawRepo(t, meta, pairsOf(append(append([]SerializedRecord{}, recs...), extra...))), repoParams(commit), "do not match")
	})
	t.Run("rejects a record whose value was swapped", func(t *testing.T) {
		p := pairsOf(recs)
		p[1][1] = recs[2].Bytes
		expectVerr(t, writeRawRepo(t, meta, p), repoParams(commit), "do not match")
	})
	t.Run("rejects records out of order or duplicated", func(t *testing.T) {
		p := pairsOf(recs)
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{p[1], p[0], p[2]}), repoParams(commit), "out of order")
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{p[0], p[0], p[1], p[2]}), repoParams(commit), "out of order")
	})
	t.Run("rejects an invalid record path", func(t *testing.T) {
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{{[]byte("not-a-path"), recs[0].Bytes}}), repoParams(commit), "invalid record path")
	})
	t.Run("rejects an oversized record before reading it", func(t *testing.T) {
		b := writeRawRepo(t, meta, nil)
		b = append(b, starFrame([]byte("app.bsky.feed.post/1"))...)
		b = append(b, binary.AppendUvarint(nil, MaxRecordSize+1)...)
		expectVerr(t, b, repoParams(commit), "exceeds limit")
	})
	t.Run("rejects a record that is not a map", func(t *testing.T) {
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{{[]byte("app.bsky.feed.post/1"), {0x01}}}), repoParams(commit), "invalid record cbor")
	})
	t.Run("rejects a truncated archive", func(t *testing.T) {
		expectVerr(t, archive[:len(archive)-3], repoParams(commit), "unexpected end")
		expectVerr(t, archive[:10], repoParams(commit), "")
	})
}

func TestVerifyRecord(t *testing.T) {
	value := map[string]any{"$type": "app.bsky.feed.post", "text": "one"}
	s, _ := SerializeRecord("app.bsky.feed.post", "1", value)
	uri := repoSpace + "/" + repoDid + "/app.bsky.feed.post/1"
	mac := ComputeRecordMac(repoSecret, uri, s.Cid)
	p := VerifyRecordParams{URI: uri, SharedSecret: repoSecret, Mac: mac}
	if !VerifyRecord(uri, s.Cid.String(), value, p) {
		t.Fatal("does not accept the requested record under its MAC")
	}
	other := p
	other.URI = uri + "x"
	if VerifyRecord(uri, s.Cid.String(), value, other) {
		t.Fatal("accepted another record")
	}
	other = p
	other.SharedSecret = bytes.Repeat([]byte{1}, 32)
	if VerifyRecord(uri, s.Cid.String(), value, other) {
		t.Fatal("accepted another secret")
	}
	if VerifyRecord(uri, s.Cid.String(), map[string]any{"text": "two"}, p) {
		t.Fatal("accepted a value that does not match its cid")
	}
	if VerifyRecord(uri, "nope", value, p) {
		t.Fatal("accepted a malformed cid")
	}
}

// export.star is a repo serialized by the reference (testdata/gen-vectors.mjs).
func TestReferenceExport(t *testing.T) {
	var exp struct {
		Did, Space, Rev, Data, KemPrivateKey, KeyShare, SharedSecret, MacHeader string
		Records                                                                 []struct{ Collection, Rkey, Cid string }
	}
	b, err := os.ReadFile("testdata/export.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Fatal(err)
	}
	star, err := os.ReadFile("testdata/export.star")
	if err != nil {
		t.Fatal(err)
	}
	kem, err := atcrypto.ParsePrivateBytesP256(unhex(t, exp.KemPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := Decapsulate(kem, exp.KeyShare)
	if err != nil || hex.EncodeToString(secret) != exp.SharedSecret {
		t.Fatalf("decapsulate: %v", err)
	}
	mac, err := ParseMacHeader([]string{exp.MacHeader}, CommitMacType)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyRepoStarFull(bytes.NewReader(star), VerifyRepoParams{Space: exp.Space, Repo: exp.Did, SharedSecret: secret, Mac: mac})
	if err != nil {
		t.Fatal(err)
	}
	if v.Commit.Rev != exp.Rev || hex.EncodeToString(v.Commit.Data) != exp.Data || len(v.Records) != len(exp.Records) {
		t.Fatalf("%+v", v.Commit)
	}
	var recs []SerializedRecord
	for i, r := range v.Records {
		if r.Collection != exp.Records[i].Collection || r.Rkey != exp.Records[i].Rkey || r.Cid.String() != exp.Records[i].Cid {
			t.Fatalf("record %d", i)
		}
		s, err := SerializeRecord(r.Collection, r.Rkey, r.Record)
		if err != nil || !s.Cid.Equals(r.Cid) {
			t.Fatalf("record %d does not re-encode: %v", i, err)
		}
		recs = append(recs, s)
	}
	// Serializing the same repo here gives the same bytes.
	var buf bytes.Buffer
	if err := SerializeRepo(&buf, v.Commit, recs); err != nil || !bytes.Equal(buf.Bytes(), star) {
		t.Fatalf("re-serialization differs: %v", err)
	}
}

func TestRepoStarBoundsKeysByRecordSize(t *testing.T) {
	_, commit := serialize(t, nil)
	b := writeRawRepo(t, RepoStarMeta(commit), nil)
	b = append(b, binary.AppendUvarint(nil, MaxRecordSize+1)...)
	_, err := VerifyRepoStarFull(bytes.NewReader(b), repoParams(commit))
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatal(err)
	}
}
