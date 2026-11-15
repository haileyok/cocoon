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
	t.Parallel()
	t.Run("round-trips metadata and pairs", func(t *testing.T) {
		var buf bytes.Buffer
		sw, err := WriteStar(&buf, map[string]any{"$type": "test", "n": int64(1)})
		if err != nil {
			t.Fatal(err)
		}
		_ = sw.WritePair([]byte("a"), []byte{1})
		_ = sw.WritePair([]byte("b"), []byte{})
		_ = sw.Close()
		// Each pair is preceded by a 0x01 control byte, and the archive ends
		// with a 0x00 one.
		if raw := buf.Bytes(); raw[len(raw)-1] != 0 || raw[len(raw)-1-5] != 1 {
			t.Fatalf("framing: %x", raw)
		}
		sr, err := ReadStar(&buf, StarLimits{})
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
	t.Run("an empty archive is the header followed by the end byte", func(t *testing.T) {
		var buf bytes.Buffer
		sw, _ := WriteStar(&buf, map[string]any{"$type": "test"})
		_ = sw.Close()
		raw := buf.Bytes()
		if raw[len(raw)-1] != 0 {
			t.Fatalf("%x", raw)
		}
		sr, err := ReadStar(bytes.NewReader(raw), StarLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := sr.Next(); err != io.EOF {
			t.Fatal(err)
		}
	})
	meta := mustCBOR(t, map[string]any{"$type": "test"})
	header := append(append([]byte{}, StarMagic...), starFrame(meta)...)
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
		if _, err := ReadStar(bytes.NewReader(b), StarLimits{}); !errors.As(err, &pe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	next := func(t *testing.T, b []byte) error {
		t.Helper()
		sr, err := ReadStar(bytes.NewReader(b), StarLimits{})
		if err != nil {
			t.Fatal(err)
		}
		for {
			if _, _, err := sr.Next(); err != nil {
				return err
			}
		}
	}
	for name, c := range map[string]struct {
		tail []byte
		want string
	}{
		"EOF before the end byte":  {nil, "unexpected end of archive"},
		"EOF inside a pair":        {append([]byte{1}, starFrame([]byte("key"))...), "unexpected end of archive"},
		"a bad control byte":       {[]byte{2}, "invalid control byte"},
		"bytes after the end byte": {[]byte{0, 0}, "unexpected bytes after end of archive"},
		"a truncated frame":        {[]byte{1, 5, 'a'}, "unexpected end of archive"},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			var pe *StarParseError
			err := next(t, append(append([]byte{}, header...), c.tail...))
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	t.Run("enforces length limits before reading a frame", func(t *testing.T) {
		pair := append(append([]byte{1}, starFrame([]byte{1, 2})...), starFrame([]byte{3, 4, 5})...)
		ok := append(append(append([]byte{}, header...), pair...), 0)
		limits := StarLimits{MaxMetaLen: uint64(len(meta)), MaxKeyLen: 2, MaxValueLen: 3}
		sr, err := ReadStar(bytes.NewReader(ok), limits)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := sr.Next(); err != nil {
			t.Fatal(err)
		}
		for name, l := range map[string]StarLimits{
			"meta":  {MaxMetaLen: uint64(len(meta)) - 1, MaxKeyLen: 2, MaxValueLen: 3},
			"key":   {MaxMetaLen: uint64(len(meta)), MaxKeyLen: 1, MaxValueLen: 3},
			"value": {MaxMetaLen: uint64(len(meta)), MaxKeyLen: 2, MaxValueLen: 2},
		} {
			sr, err := ReadStar(bytes.NewReader(ok), l)
			if err == nil {
				_, _, err = sr.Next()
			}
			if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
				t.Errorf("%s: %v", name, err)
			}
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
	return out, repo.ToCommit(CommitCtx{Space: repoSpace, Repo: repoDid, Rev: "3kbcq3p7ad222"})
}

func repoParams(t *testing.T, c Commit) VerifyRepoParams {
	t.Helper()
	return VerifyRepoParams{Space: repoSpace, Repo: repoDid, VerifyMacParams: commitMacParams(t, c, repoSecret, repoSecret)}
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
	return writeRepoBytes(t, meta, pairs, true)
}

// writeRepoBytes is writeRawRepo, optionally leaving off the end byte.
func writeRepoBytes(t *testing.T, meta map[string]any, pairs [][2][]byte, end bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	sw, err := WriteStar(&buf, meta)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pairs {
		_ = sw.WritePair(p[0], p[1])
	}
	if end {
		_ = sw.Close()
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
		sr, err := ReadStar(bytes.NewReader(archive), RepoStarLimits)
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
		v, err := VerifyRepoStarFull(iotest.OneByteReader(bytes.NewReader(archive)), repoParams(t, commit))
		if err != nil || len(v.Records) != 3 || v.Records[1].Record["text"] != "one" || !v.Records[1].Cid.Equals(recs[1].Cid) {
			t.Fatalf("%v %+v", err, v)
		}
	})
	t.Run("serializes an empty repo", func(t *testing.T) {
		_, empty := serialize(t, nil)
		v, err := VerifyRepoStarFull(bytes.NewReader(writeRepo(t, empty, nil)), repoParams(t, empty))
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
		p := repoParams(t, commit)
		p.VerifyMacParams = commitMacParams(t, commit, repoSecret, bytes.Repeat([]byte{0}, 32))
		expectVerr(t, archive, p, "MAC does not match")
		p = repoParams(t, commit)
		p.Repo = "did:example:bob"
		expectVerr(t, archive, p, "commit is not for the repo and space requested")
		p = repoParams(t, commit)
		p.Space = "at://did:example:space/space/app.bsky.group/other"
		expectVerr(t, archive, p, "commit is not for the repo and space requested")
		expectVerr(t, writeRawRepo(t, with("repo", "did:example:bob"), pairsOf(recs)), repoParams(t, commit), "commit is not for the repo and space requested")
		expectVerr(t, writeRawRepo(t, with("$type", "other"), pairsOf(recs)), repoParams(t, commit), "invalid repo metadata")
		expectVerr(t, writeRawRepo(t, with("ver", int64(2)), pairsOf(recs)), repoParams(t, commit), "unsupported commit version")
	})
	t.Run("rejects a repo missing a record", func(t *testing.T) {
		expectVerr(t, writeRawRepo(t, meta, pairsOf(recs[:2])), repoParams(t, commit), "do not match")
	})
	t.Run("rejects a repo with an extra record", func(t *testing.T) {
		extra, _ := serialize(t, []testRecord{{"app.bsky.feed.post", "3", map[string]any{"text": "three"}}})
		expectVerr(t, writeRawRepo(t, meta, pairsOf(append(append([]SerializedRecord{}, recs...), extra...))), repoParams(t, commit), "do not match")
	})
	t.Run("rejects a record whose value was swapped", func(t *testing.T) {
		p := pairsOf(recs)
		p[1][1] = recs[2].Bytes
		expectVerr(t, writeRawRepo(t, meta, p), repoParams(t, commit), "do not match")
	})
	t.Run("rejects records out of order or duplicated", func(t *testing.T) {
		p := pairsOf(recs)
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{p[1], p[0], p[2]}), repoParams(t, commit), "out of order")
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{p[0], p[0], p[1], p[2]}), repoParams(t, commit), "out of order")
	})
	t.Run("rejects an invalid record path", func(t *testing.T) {
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{{[]byte("not-a-path"), recs[0].Bytes}}), repoParams(t, commit), "invalid record path")
	})
	t.Run("rejects an oversized record before reading it", func(t *testing.T) {
		b := writeRepoBytes(t, meta, nil, false)
		b = append(b, 1)
		b = append(b, starFrame([]byte("app.bsky.feed.post/1"))...)
		b = append(b, binary.AppendUvarint(nil, MaxRecordSize+1)...)
		expectVerr(t, b, repoParams(t, commit), "exceeds limit")
	})
	t.Run("rejects a record that is not a map", func(t *testing.T) {
		expectVerr(t, writeRawRepo(t, meta, [][2][]byte{{[]byte("app.bsky.feed.post/1"), {0x01}}}), repoParams(t, commit), "invalid record cbor")
	})
	t.Run("rejects a truncated archive", func(t *testing.T) {
		expectVerr(t, archive[:len(archive)-3], repoParams(t, commit), "unexpected end")
		expectVerr(t, archive[:10], repoParams(t, commit), "")
	})
	t.Run("rejects an archive without its end byte, or with trailing bytes", func(t *testing.T) {
		expectVerr(t, archive[:len(archive)-1], repoParams(t, commit), "unexpected end of archive")
		expectVerr(t, append(append([]byte{}, archive...), 0), repoParams(t, commit), "unexpected bytes after end of archive")
	})
	t.Run("reads an archive without authenticating its commit", func(t *testing.T) {
		rr, err := ReadRepoStar(bytes.NewReader(archive))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for {
			_, err := rr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			n++
		}
		if n != 3 || rr.Commit.Repo != repoDid {
			t.Fatal(n)
		}
		// Records that don't fold to the commit's data still fail.
		rr, err = ReadRepoStar(bytes.NewReader(writeRawRepo(t, meta, pairsOf(recs[:2]))))
		if err != nil {
			t.Fatal(err)
		}
		var last error
		for last == nil {
			_, last = rr.Next()
		}
		if last == io.EOF || !strings.Contains(last.Error(), "do not match") {
			t.Fatal(last)
		}
	})
}

func TestVerifyRecord(t *testing.T) {
	t.Parallel()
	value := map[string]any{"$type": "app.bsky.feed.post", "text": "one"}
	s, _ := SerializeRecord("app.bsky.feed.post", "1", value)
	uri := repoSpace + "/" + repoDid + "/app.bsky.feed.post/1"
	p := VerifyRecordParams{URI: uri, VerifyMacParams: recordMacParams(t, uri, s.Cid, repoSecret, repoSecret)}
	if err := VerifyRecord(uri, s.Cid.String(), value, p); err != nil {
		t.Fatalf("does not accept the requested record under its MAC: %v", err)
	}
	other := p
	other.URI = uri + "x"
	if VerifyRecord(uri, s.Cid.String(), value, other) == nil {
		t.Fatal("accepted another record")
	}
	other = p
	other.VerifyMacParams = recordMacParams(t, uri, s.Cid, bytes.Repeat([]byte{1}, 32), repoSecret)
	if VerifyRecord(uri, s.Cid.String(), value, other) == nil {
		t.Fatal("accepted another secret")
	}
	if VerifyRecord(uri, s.Cid.String(), map[string]any{"text": "two"}, p) == nil {
		t.Fatal("accepted a value that does not match its cid")
	}
	if VerifyRecord(uri, "nope", value, p) == nil {
		t.Fatal("accepted a malformed cid")
	}
}

// export.star is a repo serialized by the reference (testdata/gen-vectors.mjs).
func TestReferenceExport(t *testing.T) {
	var exp struct {
		Did, Space, Rev, Data, KemPrivateKey, KeyShare, SharedSecret string
		Headers                                                      map[string]string
		Records                                                      []struct{ Collection, Rkey, Cid string }
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
	v, err := VerifyRepoStarFull(bytes.NewReader(star), VerifyRepoParams{Space: exp.Space, Repo: exp.Did, VerifyMacParams: VerifyMacParams{
		Encapsulation: Encapsulation{KeyShare: exp.KeyShare, SharedSecret: secret}, Headers: headersOf(exp.Headers),
	}})
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

func TestRepoStarBoundsKeys(t *testing.T) {
	t.Parallel()
	_, commit := serialize(t, nil)
	b := writeRepoBytes(t, RepoStarMeta(commit), nil, false)
	b = append(b, 1)
	b = append(b, binary.AppendUvarint(nil, RepoStarLimits.MaxKeyLen+1)...)
	_, err := VerifyRepoStarFull(bytes.NewReader(b), repoParams(t, commit))
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatal(err)
	}
}
