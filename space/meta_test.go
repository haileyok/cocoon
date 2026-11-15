package space

import (
	"bytes"

	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
)

// Ported from packages/space/src/space-meta-archive.test.ts, plus an archive
// the reference wrote (testdata/meta.star).

const metaSpaceURI = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/space/com.example.group/g"

func sampleMeta() SpaceMetaArchive {
	return SpaceMetaArchive{
		Space:  metaSpaceURI,
		Policy: map[string]any{"$type": "com.atproto.memberspace.policy", "publicRead": false},
		PolicyState: []PolicyStateEntry{
			{Key: "com.atproto.memberspace.member/did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", Value: map[string]any{"read": true, "write": false}},
			{Key: "com.atproto.memberspace.member/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", Value: map[string]any{"read": true, "write": true}},
		},
		Writers: []SpaceMetaWriter{
			{Did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", RepoRev: "3mvzvh4fs222b", Data: bytes.Repeat([]byte{7}, 32), SpaceRev: "3mvzvh4fs222c"},
			{Did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", RepoRev: "3mvzvh4fs2223", Data: bytes.Repeat([]byte{9}, 32), SpaceRev: "3mvzvh4fs2224"},
		},
	}
}

func writeMeta(t *testing.T, a SpaceMetaArchive) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSpaceMetaStar(&buf, a); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rawMeta writes an archive's pairs in the order given, unchecked.
func rawMeta(t *testing.T, space string, pairs [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	sw, err := WriteStar(&buf, map[string]any{"$type": SpaceMetaStarType, "ver": int64(1), "space": space})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pairs {
		_ = sw.WritePair([]byte(p[0]), mustCBOR(t, mustJSONMap(t, p[1])))
	}
	_ = sw.Close()
	return buf.Bytes()
}

func mustJSONMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		if f, ok := v.(float64); ok {
			m[k] = int64(f)
		}
		if str, ok := v.(string); ok && k == "data" {
			m[k] = atdata.Bytes(bytes.Repeat([]byte(str), 32))
		}
	}
	return m
}

func TestSpaceMetaArchive(t *testing.T) {
	t.Parallel()
	t.Run("round-trips, putting each section into key order", func(t *testing.T) {
		got, err := ReadSpaceMetaStar(bytes.NewReader(writeMeta(t, sampleMeta())))
		if err != nil {
			t.Fatal(err)
		}
		if got.Space != metaSpaceURI || got.Policy["$type"] != "com.atproto.memberspace.policy" {
			t.Fatalf("%+v", got)
		}
		if len(got.PolicyState) != 2 || !strings.HasSuffix(got.PolicyState[0].Key, "aaaaaaaaaaaaaaaaaaaaaaaa") {
			t.Fatalf("policy state not in key order: %+v", got.PolicyState)
		}
		if len(got.Writers) != 2 || got.Writers[0].Did != "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" || got.Writers[0].RepoRev != "3mvzvh4fs2223" || !bytes.Equal(got.Writers[1].Data, bytes.Repeat([]byte{7}, 32)) {
			t.Fatalf("writers: %+v", got.Writers)
		}
	})

	p := `{"$type":"com.atproto.personalspace.policy"}`
	w := `{"repoRev":"3mvzvh4fs222b","data":"x","spaceRev":"3mvzvh4fs222c"}`
	for name, c := range map[string]struct {
		pairs [][2]string
		want  string
	}{
		"a missing policy":          {[][2]string{}, "missing policy"},
		"duplicate policy keys":     {[][2]string{{"policy", p}, {"policy", p}}, "duplicate or out-of-order"},
		"a policy after the state":  {[][2]string{{"a.b.c/x", `{}`}, {"policy", p}}, "section out of order"},
		"state after the writers":   {[][2]string{{"policy", p}, {"writer/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", w}, {"z.b.c/x", `{}`}}, "section out of order"},
		"out-of-order state keys":   {[][2]string{{"policy", p}, {"b.b.c/x", `{}`}, {"a.b.c/x", `{}`}}, "duplicate or out-of-order"},
		"out-of-order writer keys":  {[][2]string{{"policy", p}, {"writer/did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", w}, {"writer/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", w}}, "duplicate or out-of-order"},
		"a writer with a bad DID":   {[][2]string{{"policy", p}, {"writer/nope", w}}, "invalid DID"},
		"a writer missing data":     {[][2]string{{"policy", p}, {"writer/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", `{"repoRev":"3mvzvh4fs222b","spaceRev":"3mvzvh4fs222c"}`}}, "data must be bytes"},
		"a writer with the old rev": {[][2]string{{"policy", p}, {"writer/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", `{"rev":"3mvzvh4fs222b","data":"x","spaceRev":"3mvzvh4fs222c"}`}}, "unexpected property"},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := ReadSpaceMetaStar(bytes.NewReader(rawMeta(t, metaSpaceURI, c.pairs)))
			var me *SpaceMetaArchiveError
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			_ = me
		})
	}

	t.Run("rejects the wrong metadata", func(t *testing.T) {
		var buf bytes.Buffer
		sw, _ := WriteStar(&buf, map[string]any{"$type": "atproto-space-repo", "ver": int64(1), "space": metaSpaceURI})
		_ = sw.Close()
		if _, err := ReadSpaceMetaStar(&buf); err == nil {
			t.Fatal("accepted")
		}
		if _, err := ReadSpaceMetaStar(bytes.NewReader(rawMeta(t, "not-a-space", [][2]string{{"policy", p}}))); err == nil {
			t.Fatal("accepted a bad space")
		}
	})

	// testdata/meta.star is an archive written by the reference
	// (testdata/gen-vectors.mjs).
	t.Run("reads and rewrites the reference's archive", func(t *testing.T) {
		star, err := os.ReadFile("testdata/meta.star")
		if err != nil {
			t.Fatal(err)
		}
		var exp struct {
			Space   string
			Policy  map[string]any
			Writers []struct{ Did, RepoRev, Data, SpaceRev string }
		}
		b, err := os.ReadFile("testdata/meta.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &exp); err != nil {
			t.Fatal(err)
		}
		got, err := ReadSpaceMetaStar(bytes.NewReader(star))
		if err != nil || got.Space != exp.Space || len(got.Writers) != len(exp.Writers) {
			t.Fatalf("%v %+v", err, got)
		}
		for i, w := range got.Writers {
			if w.Did != exp.Writers[i].Did || w.RepoRev != exp.Writers[i].RepoRev || w.SpaceRev != exp.Writers[i].SpaceRev || hex.EncodeToString(w.Data) != exp.Writers[i].Data {
				t.Fatalf("writer %d: %+v", i, w)
			}
		}
		if again := writeMeta(t, *got); !bytes.Equal(again, star) {
			t.Fatal("re-serialization differs")
		}
	})
}
