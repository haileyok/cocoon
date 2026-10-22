package space

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ipfs/go-cid"
)

// Ported from packages/space/tests/mac.test.ts.

const macURI = "at://did:example:alice/space/app.bsky.group/test/app.bsky.feed.post/1"

func TestCommitMac(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	c := NewRepoCommit().Add("app.bsky.feed.post", "1", cidA).ToCommit(testCtx)
	mac := ComputeCommitMac(secret, c)
	if len(mac) != 32 || !VerifyCommitMac(secret, c, mac) {
		t.Fatal("does not verify under the same shared secret")
	}
	if VerifyCommitMac(bytes.Repeat([]byte{2}, 32), c, mac) {
		t.Fatal("verified under another secret")
	}
	a, b := c, c
	a.Space, a.Repo = "ab", "c"
	b.Space, b.Repo = "a", "bc"
	if bytes.Equal(ComputeCommitMac(secret, a), ComputeCommitMac(secret, b)) {
		t.Fatal("ambiguous across field boundaries")
	}
	other := c
	d := NewLtHash().Digest()
	other.Data = d[:]
	if VerifyCommitMac(secret, other, mac) {
		t.Fatal("does not cover the data digest")
	}
}

func TestRecordMac(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	mac := ComputeRecordMac(secret, macURI, cidA)
	if !VerifyRecordMac(secret, macURI, cidA, mac) {
		t.Fatal("does not verify under the same shared secret")
	}
	if VerifyRecordMac(secret, macURI+"x", cidA, mac) || VerifyRecordMac(secret, macURI, cidB, mac) {
		t.Fatal("does not cover the uri and the cid")
	}
	c := Commit{Ver: 1, Space: macURI, Repo: "", Rev: "", Data: cidA.Bytes()}
	if bytes.Equal(ComputeCommitMac(secret, c), mac) {
		t.Fatal("not domain-separated from a commit MAC")
	}
}

func TestRecordMacVectors(t *testing.T) {
	for i, v := range loadVectors(t).RecordMacs {
		c := cid.MustParse(v.Cid)
		if got := hex.EncodeToString(ComputeRecordMac(unhex(t, v.SharedSecret), v.URI, c)); got != v.Mac {
			t.Errorf("vector %d mac %s", i, got)
		}
		if got := FormatMacHeader(RecordMacType, unhex(t, v.Mac)); got != v.MacHeader {
			t.Errorf("vector %d header %s", i, got)
		}
	}
}

func TestMacHeaders(t *testing.T) {
	mac := bytes.Repeat([]byte{0xab}, 32)
	if got := FormatWantMacHeader(CommitMacType, "did:key:zDnaeX"); got != `type="atproto-space-repo", ver=1, key_share="did:key:zDnaeX"` {
		t.Fatal(got)
	}
	if got := FormatMacHeader(RecordMacType, []byte{1, 2, 3, 4}); got != `type="atproto-space-record", ver=1, mac=:AQIDBA==:` {
		t.Fatal(got)
	}
	got, err := ParseMacHeader([]string{FormatMacHeader(CommitMacType, mac)}, CommitMacType)
	if err != nil || !bytes.Equal(got, mac) {
		t.Fatal(err)
	}
	// Unpadded byte sequences are tolerated.
	got, err = ParseMacHeader([]string{`type="atproto-space-record", ver=1, mac=:AQIDBA:`}, RecordMacType)
	if err != nil || !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatal(err)
	}

	bad := map[string][]string{
		"missing":         nil,
		"empty":           {""},
		"malformed":       {"not a dictionary!"},
		"no key_share":    {`type="atproto-space-repo", ver=1`},
		"key_share token": {`type="atproto-space-repo", ver=1, key_share=abc`},
		"inner list":      {`type="atproto-space-repo", ver=1, key_share=("a")`},
		"other type":      {`type="atproto-space-record", ver=1, key_share="k"`},
		"other version":   {`type="atproto-space-repo", ver=2, key_share="k"`},
		"decimal version": {`type="atproto-space-repo", ver=1.0, key_share="k"`},
		"token type":      {`type=atproto-space-repo, ver=1, key_share="k"`},
		"missing version": {`type="atproto-space-repo", key_share="k"`},
	}
	for name, v := range bad {
		var me *MacError
		if _, err := ParseWantMacHeader(v, CommitMacType); !errors.As(err, &me) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var me *MacError
	if _, err := ParseMacHeader([]string{`type="atproto-space-repo", ver=1, mac="abc"`}, CommitMacType); !errors.As(err, &me) {
		t.Fatal(err)
	}
}
