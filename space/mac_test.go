package space

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
)

// Ported from packages/space/tests/mac.test.ts and tests/_util.ts.

const (
	macURI   = "at://did:example:space/space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/1"
	macSpace = "at://did:example:space/space/app.bsky.group/test"
	keyShare = "did:key:zDnaExample"
)

var macCommit = Commit{Ver: 1, Space: macSpace, Repo: "did:example:alice", Rev: "3kbcq3p7ad400", Data: bytes.Repeat([]byte{1}, 32)}

func randSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func headersOf(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

// commitMacParams is what a syncer verifies a commit with after a host MACs
// it under hostSecret. The syncer expects secret, so the two differ only when
// a test says so.
func commitMacParams(t *testing.T, c Commit, secret, hostSecret []byte) VerifyMacParams {
	t.Helper()
	req, err := ParseMacRequest([]string{FormatMacRequest(CommitMacProfile, keyShare)}, CommitMacProfile)
	if err != nil || req == nil {
		t.Fatal(err)
	}
	headers := CreateCommitMacHeaders(c, CreateMacParams{MacRequest: *req, SharedSecret: hostSecret})
	return VerifyMacParams{Encapsulation: Encapsulation{KeyShare: keyShare, SharedSecret: secret}, Headers: headersOf(headers)}
}

func recordMacParams(t *testing.T, uri string, c cid.Cid, secret, hostSecret []byte) VerifyMacParams {
	t.Helper()
	req, err := ParseMacRequest([]string{FormatMacRequest(RecordMacProfile, keyShare)}, RecordMacProfile)
	if err != nil || req == nil {
		t.Fatal(err)
	}
	headers := CreateRecordMacHeaders(uri, c, CreateMacParams{MacRequest: *req, SharedSecret: hostSecret})
	return VerifyMacParams{Encapsulation: Encapsulation{KeyShare: keyShare, SharedSecret: secret}, Headers: headersOf(headers)}
}

func wantMacErr(t *testing.T, err error, contains string) {
	t.Helper()
	var me *MacError
	if !errors.As(err, &me) || !strings.Contains(err.Error(), contains) {
		t.Fatalf("want MacError containing %q, got %v", contains, err)
	}
}

func TestMacRequests(t *testing.T) {
	t.Parallel()
	t.Run("formats the Accept-Signature header", func(t *testing.T) {
		if got := FormatMacRequest(CommitMacProfile, keyShare); got != `mac=("atproto-space-commit";sf);keyid="did:key:zDnaExample";tag="atproto-space-commit"` {
			t.Fatal(got)
		}
		if got := FormatMacRequest(RecordMacProfile, keyShare); got != `mac=("atproto-space-record";sf);keyid="did:key:zDnaExample";tag="atproto-space-record"` {
			t.Fatal(got)
		}
	})
	t.Run("round-trips a request", func(t *testing.T) {
		h := FormatMacRequest(CommitMacProfile, keyShare)
		got, err := ParseMacRequest([]string{h}, CommitMacProfile)
		if err != nil || got == nil || got.Label != "mac" || got.KeyShare != keyShare || got.SignatureParams != strings.TrimPrefix(h, "mac=") {
			t.Fatalf("%v %+v", err, got)
		}
	})
	t.Run("finds the request by its tag, under any label", func(t *testing.T) {
		h := fmt.Sprintf(`other=("content-digest");tag="other", m=("atproto-space-commit";sf);keyid="%s";tag="atproto-space-commit"`, keyShare)
		got, err := ParseMacRequest([]string{h}, CommitMacProfile)
		if err != nil || got == nil || got.Label != "m" || got.KeyShare != keyShare {
			t.Fatalf("%v %+v", err, got)
		}
	})
	t.Run("accepts an hmac-sha256 alg, and no other", func(t *testing.T) {
		h := FormatMacRequest(CommitMacProfile, keyShare)
		if _, err := ParseMacRequest([]string{h + `;alg="hmac-sha256"`}, CommitMacProfile); err != nil {
			t.Fatal(err)
		}
		_, err := ParseMacRequest([]string{h + `;alg="ecdsa-p256-sha256"`}, CommitMacProfile)
		wantMacErr(t, err, "algorithm")
	})
	t.Run("finds no request when none has the profile tag", func(t *testing.T) {
		if got, err := ParseMacRequest(nil, CommitMacProfile); got != nil || err != nil {
			t.Fatal(got, err)
		}
		// Requests with other tags are ignored, including another profile's.
		h := `other=("content-digest");tag="other", ` + FormatMacRequest(RecordMacProfile, keyShare)
		if got, err := ParseMacRequest([]string{h}, CommitMacProfile); got != nil || err != nil {
			t.Fatal(got, err)
		}
	})
	t.Run("rejects a malformed header", func(t *testing.T) {
		_, err := ParseMacRequest([]string{"???"}, CommitMacProfile)
		wantMacErr(t, err, "malformed")
	})
	t.Run("rejects more than one request with the profile tag", func(t *testing.T) {
		r := fmt.Sprintf(`("atproto-space-commit";sf);keyid="%s";tag="atproto-space-commit"`, keyShare)
		_, err := ParseMacRequest([]string{"a=" + r + ", b=" + r}, CommitMacProfile)
		wantMacErr(t, err, "more than one MAC requested")
	})
	for _, param := range []string{"created", "expires", `nonce="abc"`} {
		t.Run("rejects a "+param+" parameter", func(t *testing.T) {
			h := FormatMacRequest(CommitMacProfile, keyShare)
			_, err := ParseMacRequest([]string{h + ";" + param}, CommitMacProfile)
			wantMacErr(t, err, "unsupported MAC parameter")
		})
	}
	for name, components := range map[string]string{
		"another header":        `("atproto-space-record";sf)`,
		"the header without sf": `("atproto-space-commit")`,
		"an additional header":  `("atproto-space-commit";sf "authorization")`,
	} {
		t.Run("rejects a request covering "+name, func(t *testing.T) {
			h := fmt.Sprintf(`mac=%s;keyid="%s";tag="atproto-space-commit"`, components, keyShare)
			_, err := ParseMacRequest([]string{h}, CommitMacProfile)
			wantMacErr(t, err, "must cover exactly")
		})
	}
	for name, keyid := range map[string]string{"missing": "", "not a DID": `;keyid="not-a-did"`} {
		t.Run("rejects a keyid that is "+name, func(t *testing.T) {
			h := `mac=("atproto-space-commit";sf)` + keyid + `;tag="atproto-space-commit"`
			_, err := ParseMacRequest([]string{h}, CommitMacProfile)
			wantMacErr(t, err, "keyid")
		})
	}
}

func TestCommitMac(t *testing.T) {
	t.Parallel()
	secret := randSecret(t)

	t.Run("covers an Atproto-Space-Commit header under the requested parameters", func(t *testing.T) {
		params := fmt.Sprintf(`("atproto-space-commit";sf);keyid="%s";tag="atproto-space-commit"`, keyShare)
		req, err := ParseMacRequest([]string{"sig1=" + params}, CommitMacProfile)
		if err != nil || req == nil {
			t.Fatal(err)
		}
		headers := CreateCommitMacHeaders(macCommit, CreateMacParams{MacRequest: *req, SharedSecret: secret})

		covered := fmt.Sprintf(`ver=1, repo="did:example:alice", space="%s", rev="3kbcq3p7ad400", data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:`, macSpace)
		if headers["atproto-space-commit"] != covered || headers["signature-input"] != "sig1="+params {
			t.Fatalf("%v", headers)
		}
		// An RFC 9421 hmac-sha256 signature over the covered header.
		base := `"atproto-space-commit";sf: ` + covered + "\n" + `"@signature-params": ` + params
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(base))
		if headers["signature"] != "sig1=:"+base64.StdEncoding.EncodeToString(m.Sum(nil))+":" {
			t.Fatalf("signature %s", headers["signature"])
		}
	})
	t.Run("verifies under the same shared secret", func(t *testing.T) {
		if err := VerifyCommitMac(macCommit, commitMacParams(t, macCommit, secret, secret)); err != nil {
			t.Fatal(err)
		}
		wantMacErr(t, VerifyCommitMac(macCommit, commitMacParams(t, macCommit, secret, randSecret(t))), "MAC does not match")
	})
	for name, mod := range map[string]func(*Commit){
		"ver":   func(c *Commit) { c.Ver = 2 },
		"repo":  func(c *Commit) { c.Repo = "did:example:bob" },
		"space": func(c *Commit) { c.Space += "2" },
		"rev":   func(c *Commit) { c.Rev = "3kbcq3p7ad401" },
		"data":  func(c *Commit) { c.Data = bytes.Repeat([]byte{2}, 32) },
	} {
		t.Run("rejects a commit with another "+name, func(t *testing.T) {
			mac := commitMacParams(t, macCommit, secret, secret)
			other := macCommit
			mod(&other)
			wantMacErr(t, VerifyCommitMac(other, mac), "commit does not match its MAC")
		})
	}
	t.Run("rejects a tampered header", func(t *testing.T) {
		mac := commitMacParams(t, macCommit, secret, secret)
		mac.Headers.Set("atproto-space-commit", strings.Replace(mac.Headers.Get("atproto-space-commit"), "3kbcq3p7ad400", "3kbcq3p7ad401", 1))
		other := macCommit
		other.Rev = "3kbcq3p7ad401"
		wantMacErr(t, VerifyCommitMac(other, mac), "MAC does not match")
	})
	t.Run("covers the header as a structured field", func(t *testing.T) {
		// Whitespace isn't significant, since the header is re-serialized.
		mac := commitMacParams(t, macCommit, secret, secret)
		mac.Headers.Set("atproto-space-commit", strings.ReplaceAll(mac.Headers.Get("atproto-space-commit"), ", ", ",   "))
		if err := VerifyCommitMac(macCommit, mac); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("finds the MAC by its tag, under any label", func(t *testing.T) {
		mac := commitMacParams(t, macCommit, secret, secret)
		for _, name := range []string{"signature-input", "signature"} {
			mac.Headers.Set(name, strings.Replace(mac.Headers.Get(name), "mac=", "other=", 1))
		}
		if err := VerifyCommitMac(macCommit, mac); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rejects more than one MAC with the profile tag", func(t *testing.T) {
		mac := commitMacParams(t, macCommit, secret, secret)
		for _, name := range []string{"signature-input", "signature"} {
			v := mac.Headers.Get(name)
			mac.Headers.Set(name, v+", "+strings.Replace(v, "mac=", "other=", 1))
		}
		wantMacErr(t, VerifyCommitMac(macCommit, mac), "more than one")
	})

	// A MAC over the commit header with the given signature parameters,
	// standing in for a host that answers differently than this package does.
	macWithParams := func(params string) VerifyMacParams {
		mac := commitMacParams(t, macCommit, secret, secret)
		covered := mac.Headers.Get("atproto-space-commit")
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(`"atproto-space-commit";sf: ` + covered + "\n" + `"@signature-params": ` + params))
		mac.Headers.Set("signature-input", "mac="+params)
		mac.Headers.Set("signature", "mac=:"+base64.StdEncoding.EncodeToString(m.Sum(nil))+":")
		return mac
	}
	for name, params := range map[string]string{
		"parameters added and reordered": fmt.Sprintf(`("atproto-space-commit";sf);tag="atproto-space-commit";created=1700000000;keyid="%s"`, keyShare),
		"no keyid":                       `("atproto-space-commit";sf);tag="atproto-space-commit"`,
		"an hmac-sha256 alg":             fmt.Sprintf(`("atproto-space-commit";sf);keyid="%s";tag="atproto-space-commit";alg="hmac-sha256"`, keyShare),
	} {
		t.Run("accepts a MAC with "+name, func(t *testing.T) {
			if err := VerifyCommitMac(macCommit, macWithParams(params)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, c := range []struct{ name, params, err string }{
		{"another keyid", `("atproto-space-commit";sf);keyid="did:key:zDnaOther";tag="atproto-space-commit"`, "keyid does not match"},
		{"another alg", fmt.Sprintf(`("atproto-space-commit";sf);keyid="%s";tag="atproto-space-commit";alg="hmac-sha512"`, keyShare), "algorithm"},
		{"another tag", fmt.Sprintf(`("atproto-space-commit";sf);keyid="%s";tag="other"`, keyShare), "missing or malformed signature with tag"},
		{"the header not flagged sf", fmt.Sprintf(`("atproto-space-commit");keyid="%s";tag="atproto-space-commit"`, keyShare), "must cover exactly"},
	} {
		t.Run("rejects a MAC with "+c.name, func(t *testing.T) {
			wantMacErr(t, VerifyCommitMac(macCommit, macWithParams(c.params)), c.err)
		})
	}
	for _, name := range []string{"atproto-space-commit", "signature-input", "signature"} {
		t.Run("rejects a response without a "+name+" header", func(t *testing.T) {
			mac := commitMacParams(t, macCommit, secret, secret)
			mac.Headers.Del(name)
			wantMacErr(t, VerifyCommitMac(macCommit, mac), "")
		})
	}
}

func TestRecordMac(t *testing.T) {
	t.Parallel()
	secret := randSecret(t)
	t.Run("verifies under the same shared secret", func(t *testing.T) {
		mac := recordMacParams(t, macURI, cidA, secret, secret)
		if got := mac.Headers.Get("atproto-space-record"); got != fmt.Sprintf(`uri="%s", cid="%s"`, macURI, cidA) {
			t.Fatal(got)
		}
		if err := VerifyRecordMac(macURI, cidA, mac); err != nil {
			t.Fatal(err)
		}
		wantMacErr(t, VerifyRecordMac(macURI, cidA, recordMacParams(t, macURI, cidA, secret, randSecret(t))), "MAC does not match")
	})
	t.Run("covers the uri and the cid", func(t *testing.T) {
		mac := recordMacParams(t, macURI, cidA, secret, secret)
		wantMacErr(t, VerifyRecordMac(macURI+"2", cidA, mac), "record does not match its MAC")
		wantMacErr(t, VerifyRecordMac(macURI, cidB, mac), "record does not match its MAC")
	})
	t.Run("is not accepted as a commit MAC", func(t *testing.T) {
		mac := recordMacParams(t, macURI, cidA, secret, secret)
		wantMacErr(t, VerifyCommitMac(macCommit, mac), `missing or malformed signature with tag "atproto-space-commit"`)
	})
}

func TestMacVectors(t *testing.T) {
	t.Parallel()
	v := loadVectors(t)
	for i, c := range v.Commits {
		var recs []RecordRef
		for _, r := range c.Records {
			recs = append(recs, RecordRef{r.Collection, r.Rkey, cid.MustParse(r.Cid)})
		}
		commit := RepoCommitFromRecords(recs).ToCommit(c.Ctx)
		secret := unhex(t, c.SharedSecret)
		req, err := ParseMacRequest([]string{c.AcceptSignature}, CommitMacProfile)
		if err != nil || req == nil {
			t.Fatal(err)
		}
		got := CreateCommitMacHeaders(commit, CreateMacParams{MacRequest: *req, SharedSecret: secret})
		for k, want := range c.Headers {
			if got[k] != want {
				t.Errorf("commit vector %d %s: got %q want %q", i, k, got[k], want)
			}
		}
		if err := VerifyCommit(commit, VerifyCommitParams{Space: c.Ctx.Space, Repo: c.Ctx.Repo, VerifyMacParams: VerifyMacParams{
			Encapsulation: Encapsulation{KeyShare: c.KeyShare, SharedSecret: secret}, Headers: headersOf(c.Headers),
		}}); err != nil {
			t.Errorf("commit vector %d does not verify: %v", i, err)
		}
	}
	for i, r := range v.RecordMacs {
		secret := unhex(t, r.SharedSecret)
		req, err := ParseMacRequest([]string{r.AcceptSignature}, RecordMacProfile)
		if err != nil || req == nil {
			t.Fatal(err)
		}
		c := cid.MustParse(r.Cid)
		got := CreateRecordMacHeaders(r.URI, c, CreateMacParams{MacRequest: *req, SharedSecret: secret})
		for k, want := range r.Headers {
			if got[k] != want {
				t.Errorf("record vector %d %s: got %q want %q", i, k, got[k], want)
			}
		}
		if err := VerifyRecordMac(r.URI, c, VerifyMacParams{Encapsulation: Encapsulation{KeyShare: r.KeyShare, SharedSecret: secret}, Headers: headersOf(r.Headers)}); err != nil {
			t.Errorf("record vector %d does not verify: %v", i, err)
		}
	}
}
