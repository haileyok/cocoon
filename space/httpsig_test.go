package space

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// Ported from packages/space/src/http-signature.test.ts.

const (
	sigAuthorization = "Atproto-Space credential"
	sigAudience      = "did:example:repo"
)

func hdrs(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

func expectSigErr(t *testing.T, err error, contains string) {
	t.Helper()
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("not a SignatureError: %v", err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not contain %q", err, contains)
	}
}

func TestHTTPSignatures(t *testing.T) {
	key := newP256(t)
	keyID := didKeyOf(t, key)
	signed := func() http.Header {
		h, err := CreateSpaceSigHeaders(key, sigAuthorization, sigAudience)
		if err != nil {
			t.Fatal(err)
		}
		return hdrs(h)
	}
	signRaw := func(base string) string {
		sig, err := key.HashAndSign([]byte(base))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}

	t.Run("signs the RFC 9421 signature base with a compact P-256 signature", func(t *testing.T) {
		input, sig, err := CreateSpaceSig(key, sigAuthorization, sigAudience)
		if err != nil {
			t.Fatal(err)
		}
		if input != `("authorization" "atproto-space-audience")` || len(sig) != 64 {
			t.Fatalf("%s %d", input, len(sig))
		}
		base := "\"authorization\": " + sigAuthorization + "\n\"atproto-space-audience\": " + sigAudience + "\n\"@signature-params\": " + input
		pub, _ := key.PublicKey()
		raw := pub.UncompressedBytes()
		ek := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(raw[1:33]), Y: new(big.Int).SetBytes(raw[33:])}
		d := sha256.Sum256([]byte(base))
		if !ecdsa.Verify(ek, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("stdlib does not verify the base")
		}
		got, err := VerifySpaceSignature(signed(), keyID)
		if err != nil || got != keyID {
			t.Fatal(err)
		}
	})

	t.Run("signs a delegation token without an audience", func(t *testing.T) {
		m, _ := CreateSpaceSigHeaders(key, "Bearer delegation", "")
		if m["signature-input"] != `atproto-space=("authorization");keyid="`+keyID+`"` {
			t.Fatal(m["signature-input"])
		}
		if _, ok := m["atproto-space-audience"]; ok {
			t.Fatal("audience set")
		}
		if got, err := VerifySpaceSignature(hdrs(m), ""); err != nil || got != keyID {
			t.Fatal(err)
		}
		_, err := VerifySpaceSignature(hdrs(m), keyID)
		expectSigErr(t, err, "")
	})

	t.Run("accepts high-S as well as low-S signatures", func(t *testing.T) {
		h := signed()
		s := h.Get("signature")
		sig, _ := base64.StdEncoding.DecodeString(s[len("atproto-space=:") : len(s)-1])
		n := elliptic.P256().Params().N
		lowS := new(big.Int).SetBytes(sig[32:])
		if lowS.Cmp(new(big.Int).Rsh(n, 1)) >= 0 {
			t.Fatal("not low-S")
		}
		new(big.Int).Sub(n, lowS).FillBytes(sig[32:])
		h.Set("signature", "atproto-space=:"+base64.StdEncoding.EncodeToString(sig)+":")
		if got, err := VerifySpaceSignature(h, keyID); err != nil || got != keyID {
			t.Fatal(err)
		}
	})

	t.Run("accepts delegation signatures with an optional alg", func(t *testing.T) {
		input := `("authorization");keyid="` + keyID + `";alg="ecdsa-p256-sha256"`
		base := "\"authorization\": Bearer delegation\n\"@signature-params\": " + input
		h := hdrs(map[string]string{"authorization": "Bearer delegation", "signature-input": "atproto-space=" + input, "signature": "atproto-space=:" + signRaw(base) + ":"})
		if got, err := VerifySpaceSignature(h, ""); err != nil || got != keyID {
			t.Fatal(err)
		}
	})

	t.Run("accepts optional credential parameters and other signature labels", func(t *testing.T) {
		input := `("authorization" "atproto-space-audience");alg="ecdsa-p256-sha256";keyid="` + keyID + `"`
		base := "\"authorization\": " + sigAuthorization + "\n\"atproto-space-audience\": " + sigAudience + "\n\"@signature-params\": " + input
		h := hdrs(map[string]string{
			"authorization":          sigAuthorization,
			"atproto-space-audience": sigAudience,
			"signature-input":        `other=("authorization");keyid="other", atproto-space=` + input,
			"signature":              "other=:YWJj:, atproto-space=:" + signRaw(base) + ":",
		})
		if got, err := VerifySpaceSignature(h, keyID); err != nil || got != keyID {
			t.Fatal(err)
		}
	})

	for _, name := range []string{"authorization", "atproto-space-audience"} {
		h := signed()
		h.Set(name, h.Get(name)+"-changed")
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "")

		h = signed()
		h.Add(name, h.Get(name))
		_, err = VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "exactly one")
	}
	for _, name := range []string{"authorization", "atproto-space-audience", "signature-input", "signature"} {
		h := signed()
		h.Del(name)
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "")
	}

	t.Run("requires the audience to be covered by the signature", func(t *testing.T) {
		m, _ := CreateSpaceSigHeaders(key, sigAuthorization, "")
		h := hdrs(m)
		h.Set("atproto-space-audience", sigAudience)
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "must cover")
	})

	t.Run("rejects another signing key", func(t *testing.T) {
		m, _ := CreateSpaceSigHeaders(newP256(t), sigAuthorization, sigAudience)
		_, err := VerifySpaceSignature(hdrs(m), keyID)
		expectSigErr(t, err, "invalid HTTP message signature")
	})

	t.Run("rejects an optional keyid that differs from the credential key", func(t *testing.T) {
		h := signed()
		h.Set("signature-input", h.Get("signature-input")+`;keyid="`+didKeyOf(t, newP256(t))+`"`)
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "keyid does not match the credential key")
	})

	for _, params := range []string{"", ";keyid", ";keyid=123", `;keyid="not-a-key"`} {
		m, _ := CreateSpaceSigHeaders(key, "Bearer delegation", "")
		h := hdrs(m)
		h.Set("signature-input", `atproto-space=("authorization")`+params)
		_, err := VerifySpaceSignature(h, "")
		expectSigErr(t, err, "")
	}

	for name, comps := range map[string]string{
		"missing authorization":           `("atproto-space-audience")`,
		"reversed headers":                `("atproto-space-audience" "authorization")`,
		"additional header":               `("authorization" "atproto-space-audience" "content-type")`,
		"duplicate component":             `("authorization" "authorization" "atproto-space-audience")`,
		"unsupported component parameter": `("authorization";sf "atproto-space-audience")`,
		"malformed input":                 `not-a-list`,
	} {
		h := signed()
		h.Set("signature-input", "atproto-space="+comps)
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "")
		if !strings.Contains(err.Error(), "must cover exactly") && !strings.Contains(err.Error(), "missing or malformed") {
			t.Fatalf("%s: %v", name, err)
		}
	}

	t.Run("rejects credential signatures on the delegation exchange", func(t *testing.T) {
		_, err := VerifySpaceSignature(signed(), "")
		expectSigErr(t, err, "must cover exactly")
	})

	t.Run("rejects changed signature parameters", func(t *testing.T) {
		h := signed()
		h.Set("signature-input", h.Get("signature-input")+`;alg="ecdsa-p256-sha256"`)
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "invalid HTTP message signature")
	})

	for _, aud := range []string{"", sigAudience} {
		m, _ := CreateSpaceSigHeaders(key, sigAuthorization, aud)
		h := hdrs(m)
		h.Set("signature-input", h.Get("signature-input")+`;alg="ecdsa-p384-sha384"`)
		kid := ""
		if aud != "" {
			kid = keyID
		}
		_, err := VerifySpaceSignature(h, kid)
		expectSigErr(t, err, "algorithm")
	}

	t.Run("rejects other key types", func(t *testing.T) {
		other := newK256(t)
		if _, err := CreateSpaceSigHeaders(other, sigAuthorization, ""); err == nil || !strings.Contains(err.Error(), "P-256") {
			t.Fatal(err)
		}
		h := signed()
		_, err := VerifySpaceSignature(h, didKeyOf(t, other))
		expectSigErr(t, err, "P-256")
		h.Set("signature-input", `atproto-space=("authorization");keyid="`+didKeyOf(t, other)+`"`)
		_, err = VerifySpaceSignature(h, "")
		expectSigErr(t, err, "P-256")
	})

	for _, s := range []string{"not-a-byte-sequence", ":YWJj:", ":!!!:"} {
		h := signed()
		h.Set("signature", "atproto-space="+s)
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "")
	}

	t.Run("rejects a DER-encoded signature", func(t *testing.T) {
		h := signed()
		s := h.Get("signature")
		compact, _ := base64.StdEncoding.DecodeString(s[len("atproto-space=:") : len(s)-1])
		var ints []byte
		for _, v := range [][]byte{compact[:32], compact[32:]} {
			b := v
			if v[0]&0x80 != 0 {
				b = append([]byte{0}, v...)
			}
			ints = append(ints, 2, byte(len(b)))
			ints = append(ints, b...)
		}
		der := append([]byte{0x30, byte(len(ints))}, ints...)
		h.Set("signature", "atproto-space=:"+base64.StdEncoding.EncodeToString(der)+":")
		_, err := VerifySpaceSignature(h, keyID)
		expectSigErr(t, err, "")
	})
}

func TestHTTPSigVectors(t *testing.T) {
	for i, v := range loadVectors(t).HTTPSig {
		kid := ""
		if v.CredentialKey != nil {
			kid = *v.CredentialKey
		}
		got, err := VerifySpaceSignature(hdrs(v.Headers), kid)
		if err != nil || got != v.KeyDid {
			t.Errorf("vector %d: %v %s", i, err, got)
		}
	}
}

var _ atcrypto.PrivateKey = (*atcrypto.PrivateKeyP256)(nil)
