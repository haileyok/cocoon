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
)

// Ported from packages/space/src/http-signature.test.ts.

const (
	sigAuthorization = "Atproto-Space-Credential credential"
	sigAudience      = "did:example:repo"
	sigPrefix        = "atproto-space-credential=:"
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
	sigBytes := func(h http.Header) []byte {
		s := h.Get("signature")
		b, err := base64.StdEncoding.DecodeString(s[len(sigPrefix) : len(s)-1])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("signs the RFC 9421 signature base with a compact P-256 signature", func(t *testing.T) {
		input, sig, err := CreateSpaceSig(key, sigAuthorization, sigAudience)
		if err != nil {
			t.Fatal(err)
		}
		want := `("authorization" "atproto-space-audience");tag="atproto-space-credential"`
		if input != want || len(sig) != 64 {
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
		if err := VerifyCredentialSig(signed(), keyID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("emits padded base64 and accepts it unpadded", func(t *testing.T) {
		h := signed()
		s := h.Get("signature")
		if !strings.HasSuffix(s, "=:") {
			t.Fatalf("not padded: %s", s)
		}
		h.Set("signature", strings.TrimRight(s[:len(s)-1], "=")+":")
		if err := VerifyCredentialSig(h, keyID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("requires an audience to sign", func(t *testing.T) {
		if _, err := CreateSpaceSigHeaders(key, sigAuthorization, ""); err == nil {
			t.Fatal("signed without an audience")
		}
	})

	for name, tag := range map[string]string{"missing": "", "other": `;tag="other"`} {
		t.Run("rejects a "+name+" tag on a credential use", func(t *testing.T) {
			h := signed()
			h.Set("signature-input", strings.Replace(h.Get("signature-input"), `;tag="atproto-space-credential"`, tag, 1))
			expectSigErr(t, VerifyCredentialSig(h, keyID), `tag must be "atproto-space-credential"`)
		})
	}

	t.Run("rejects the old atproto-space label", func(t *testing.T) {
		h := signed()
		h.Set("signature-input", strings.Replace(h.Get("signature-input"), "atproto-space-credential=", "atproto-space=", 1))
		h.Set("signature", strings.Replace(h.Get("signature"), "atproto-space-credential=", "atproto-space=", 1))
		expectSigErr(t, VerifyCredentialSig(h, keyID), "missing or malformed")
	})

	t.Run("signs the authorization exactly as sent, whatever its case", func(t *testing.T) {
		m, err := CreateSpaceSigHeaders(key, "atproto-space-credential credential", sigAudience)
		if err != nil {
			t.Fatal(err)
		}
		h := hdrs(m)
		if err := VerifyCredentialSig(h, keyID); err != nil {
			t.Fatal(err)
		}
		h.Set("authorization", sigAuthorization)
		expectSigErr(t, VerifyCredentialSig(h, keyID), "invalid HTTP message signature")
	})

	t.Run("accepts high-S as well as low-S signatures", func(t *testing.T) {
		h := signed()
		sig := sigBytes(h)
		n := elliptic.P256().Params().N
		lowS := new(big.Int).SetBytes(sig[32:])
		if lowS.Cmp(new(big.Int).Rsh(n, 1)) >= 0 {
			t.Fatal("not low-S")
		}
		new(big.Int).Sub(n, lowS).FillBytes(sig[32:])
		h.Set("signature", sigPrefix+base64.StdEncoding.EncodeToString(sig)+":")
		if err := VerifyCredentialSig(h, keyID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("accepts optional credential parameters and other signature labels", func(t *testing.T) {
		input := `("authorization" "atproto-space-audience");alg="ecdsa-p256-sha256";keyid="` + keyID + `";tag="atproto-space-credential"`
		base := "\"authorization\": " + sigAuthorization + "\n\"atproto-space-audience\": " + sigAudience + "\n\"@signature-params\": " + input
		h := hdrs(map[string]string{
			"authorization":          sigAuthorization,
			"atproto-space-audience": sigAudience,
			"signature-input":        `other=("authorization");keyid="other", atproto-space-credential=` + input,
			"signature":              "other=:YWJj:, " + sigPrefix + signRaw(base) + ":",
		})
		if err := VerifyCredentialSig(h, keyID); err != nil {
			t.Fatal(err)
		}
	})

	for _, name := range []string{"authorization", "atproto-space-audience"} {
		h := signed()
		h.Set(name, h.Get(name)+"-changed")
		expectSigErr(t, VerifyCredentialSig(h, keyID), "")

		h = signed()
		h.Add(name, h.Get(name))
		expectSigErr(t, VerifyCredentialSig(h, keyID), "malformed")
	}
	for _, name := range []string{"authorization", "atproto-space-audience", "signature-input", "signature"} {
		h := signed()
		h.Del(name)
		expectSigErr(t, VerifyCredentialSig(h, keyID), "")
	}

	t.Run("requires the audience to be covered by the signature", func(t *testing.T) {
		input := `("authorization");tag="atproto-space-credential"`
		base := "\"authorization\": " + sigAuthorization + "\n\"@signature-params\": " + input
		h := hdrs(map[string]string{
			"authorization":          sigAuthorization,
			"atproto-space-audience": sigAudience,
			"signature-input":        "atproto-space-credential=" + input,
			"signature":              sigPrefix + signRaw(base) + ":",
		})
		expectSigErr(t, VerifyCredentialSig(h, keyID), "must cover")
	})

	t.Run("rejects another signing key", func(t *testing.T) {
		m, _ := CreateSpaceSigHeaders(newP256(t), sigAuthorization, sigAudience)
		expectSigErr(t, VerifyCredentialSig(hdrs(m), keyID), "invalid HTTP message signature")
	})

	t.Run("rejects an optional keyid that differs from the credential key", func(t *testing.T) {
		h := signed()
		h.Set("signature-input", h.Get("signature-input")+`;keyid="`+didKeyOf(t, newP256(t))+`"`)
		expectSigErr(t, VerifyCredentialSig(h, keyID), "keyid does not match the credential key")
	})

	for name, comps := range map[string]string{
		"missing authorization":           `("atproto-space-audience")`,
		"reversed headers":                `("atproto-space-audience" "authorization")`,
		"additional header":               `("authorization" "atproto-space-audience" "content-type")`,
		"duplicate component":             `("authorization" "authorization" "atproto-space-audience")`,
		"unsupported component parameter": `("authorization";sf "atproto-space-audience")`,
		"malformed input":                 `not-a-list`,
	} {
		h := signed()
		h.Set("signature-input", "atproto-space-credential="+comps)
		err := VerifyCredentialSig(h, keyID)
		expectSigErr(t, err, "")
		if !strings.Contains(err.Error(), "must cover exactly") && !strings.Contains(err.Error(), "missing or malformed") {
			t.Fatalf("%s: %v", name, err)
		}
	}

	t.Run("rejects changed signature parameters", func(t *testing.T) {
		h := signed()
		h.Set("signature-input", h.Get("signature-input")+`;alg="ecdsa-p256-sha256"`)
		expectSigErr(t, VerifyCredentialSig(h, keyID), "invalid HTTP message signature")
	})

	t.Run("rejects other algorithms", func(t *testing.T) {
		h := signed()
		h.Set("signature-input", h.Get("signature-input")+`;alg="ecdsa-p384-sha384"`)
		expectSigErr(t, VerifyCredentialSig(h, keyID), "algorithm")
	})

	t.Run("rejects other key types", func(t *testing.T) {
		other := newK256(t)
		if _, err := CreateSpaceSigHeaders(other, sigAuthorization, sigAudience); err == nil || !strings.Contains(err.Error(), "P-256") {
			t.Fatal(err)
		}
		expectSigErr(t, VerifyCredentialSig(signed(), didKeyOf(t, other)), "P-256")
	})

	for _, s := range []string{"not-a-byte-sequence", ":YWJj:", ":!!!:"} {
		h := signed()
		h.Set("signature", "atproto-space-credential="+s)
		expectSigErr(t, VerifyCredentialSig(h, keyID), "")
	}

	t.Run("rejects a DER-encoded signature", func(t *testing.T) {
		h := signed()
		compact := sigBytes(h)
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
		h.Set("signature", sigPrefix+base64.StdEncoding.EncodeToString(der)+":")
		expectSigErr(t, VerifyCredentialSig(h, keyID), "")
	})
}

func TestHTTPSigVectors(t *testing.T) {
	for i, v := range loadVectors(t).HTTPSig {
		if err := VerifyCredentialSig(hdrs(v.Headers), v.KeyDid); err != nil {
			t.Errorf("vector %d: %v", i, err)
		}
	}
}
