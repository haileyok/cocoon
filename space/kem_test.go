package space

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// Ported from packages/space/tests/kem.test.ts.

func TestKem(t *testing.T) {
	author := newP256(t)
	authorKey := didKeyOf(t, author)

	t.Run("derives the same shared secret on both sides", func(t *testing.T) {
		enc, err := Encapsulate(authorKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decapsulate(author, enc.KeyShare)
		if err != nil || !bytes.Equal(got, enc.SharedSecret) || len(got) != 32 {
			t.Fatalf("%v %x %x", err, got, enc.SharedSecret)
		}
	})
	t.Run("uses a fresh key share per encapsulation", func(t *testing.T) {
		a, _ := Encapsulate(authorKey)
		b, _ := Encapsulate(authorKey)
		if a.KeyShare == b.KeyShare || bytes.Equal(a.SharedSecret, b.SharedSecret) {
			t.Fatal("reused")
		}
	})
	t.Run("derives a different secret under a different author key", func(t *testing.T) {
		enc, _ := Encapsulate(authorKey)
		got, err := Decapsulate(newP256(t), enc.KeyShare)
		if err != nil || bytes.Equal(got, enc.SharedSecret) {
			t.Fatal(err)
		}
	})
	t.Run("rejects a key that is not P-256", func(t *testing.T) {
		var me *MacError
		if _, err := Encapsulate(didKeyOf(t, newK256(t))); !errors.As(err, &me) {
			t.Fatal(err)
		}
		if _, err := Decapsulate(author, didKeyOf(t, newK256(t))); !errors.As(err, &me) {
			t.Fatal(err)
		}
		if _, err := Decapsulate(author, "did:key:nope"); !errors.As(err, &me) {
			t.Fatal(err)
		}
	})
	// RFC 9180 §A.3.1, DHKEM(P-256, HKDF-SHA256): the syncer's key share is
	// pkEm and the author's KEM keypair is skRm.
	t.Run("matches the RFC 9180 test vector", func(t *testing.T) {
		pkEm := unhex(t, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
		skRm, err := atcrypto.ParsePrivateBytesP256(unhex(t, "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := atcrypto.ParsePublicUncompressedBytesP256(pkEm)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decapsulate(skRm, pub.DIDKey())
		if err != nil || hex.EncodeToString(got) != "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8" {
			t.Fatalf("%v %x", err, got)
		}
	})
}

func TestKemVectors(t *testing.T) {
	for i, v := range loadVectors(t).Kem {
		kem, err := atcrypto.ParsePrivateBytesP256(unhex(t, v.KemPrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		if didKeyOf(t, kem) != v.KemKey {
			t.Errorf("vector %d kem key", i)
		}
		got, err := Decapsulate(kem, v.KeyShare)
		if err != nil || hex.EncodeToString(got) != v.SharedSecret {
			t.Errorf("vector %d: %v %x", i, err, got)
		}
		if FormatWantMacHeader(CommitMacType, v.KeyShare) != v.WantMacHeader || FormatWantMacHeader(RecordMacType, v.KeyShare) != v.WantRecordMacHeader {
			t.Errorf("vector %d want-mac header", i)
		}
		ks, err := ParseWantMacHeader([]string{v.WantMacHeader}, CommitMacType)
		if err != nil || ks != v.KeyShare {
			t.Errorf("vector %d parse: %v", i, err)
		}
	}
}
