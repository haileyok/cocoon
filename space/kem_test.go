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
		var ke *KemError
		if _, err := Encapsulate(didKeyOf(t, newK256(t))); !errors.As(err, &ke) {
			t.Fatal(err)
		}
		if _, err := Decapsulate(author, didKeyOf(t, newK256(t))); !errors.As(err, &ke) {
			t.Fatal(err)
		}
		if _, err := Decapsulate(author, "did:key:nope"); !errors.As(err, &ke) {
			t.Fatal(err)
		}
	})
	// The keys are from the export-only DHKEM(P-256, HKDF-SHA256) entry of the
	// HPKE test vectors (github.com/cfrg/draft-irtf-cfrg-hpke), where the
	// syncer's key share is enc and the author's KEM keypair is skRm. Those
	// vectors use a different info, so the expected secret was computed with
	// Go's crypto/hpke, using info "atproto-mac" and an empty exporter context.
	t.Run("matches HPKE secret export", func(t *testing.T) {
		enc := unhex(t, "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d")
		skRm, err := atcrypto.ParsePrivateBytesP256(unhex(t, "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346"))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := atcrypto.ParsePublicUncompressedBytesP256(enc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decapsulate(skRm, pub.DIDKey())
		if err != nil || hex.EncodeToString(got) != "2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d" {
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
		if FormatMacRequest(CommitMacProfile, v.KeyShare) != v.AcceptCommitSignature || FormatMacRequest(RecordMacProfile, v.KeyShare) != v.AcceptRecordSignature {
			t.Errorf("vector %d accept-signature header", i)
		}
		req, err := ParseMacRequest([]string{v.AcceptCommitSignature}, CommitMacProfile)
		if err != nil || req == nil || req.KeyShare != v.KeyShare {
			t.Errorf("vector %d parse: %v", i, err)
		}
	}
}
