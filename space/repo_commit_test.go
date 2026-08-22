package space

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	cbor "github.com/ipfs/go-ipld-cbor"
)

func TestEncodeCommitContextAndMACVector(t *testing.T) {
	ikm := make([]byte, CommitIKMBytes)
	for i := range ikm {
		ikm[i] = byte(i + 1)
	}
	ctx := CommitContext{
		Space:  "at://did:plc:test/space/com.example/alpha",
		Author: "did:key:test",
		Rev:    "0000000000000",
	}
	gotContext, err := EncodeCommitContext(ctx, ikm)
	if err != nil {
		t.Fatal(err)
	}
	wantContext, err := hex.DecodeString("617470726f746f2d73706163652d7631002961743a2f2f6469643a706c633a746573742f73706163652f636f6d2e6578616d706c652f616c706861000c6469643a6b65793a74657374000d3030303030303030303030303000200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotContext, wantContext) {
		t.Fatalf("context = %x, want %x", gotContext, wantContext)
	}
	hash := make([]byte, CommitHashBytes)
	for i := range hash {
		hash[i] = byte(0xa0 + i)
	}
	mac, err := ComputeCommitMAC(ikm, gotContext, hash)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(mac), "9f7b191453e43b0e759f42eb996873a884d9345fb4215052f747c8d8317472fc"; got != want {
		t.Fatalf("MAC = %s, want %s", got, want)
	}
}

func TestSignVerifyCanonicalCommitAndTampering(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	valueCID, err := CIDForCBOR([]byte{0x61, 0x76})
	if err != nil {
		t.Fatal(err)
	}
	repo := NewRepoCommit().Add("com.example.notes", "one", valueCID)
	ctx := CommitContext{Space: "at://did:plc:test/space/com.example/alpha", Author: "did:plc:author", Rev: "3jzfcijpj2s2a"}
	ikm := bytes.Repeat([]byte{0x42}, CommitIKMBytes)
	commit, err := repo.Sign(ctx, key, SignOptions{IKM: ikm})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(commit.IKM, ikm) {
		t.Fatal("signing did not preserve deterministic IKM")
	}
	if !VerifyCommit(commit, ctx, pub.DIDKey()) {
		t.Fatal("valid commit did not verify")
	}
	if !VerifyCommitWithVerifier(commit, ctx, pub) {
		t.Fatal("valid commit did not verify through interface")
	}

	encoded, err := EncodeSignedCommit(commit)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedCommit(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Hash, commit.Hash) || decoded.Rev != commit.Rev {
		t.Fatalf("decoded commit changed fields: %#v", decoded)
	}
	if _, err := DecodeSignedCommit(mustCBOR(t, map[string]interface{}{"ver": commit.Ver, "hash": commit.Hash, "ikm": commit.IKM, "sig": commit.Sig, "mac": commit.MAC, "rev": commit.Rev, "extra": true})); err == nil {
		t.Fatal("decoder accepted unknown signedCommit field")
	}

	badHash := commit
	badHash.Hash = append([]byte(nil), commit.Hash...)
	badHash.Hash[0]++
	if VerifyCommit(badHash, ctx, pub.DIDKey()) {
		t.Fatal("tampered hash verified")
	}
	badSig := commit
	badSig.Sig = append([]byte(nil), commit.Sig...)
	badSig.Sig[0]++
	if VerifyCommit(badSig, ctx, pub.DIDKey()) {
		t.Fatal("tampered signature verified")
	}
	if err := (SignedCommit{Ver: CommitVersion, Hash: make([]byte, 31), IKM: make([]byte, 32), Sig: make([]byte, 64), MAC: make([]byte, 32)}).Validate(); err == nil {
		t.Fatal("short commit hash accepted")
	}
}

func TestSignUsesInjectedReaderAndRejectsContextOverflow(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	r := NewRepoCommit()
	readerIKM := bytes.Repeat([]byte{0x7e}, CommitIKMBytes)
	commit, err := r.Sign(CommitContext{Space: "s", Author: "a", Rev: "r"}, key, SignOptions{Rand: bytes.NewReader(readerIKM)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(commit.IKM, readerIKM) {
		t.Fatal("reader IKM was not consumed")
	}
	if _, err := EncodeCommitContext(CommitContext{Space: string(bytes.Repeat([]byte{'x'}, MaxCommitContextFieldBytes+1))}, readerIKM); err == nil {
		t.Fatal("oversized context field accepted")
	}
	if _, err := r.Sign(CommitContext{Space: "s", Author: "a", Rev: "r"}, key, SignOptions{IKM: make([]byte, 31)}); err == nil {
		t.Fatal("short deterministic IKM accepted")
	}
}

func mustCBOR(t *testing.T, value interface{}) []byte {
	t.Helper()
	data, err := cbor.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
