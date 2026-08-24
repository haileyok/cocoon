package space

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestLtHashFixedVector(t *testing.T) {
	const element = "com.example.collection/3jzfc/bafybeigdyrzt4example"
	const wantDigest = "d02d6f400d974a5c6fea7f04df49270bf4074c20544a509b8b76c5df31e6f484"
	const wantStatePrefix = "640ce11a3d562f63a39cc1fe2b05b98a6b90a2ff1a34bb24ce3fbff7e38275276deb42cc6c34e4d526e464d212a5a3844795812a7cdc693876fc1deb1e4d22b2"

	hash, err := NewLtHash()
	if err != nil {
		t.Fatal(err)
	}
	hash.Add(element)
	if got := hex.EncodeToString(hash.Digest()); got != wantDigest {
		t.Fatalf("digest = %s, want %s", got, wantDigest)
	}
	wantPrefix, err := hex.DecodeString(wantStatePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if got := hash.State()[:len(wantPrefix)]; !bytes.Equal(got, wantPrefix) {
		t.Fatalf("state prefix = %x, want %x", got, wantPrefix)
	}
}

func TestLtHashEmptyDigest(t *testing.T) {
	hash, err := NewLtHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hash.IsEmpty() {
		t.Fatal("new hash is not empty")
	}
	if got, want := hex.EncodeToString(hash.Digest()), "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"; got != want {
		t.Fatalf("empty digest = %s, want %s", got, want)
	}
}

func TestLtHashAdditionCommutes(t *testing.T) {
	first, err := NewLtHash()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLtHash()
	if err != nil {
		t.Fatal(err)
	}
	first.Add("one").Add("two").Add("three")
	second.Add("three").Add("one").Add("two")
	if !first.Equals(second) {
		t.Fatalf("addition is not commutative: %x != %x", first.Digest(), second.Digest())
	}
	if !first.Equal(second) {
		t.Fatal("Equal disagrees with Equals")
	}
}

func TestLtHashAddRemoveInverse(t *testing.T) {
	hash, err := NewLtHash()
	if err != nil {
		t.Fatal(err)
	}
	hash.Add("one").Add("two").Remove("one").Remove("two")
	if !hash.IsEmpty() {
		t.Fatalf("add/remove did not return to empty: %x", hash.State())
	}
}

func TestLtHashStateCopySafety(t *testing.T) {
	input := make([]byte, LtHashStateBytes)
	input[0] = 0x12
	input[1] = 0x34
	hash, err := NewLtHash(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 0xff
	if got := hash.State()[0]; got != 0x12 {
		t.Fatalf("constructor retained input alias: got %#x", got)
	}

	state := hash.State()
	state[0] = 0xff
	if got := hash.State()[0]; got != 0x12 {
		t.Fatalf("State retained output alias: got %#x", got)
	}

	digest := hash.Digest()
	wantDigest := append([]byte(nil), digest...)
	digest[0] ^= 0xff
	if got := hash.Digest(); !bytes.Equal(got, wantDigest) {
		t.Fatalf("Digest retained output alias: got %x, want %x", got, wantDigest)
	}
}

func TestLtHashRejectsMalformedState(t *testing.T) {
	for _, size := range []int{1, LtHashStateBytes - 1, LtHashStateBytes + 1} {
		if _, err := NewLtHash(make([]byte, size)); err == nil {
			t.Errorf("NewLtHash accepted %d-byte state", size)
		}
	}
	if _, err := NewLtHash(nil, nil); err == nil {
		t.Error("NewLtHash accepted multiple states")
	}
}

func TestFormatElement(t *testing.T) {
	want := "com.example.collection/3jzfc/bafybeigdyrzt4example"
	if got := FormatElement("com.example.collection", "3jzfc", "bafybeigdyrzt4example"); got != want {
		t.Fatalf("FormatElement = %q, want %q", got, want)
	}
	if got := FormatSetHashElement("com.example.collection", "3jzfc", "bafybeigdyrzt4example"); got != want {
		t.Fatalf("FormatSetHashElement = %q, want %q", got, want)
	}
}

func TestLtHashWrapsUint16Lanes(t *testing.T) {
	state := bytes.Repeat([]byte{0xff}, LtHashStateBytes)
	hash, err := NewLtHash(state)
	if err != nil {
		t.Fatal(err)
	}
	before := hash.State()
	hash.Add("wrap").Remove("wrap")
	if !bytes.Equal(hash.State(), before) {
		t.Fatal("wrapped add/remove changed state")
	}
}
