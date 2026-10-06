package space

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Ported from packages/space/tests/lthash.test.ts.

var zeros = make([]byte, LtHashStateBytes)

func TestLtHashStartsEmpty(t *testing.T) {
	h := NewLtHash()
	if !bytes.Equal(h.State(), zeros) || !h.IsEmpty() {
		t.Fatal("new hash is not 2048 zero bytes")
	}
}

func TestLtHashAddRemoveReturnsToZero(t *testing.T) {
	h := NewLtHash().Add("a")
	if bytes.Equal(h.State(), zeros) {
		t.Fatal("add left the state at zero")
	}
	h.Remove("a")
	if !bytes.Equal(h.State(), zeros) {
		t.Fatal("remove did not return to zero")
	}
}

func TestLtHashOrderIndependent(t *testing.T) {
	a := NewLtHash().Add("a").Add("b")
	b := NewLtHash().Add("b").Add("a")
	if !a.Equal(b) || a.Digest() != b.Digest() {
		t.Fatal("order changed the hash")
	}
}

func TestLtHashDistinguishesElements(t *testing.T) {
	if NewLtHash().Add("a").Equal(NewLtHash().Add("b")) {
		t.Fatal("a == b")
	}
}

func TestLtHashIsAMultiset(t *testing.T) {
	h := NewLtHash().Add("a").Add("a")
	if h.IsEmpty() {
		t.Fatal("double add cancelled out")
	}
	h.Remove("a")
	if !h.Equal(NewLtHash().Add("a")) {
		t.Fatal("remove of one copy is wrong")
	}
}

func TestLtHashStateRoundTrips(t *testing.T) {
	a := NewLtHash().Add("a").Add("b")
	r, err := LtHashFromState(a.State())
	if err != nil || !r.Equal(a) {
		t.Fatalf("resume failed: %v", err)
	}
	for _, s := range [][]byte{nil, {}} {
		h, err := LtHashFromState(s)
		if err != nil || !h.IsEmpty() {
			t.Fatalf("nullish state not empty: %v", err)
		}
	}
	if _, err := LtHashFromState(make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "must be 2048 bytes") {
		t.Fatalf("wrong-length state: %v", err)
	}
}

func TestLtHashDoesNotAlias(t *testing.T) {
	state := make([]byte, LtHashStateBytes)
	state[0] = 0xff
	h, _ := LtHashFromState(state)
	state[0] = 0
	if h.State()[0] != 0xff {
		t.Fatal("aliases input state")
	}
	h2 := NewLtHash().Add("a")
	out := h2.State()
	out[0] ^= 0xff
	if bytes.Equal(h2.State(), out) {
		t.Fatal("aliases output state")
	}
	original := NewLtHash().Add("a")
	staged, _ := LtHashFromState(original.State())
	staged.Add("b")
	if original.Equal(staged) || !original.Equal(NewLtHash().Add("a")) {
		t.Fatal("staged hash shares state")
	}
}

func TestLtHashDigest(t *testing.T) {
	d := NewLtHash().Digest()
	if hex.EncodeToString(d[:]) != "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad" {
		t.Fatalf("empty digest %x", d)
	}
	d = NewLtHash().Add("one").Add("two").Digest()
	if hex.EncodeToString(d[:]) != "ae05cb6d224379d9710c290c8529945c5b0e0fde9ead30b9699057ce701c63e7" {
		t.Fatalf("snapshot digest %x", d)
	}
}

func TestLtHashVectors(t *testing.T) {
	for i, v := range loadVectors(t).LtHash {
		h := NewLtHash()
		for _, op := range v.Ops {
			if op[0] == "+" {
				h.Add(op[1])
			} else {
				h.Remove(op[1])
			}
		}
		d := h.Digest()
		if hex.EncodeToString(d[:]) != v.Digest {
			t.Errorf("vector %d digest %x want %s", i, d, v.Digest)
		}
		if hex.EncodeToString(h.State()) != v.State {
			t.Errorf("vector %d state mismatch", i)
		}
		if h.IsEmpty() != v.Empty {
			t.Errorf("vector %d empty=%v", i, h.IsEmpty())
		}
	}
}
