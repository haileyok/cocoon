// Package space implements the primitives of ATProto Spaces (permissioned
// data), following @atproto/space in bluesky-social/atproto PR #5187 at
// 5b95b2f2: the set hash, signed space repo commits, space tokens, HTTP
// message signatures and the space repo CAR format.
package space

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"lukechampine.com/blake3"
)

const (
	ltHashLanes = 1024
	// LtHashStateBytes is the size of a persisted set hash state.
	LtHashStateBytes = ltHashLanes * 2
)

// LtHash is a homomorphic set hash. Each element expands (BLAKE3 XOF) to 1024
// little-endian u16 lanes, which are summed into the state mod 2^16, so the
// state depends only on the current multiset, not on insertion order.
type LtHash struct {
	lanes [ltHashLanes]uint16
}

// NewLtHash returns the empty set hash.
func NewLtHash() *LtHash { return &LtHash{} }

// LtHashFromState resumes a set hash from a persisted state. An empty state
// yields the empty hash.
func LtHashFromState(state []byte) (*LtHash, error) {
	h := &LtHash{}
	if len(state) == 0 {
		return h, nil
	}
	if len(state) != LtHashStateBytes {
		return nil, fmt.Errorf("LtHash state must be %d bytes, got %d", LtHashStateBytes, len(state))
	}
	for i := range h.lanes {
		h.lanes[i] = binary.LittleEndian.Uint16(state[i*2:])
	}
	return h, nil
}

func expand(element string) *[ltHashLanes]uint16 {
	hasher := blake3.New(32, nil)
	hasher.Write([]byte(element))
	var buf [LtHashStateBytes]byte
	if _, err := hasher.XOF().Read(buf[:]); err != nil {
		panic(err) // the XOF never fails
	}
	var lanes [ltHashLanes]uint16
	for i := range lanes {
		lanes[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return &lanes
}

// Add folds an element into the set.
func (h *LtHash) Add(element string) *LtHash {
	e := expand(element)
	for i := range h.lanes {
		h.lanes[i] += e[i]
	}
	return h
}

// Remove takes an element out of the set.
func (h *LtHash) Remove(element string) *LtHash {
	e := expand(element)
	for i := range h.lanes {
		h.lanes[i] -= e[i]
	}
	return h
}

// State returns a copy of the full state, for persistence.
func (h *LtHash) State() []byte {
	out := make([]byte, LtHashStateBytes)
	for i, l := range h.lanes {
		binary.LittleEndian.PutUint16(out[i*2:], l)
	}
	return out
}

// Digest is sha256 over the state.
func (h *LtHash) Digest() [32]byte { return sha256.Sum256(h.State()) }

// IsEmpty reports whether the state is all zeros.
func (h *LtHash) IsEmpty() bool {
	for _, l := range h.lanes {
		if l != 0 {
			return false
		}
	}
	return true
}

// Equal compares two states.
func (h *LtHash) Equal(o *LtHash) bool { return h.lanes == o.lanes }

// Clone returns an independent copy.
func (h *LtHash) Clone() *LtHash {
	c := *h
	return &c
}
