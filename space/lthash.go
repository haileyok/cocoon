package space

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"lukechampine.com/blake3"
)

const (
	// LtHashLanes is the number of uint16 lanes in an LtHash state.
	LtHashLanes = 1024
	// LtHashStateBytes is the serialized state size.
	LtHashStateBytes = LtHashLanes * 2

	// LTHASH_STATE_BYTES is retained as a name matching the reference package.
	LTHASH_STATE_BYTES = LtHashStateBytes
	// StateBytes is a concise alias for LtHashStateBytes.
	StateBytes = LtHashStateBytes
)

// LtHash is a homomorphic set hash. Each element expands to 1024 little-endian
// uint16 lanes, which are summed into the state modulo 2^16. Consequently,
// addition and subtraction commute and the state depends only on the current
// set (assuming each set member is added at most once).
type LtHash struct {
	state [LtHashStateBytes]byte
}

// NewLtHash creates an empty hash, or copies one serialized state. A nil state
// is equivalent to an omitted state; a non-nil state must be exactly 2048
// bytes. The variadic form permits both NewLtHash() and NewLtHash(state).
func NewLtHash(states ...[]byte) (*LtHash, error) {
	if len(states) > 1 {
		return nil, fmt.Errorf("LtHash accepts at most one state, got %d", len(states))
	}
	hash := new(LtHash)
	if len(states) == 0 || states[0] == nil {
		return hash, nil
	}
	if len(states[0]) != LtHashStateBytes {
		return nil, fmt.Errorf("LtHash state must be %d bytes, got %d", LtHashStateBytes, len(states[0]))
	}
	copy(hash.state[:], states[0])
	return hash, nil
}

// NewLtHashFromState is an explicit spelling for constructing from serialized
// state.
func NewLtHashFromState(state []byte) (*LtHash, error) { return NewLtHash(state) }

// LtHashFromState is an alias for NewLtHashFromState.
func LtHashFromState(state []byte) (*LtHash, error) { return NewLtHash(state) }

// Add incorporates element into the state and returns h for convenient
// chaining. Lane arithmetic wraps modulo 2^16.
func (h *LtHash) Add(element string) *LtHash {
	expanded := ExpandElement(element)
	for i := 0; i < LtHashLanes; i++ {
		offset := i * 2
		current := binary.LittleEndian.Uint16(h.state[offset : offset+2])
		addition := binary.LittleEndian.Uint16(expanded[offset : offset+2])
		binary.LittleEndian.PutUint16(h.state[offset:offset+2], current+addition)
	}
	return h
}

// Remove subtracts element from the state and returns h for convenient
// chaining. Lane arithmetic wraps modulo 2^16.
func (h *LtHash) Remove(element string) *LtHash {
	expanded := ExpandElement(element)
	for i := 0; i < LtHashLanes; i++ {
		offset := i * 2
		current := binary.LittleEndian.Uint16(h.state[offset : offset+2])
		subtraction := binary.LittleEndian.Uint16(expanded[offset : offset+2])
		binary.LittleEndian.PutUint16(h.state[offset:offset+2], current-subtraction)
	}
	return h
}

// State returns a defensive copy of the serialized state.
func (h *LtHash) State() []byte {
	state := make([]byte, LtHashStateBytes)
	copy(state, h.state[:])
	return state
}

// Digest returns SHA-256 of the serialized state.
func (h *LtHash) Digest() []byte {
	digest := sha256.Sum256(h.state[:])
	return digest[:]
}

// IsEmpty reports whether every state lane is zero.
func (h *LtHash) IsEmpty() bool {
	for _, b := range h.state {
		if b != 0 {
			return false
		}
	}
	return true
}

// Equals reports whether h and other have identical states.
func (h *LtHash) Equals(other *LtHash) bool {
	if h == nil || other == nil {
		return h == other
	}
	return h.state == other.state
}

// Equal is an alias for Equals.
func (h *LtHash) Equal(other *LtHash) bool { return h.Equals(other) }

// ExpandElement expands an element to the exact 2048-byte BLAKE3 XOF output
// used as the lane vector by LtHash. The returned bytes are independent of any
// internal hash state.
func ExpandElement(element string) []byte {
	hasher := blake3.New(LtHashStateBytes, nil)
	_, _ = hasher.Write([]byte(element))
	output := make([]byte, LtHashStateBytes)
	_, _ = io.ReadFull(hasher.XOF(), output)
	return output
}

// FormatElement formats a record identity for inclusion in an LtHash:
// {collection}/{rkey}/{cid}.
func FormatElement(collection, rkey, cid string) string {
	return collection + "/" + rkey + "/" + cid
}

// FormatSetHashElement is an alias matching the reference helper's name.
func FormatSetHashElement(collection, rkey, cid string) string {
	return FormatElement(collection, rkey, cid)
}
