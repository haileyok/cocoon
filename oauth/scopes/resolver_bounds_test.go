package scopes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/identity"
	carutil "github.com/ipld/go-car/util"
)

func proofIdentity(pub string) *identity.Identity {
	return &identity.Identity{DID: "did:plc:abcdefghijklmnopqrstuvwx", Keys: map[string]identity.VerificationMethod{
		"atproto": {Type: "Multikey", PublicKeyMultibase: pub},
	}}
}

// Add an unknown field without asking a generic encoder to process hostile
// nesting. Existing fixture CIDs/signatures are built over these raw bytes.
func proofUnknownField(t *testing.T, raw, value []byte) []byte {
	t.Helper()
	if len(raw) == 0 || raw[0] < 0xa0 || raw[0] >= 0xb7 {
		t.Fatal("expected small definite-length map")
	}
	out := append([]byte(nil), raw...)
	out[0]++
	out = append(out, 0x61, 'z')
	return append(out, value...)
}

func TestLexiconProofCBORBounds(t *testing.T) {
	for _, part := range []string{"header", "commit", "MST", "record"} {
		for name, value := range map[string][]byte{
			"depth":        append(bytes.Repeat([]byte{0x81}, 128), 0xf6),
			"array length": {0x9a, 2, 0, 0, 0},
			"map length":   {0xba, 2, 0, 0, 0},
			"byte length":  {0x5a, 2, 0, 0, 0},
			"text length":  {0x7a, 2, 0, 0, 0},
		} {
			t.Run(part+"/"+name, func(t *testing.T) {
				proof, pub := lexiconProofFixtureWithCBOR(t, "permission-set", "valid", func(where string, raw []byte) []byte {
					if where == part {
						return proofUnknownField(t, raw, value)
					}
					return raw
				})
				_, err := verifyLexiconProof(t.Context(), proof, proofIdentity(pub), "com.example.lexicon")
				// Eventual EOF, decoder errors, or a valid signature are not
				// enough: rejection must precede all allocating CBOR decoders.
				if err == nil || !strings.Contains(err.Error(), "CAR preflight") {
					t.Fatalf("not rejected by bounded preflight: %v", err)
				}
			})
		}
	}
}

func TestLexiconProofCIDDigestAllocation(t *testing.T) {
	proof, pub := lexiconProofFixture(t, "permission-set", "valid")
	size, n := binary.Uvarint(proof)
	var out bytes.Buffer
	out.Write(proof[:n+int(size)]) // valid CAR header
	// Seven-byte section; CidFromReader used to allocate 32 MiB for the
	// advertised digest before discovering that none of it is present.
	badCID := []byte{1, 0x71, 0x12}
	badCID = binary.AppendUvarint(badCID, 32<<20)
	if err := carutil.LdWrite(&out, badCID); err != nil {
		t.Fatal(err)
	}
	ident := proofIdentity(pub)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := verifyLexiconProof(t.Context(), out.Bytes(), ident, "com.example.lexicon")
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("%d-byte proof allocated %d bytes", out.Len(), allocated)
	if err == nil || !strings.Contains(err.Error(), "CAR preflight") {
		t.Errorf("not rejected before CID decoding: %v", err)
	}
	if allocated > 1<<20 {
		t.Errorf("digest allocation escaped bound: %d bytes", allocated)
	}
}

func TestLexiconProofCBORNestingBoundary(t *testing.T) {
	for _, levels := range []int{31, 32, 200000} {
		t.Run(fmt.Sprint(levels), func(t *testing.T) {
			proof, pub := lexiconProofFixtureWithCBOR(t, "permission-set", "valid", func(part string, raw []byte) []byte {
				if part == "record" {
					return proofUnknownField(t, raw, append(bytes.Repeat([]byte{0x81}, levels), 0xf6))
				}
				return raw
			})
			if len(proof) > atdata.MAX_CBOR_RECORD_SIZE {
				t.Fatal("fixture must fit below the existing record size limit")
			}
			ident := proofIdentity(pub)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := verifyLexiconProof(t.Context(), proof, ident, "com.example.lexicon")
			runtime.ReadMemStats(&after)
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("%d-byte signed proof (%d arrays plus record map) allocated %d bytes", len(proof), levels, allocated)
			if levels == 31 {
				if err != nil {
					t.Fatalf("32-level document rejected: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "CAR preflight") || !strings.Contains(err.Error(), "nesting exceeds 32") {
					t.Errorf("not rejected before generic decoding: %v", err)
				}
				if allocated > 1<<20 {
					t.Errorf("nested value allocation escaped bound: %d bytes", allocated)
				}
			}
		})
	}
}

func TestProofCBORPreflight(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty array": {0x80}, "empty map": {0xa0}, "empty text": {0x60}, "empty bytes": {0x40},
		"siblings":  {0x83, 0x81, 0x80, 0xa1, 0x61, 'k', 0xf6, 0xf5},
		"32 arrays": append(bytes.Repeat([]byte{0x81}, 32), 0xf6),
		"32 tags":   append(bytes.Repeat([]byte{0xd8, 42}, 32), 0x40),
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkProofCBOR(data); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, data := range map[string][]byte{
		"empty": nil, "truncated child": {0x81}, "trailing bytes": {0xa0, 0xf6},
		"indefinite array": {0x9f, 0xff}, "indefinite map": {0xbf, 0xff},
		"indefinite text": {0x7f, 0xff}, "indefinite bytes": {0x5f, 0xff},
		"missing map value": {0xa1, 0x61, 'k'}, "truncated text": {0x62, 'x'},
		"truncated bytes": {0x42, 0}, "unsupported float": {0xf9, 0x3c, 0},
		"33 arrays":       append(bytes.Repeat([]byte{0x81}, 33), 0xf6),
		"33 empty arrays": append(bytes.Repeat([]byte{0x81}, 32), 0x80),
		"33 tags":         append(bytes.Repeat([]byte{0xd8, 42}, 33), 0x40),
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkProofCBOR(data); err == nil {
				t.Fatal("invalid or unbounded CBOR accepted")
			}
		})
	}
}
