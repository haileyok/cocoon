package scopes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	cbg "github.com/whyrusleeping/cbor-gen"
)

// checkProofCAR runs before car.NewCarReader/Next: neither their header CBOR
// decoder nor CidFromReader bounds allocations by the available input bytes.
// Inspect slices without allocating from any wire-supplied length.
func checkProofCAR(proof []byte) error {
	for section := 0; len(proof) > 0; section++ {
		size, n := binary.Uvarint(proof)
		if n <= 0 {
			return fmt.Errorf("invalid CAR section length")
		}
		proof = proof[n:]
		if size > uint64(len(proof)) {
			return io.ErrUnexpectedEOF
		}
		data := proof[:int(size)]
		proof = proof[int(size):]
		if section != 0 {
			// These are the only repository block CIDs we accept. Checking
			// before CidFromReader also prevents its 32 MiB digest allocation
			// for a seven-byte section that advertises a nonexistent digest.
			for _, want := range [...]uint64{1, cid.DagCBOR, multihash.SHA2_256, 32} {
				value, n := binary.Uvarint(data)
				if n != 1 || value != want {
					return fmt.Errorf("invalid repository block CID prefix")
				}
				data = data[n:]
			}
			if len(data) < 32 {
				return io.ErrUnexpectedEOF
			}
			data = data[32:]
		}
		// Includes the header and every supplied block, even unknown fields
		// or blocks that will not be visited by the requested MST path.
		if err := checkProofCBOR(data); err != nil {
			return fmt.Errorf("section %d CBOR: %w", section, err)
		}
	}
	return nil
}

// checkProofCBOR is a resource preflight, not a general schema decoder. The
// existing cbor-gen header reader handles canonical definite-length headers
// using fixed scratch space. Its ValidateCBOR has no nesting limit, so keep a
// fixed stack of remaining items here instead of decoding values or recursing.
// Count tags as nesting too: otherwise unknown tagged values could evade the
// bound. Downstream decoders still validate data types and proof semantics.
func checkProofCBOR(data []byte) error {
	r := bytes.NewReader(data)
	cr := cbg.NewCborReader(r)
	var remaining [atdata.MAX_CBOR_NESTED_LEVELS + 1]uint64
	remaining[0] = 1
	depth := 0
	for depth >= 0 {
		if remaining[depth] == 0 {
			depth--
			continue
		}
		remaining[depth]--
		major, size, err := cr.ReadHeader()
		if err != nil {
			return err
		}
		var children uint64
		switch major {
		case cbg.MajUnsignedInt, cbg.MajNegativeInt:
			continue
		case cbg.MajOther:
			if size != 20 && size != 21 && size != 22 {
				return fmt.Errorf("unsupported CBOR simple value")
			}
			continue
		case cbg.MajByteString, cbg.MajTextString:
			if size > uint64(r.Len()) {
				return io.ErrUnexpectedEOF
			}
			if _, err := r.Seek(int64(size), io.SeekCurrent); err != nil {
				return err
			}
			continue
		case cbg.MajArray, cbg.MajMap:
			if size > atdata.MAX_CBOR_CONTAINER_LEN {
				return fmt.Errorf("CBOR container exceeds entry limit")
			}
			children = size
			if major == cbg.MajMap {
				children *= 2
			}
		case cbg.MajTag:
			children = 1
		default:
			return fmt.Errorf("unsupported CBOR major type")
		}
		if depth == atdata.MAX_CBOR_NESTED_LEVELS {
			return fmt.Errorf("CBOR nesting exceeds %d levels", atdata.MAX_CBOR_NESTED_LEVELS)
		}
		// Every child requires at least one byte. Check before an allocating
		// decoder can turn an impossible container length into a large slice.
		if children > uint64(r.Len()) {
			return io.ErrUnexpectedEOF
		}
		depth++
		remaining[depth] = children
	}
	if r.Len() != 0 {
		return fmt.Errorf("trailing CBOR data")
	}
	return nil
}
