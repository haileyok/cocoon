package space

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/bluesky-social/indigo/atproto/atdata"
)

// STAR archives: a metadata header, then key/value pairs each preceded by a
// 0x01 control byte, then a 0x00 control byte to end the archive.
//
//	[ magic | len | meta ] [ 1 | len | key | len | val ] [ 1 | len | key | len | val ] ... [ 0 ]
//
// Each len is an unsigned varint in its shortest form. Applications define
// what keys and values mean in a profile named by the metadata's $type. See
// https://dasl.ing/star.html and @atproto/star.

// StarMagic opens every STAR archive.
var StarMagic = []byte{0x2a, 0x6c, 0x01, 0x00}

const (
	starControlEnd  = 0x00
	starControlPair = 0x01

	maxVarintBytes = 9
)

// StarLimits bounds the lengths a reader accepts. STAR sets none of its own,
// so an unset (zero) limit is unlimited; set them when reading untrusted
// input. Lengths are checked before a frame is read, so an oversized frame is
// never buffered.
type StarLimits struct {
	MaxMetaLen  uint64
	MaxKeyLen   uint64
	MaxValueLen uint64
}

// StarParseError is an archive that doesn't parse.
type StarParseError struct{ Message string }

func (e *StarParseError) Error() string { return e.Message }

func starErr(format string, args ...any) error {
	return &StarParseError{Message: fmt.Sprintf(format, args...)}
}

// StarWriter writes an archive's pairs after its header.
type StarWriter struct{ w io.Writer }

// WriteStar writes the magic bytes and the metadata, which must be a map with
// a string $type, as canonical DRISL. Call Close once every pair is written.
func WriteStar(w io.Writer, meta map[string]any) (*StarWriter, error) {
	if _, ok := meta["$type"].(string); !ok {
		return nil, errors.New("star metadata must have a $type")
	}
	b, err := atdata.MarshalCBOR(meta)
	if err != nil {
		return nil, err
	}
	sw := &StarWriter{w: w}
	if _, err := w.Write(StarMagic); err != nil {
		return nil, err
	}
	if err := sw.frame(b); err != nil {
		return nil, err
	}
	return sw, nil
}

// WritePair writes one key/value pair.
func (sw *StarWriter) WritePair(key, value []byte) error {
	if _, err := sw.w.Write([]byte{starControlPair}); err != nil {
		return err
	}
	if err := sw.frame(key); err != nil {
		return err
	}
	return sw.frame(value)
}

// Close ends the archive.
func (sw *StarWriter) Close() error {
	_, err := sw.w.Write([]byte{starControlEnd})
	return err
}

func (sw *StarWriter) frame(b []byte) error {
	if _, err := sw.w.Write(binary.AppendUvarint(nil, uint64(len(b)))); err != nil {
		return err
	}
	_, err := sw.w.Write(b)
	return err
}

// StarReader reads an archive's pairs lazily, after its header.
type StarReader struct {
	Meta map[string]any

	br     *bufio.Reader
	limits StarLimits
	done   bool
}

// ReadStar reads an archive's header.
func ReadStar(r io.Reader, limits StarLimits) (*StarReader, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(StarMagic))
	if _, err := io.ReadFull(br, magic); err != nil || !bytes.Equal(magic, StarMagic) {
		return nil, starErr("invalid magic bytes")
	}
	metaBytes, err := readStarFrame(br, limits.MaxMetaLen)
	if err != nil {
		return nil, err
	}
	meta, err := atdata.UnmarshalCBOR(metaBytes)
	if err != nil {
		return nil, starErr("invalid metadata: %v", err)
	}
	if _, ok := meta["$type"].(string); !ok {
		return nil, starErr("metadata must be a map with a $type")
	}
	// The decoder accepts some non-canonical forms, so check the metadata
	// re-encodes to the same bytes.
	if re, err := atdata.MarshalCBOR(meta); err != nil || !bytes.Equal(re, metaBytes) {
		return nil, starErr("metadata is not canonical DRISL")
	}
	return &StarReader{Meta: meta, br: br, limits: limits}, nil
}

// Next returns the next pair, or io.EOF once the end byte has been read and
// nothing follows it. An archive that ends any other way is an error.
func (sr *StarReader) Next() ([]byte, []byte, error) {
	if sr.done {
		return nil, nil, io.EOF
	}
	control, err := sr.br.ReadByte()
	if err != nil {
		if err == io.EOF {
			return nil, nil, starErr("unexpected end of archive")
		}
		return nil, nil, err
	}
	switch control {
	case starControlEnd:
		if _, err := sr.br.ReadByte(); err != io.EOF {
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, starErr("unexpected bytes after end of archive")
		}
		sr.done = true
		return nil, nil, io.EOF
	case starControlPair:
	default:
		return nil, nil, starErr("invalid control byte: %d", control)
	}
	key, err := readStarFrame(sr.br, sr.limits.MaxKeyLen)
	if err != nil {
		return nil, nil, err
	}
	value, err := readStarFrame(sr.br, sr.limits.MaxValueLen)
	if err != nil {
		return nil, nil, err
	}
	return key, value, nil
}

// readStarFrame reads a length-prefixed frame. A zero limit is no limit.
func readStarFrame(br *bufio.Reader, maxLen uint64) ([]byte, error) {
	n, err := readStarVarint(br)
	if err != nil {
		return nil, err
	}
	if maxLen != 0 && n > maxLen {
		return nil, starErr("length %d exceeds limit of %d", n, maxLen)
	}
	// Read in bounded steps rather than trusting the length with one
	// allocation, so a short archive claiming a huge frame costs little.
	const step = 1 << 20
	b := make([]byte, 0, min(n, step))
	for uint64(len(b)) < n {
		chunk := min(n-uint64(len(b)), step)
		off := len(b)
		b = append(b, make([]byte, chunk)...)
		if _, err := io.ReadFull(br, b[off:]); err != nil {
			return nil, starErr("unexpected end of archive")
		}
	}
	return b, nil
}

// readStarVarint reads an unsigned varint in its shortest form.
func readStarVarint(br *bufio.Reader) (uint64, error) {
	var v uint64
	for i := 0; i < maxVarintBytes; i++ {
		c, err := br.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, starErr("unexpected end of archive")
			}
			return 0, err
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			// A final zero byte only pads the encoding, which STAR forbids.
			if c == 0 && i > 0 {
				return 0, starErr("non-canonical varint")
			}
			return v, nil
		}
	}
	return 0, starErr("varint too long")
}
