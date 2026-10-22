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

// STAR-lite v1 archives: a metadata header followed by key/value pairs until
// EOF.
//
//	[ magic | len | meta ] [ len | key | len | val ] [ len | key | len | val ] ...
//
// Each len is an unsigned varint in its shortest form. Applications define
// what keys and values mean in a profile named by the metadata's $type. See
// https://tangled.org/microcosm.blue/star/tree/main/v1-star and
// @atproto/space's star.ts.

// StarMagic opens every STAR archive.
var StarMagic = []byte{0x2a, 0x6c, 0x01, 0x00}

const (
	maxVarintBytes  = 6
	maxStarMetaLen  = 64 * 1024 * 1024
	maxStarKeyLen   = 64 * 1024 * 1024
	maxStarValueLen = 64 * 1024 * 1024 * 1024
)

// StarParseError is an archive that doesn't parse.
type StarParseError struct{ Message string }

func (e *StarParseError) Error() string { return e.Message }

func starErr(format string, args ...any) error {
	return &StarParseError{Message: fmt.Sprintf(format, args...)}
}

// StarWriter writes an archive's pairs after its header.
type StarWriter struct{ w io.Writer }

// WriteStar writes the magic bytes and the metadata, which must be a map with
// a string $type, as canonical DRISL.
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
	if err := sw.frame(key); err != nil {
		return err
	}
	return sw.frame(value)
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

	br          *bufio.Reader
	maxValueLen uint64
}

// ReadStar reads an archive's header. maxValueLen, if non-zero, lowers STAR's
// own value length limit. Lengths are checked before a frame is read, so an
// oversized frame is never buffered.
func ReadStar(r io.Reader, maxValueLen uint64) (*StarReader, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(StarMagic))
	if _, err := io.ReadFull(br, magic); err != nil || !bytes.Equal(magic, StarMagic) {
		return nil, starErr("invalid magic bytes")
	}
	metaBytes, err := readStarFrame(br, maxStarMetaLen)
	if err != nil {
		return nil, err
	}
	if metaBytes == nil {
		return nil, starErr("missing metadata")
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
	if maxValueLen == 0 || maxValueLen > maxStarValueLen {
		maxValueLen = maxStarValueLen
	}
	return &StarReader{Meta: meta, br: br, maxValueLen: maxValueLen}, nil
}

// Next returns the next pair, or io.EOF at the end of the archive. EOF is
// only allowed at a pair boundary.
func (sr *StarReader) Next() ([]byte, []byte, error) {
	// A lowered value limit bounds keys too, so a hostile archive can't force
	// a 64 MiB allocation from a short length prefix.
	key, err := readStarFrame(sr.br, min(sr.maxValueLen, maxStarKeyLen))
	if err != nil {
		return nil, nil, err
	}
	if key == nil {
		return nil, nil, io.EOF
	}
	value, err := readStarFrame(sr.br, sr.maxValueLen)
	if err != nil {
		return nil, nil, err
	}
	if value == nil {
		return nil, nil, starErr("missing value for key")
	}
	return key, value, nil
}

// readStarFrame returns nil at EOF before a frame starts.
func readStarFrame(br *bufio.Reader, maxLen uint64) ([]byte, error) {
	n, ok, err := readStarVarint(br)
	if err != nil || !ok {
		return nil, err
	}
	if n > maxLen {
		return nil, starErr("length %d exceeds limit of %d", n, maxLen)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(br, b); err != nil {
		return nil, starErr("unexpected end of archive")
	}
	return b, nil
}

// readStarVarint reads an unsigned varint in its shortest form; ok is false
// at EOF before its first byte.
func readStarVarint(br *bufio.Reader) (uint64, bool, error) {
	var v uint64
	for i := 0; i < maxVarintBytes; i++ {
		c, err := br.ReadByte()
		if err != nil {
			if err == io.EOF && i == 0 {
				return 0, false, nil
			}
			if err == io.EOF {
				return 0, false, starErr("unexpected end of archive")
			}
			return 0, false, err
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			// A final zero byte only pads the encoding, which STAR forbids.
			if c == 0 && i > 0 {
				return 0, false, starErr("non-canonical varint")
			}
			return v, true, nil
		}
	}
	return 0, false, starErr("varint too long")
}
