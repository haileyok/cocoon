package space

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	cbor "github.com/ipfs/go-ipld-cbor"
)

const (
	// CommitVersion is the signedCommit format version.
	CommitVersion uint64 = 1
	// COMMIT_VERSION is retained as a reference-compatible spelling.
	COMMIT_VERSION = CommitVersion

	CommitHashBytes = sha256.Size
	CommitIKMBytes  = sha256.Size
	CommitMACBytes  = sha256.Size

	// MaxCommitContextFieldBytes is the largest value representable by a u16
	// context length prefix.
	MaxCommitContextFieldBytes = int(^uint16(0))
	// @atproto/crypto and Indigo use compact secp256k1 r||s signatures.
	MaxCommitSignatureBytes = 64
)

var commitDomain = []byte("atproto-space-v1")

// CommitContext is the data bound into a signed commit. Author is the
// author's DID and Space is the canonical space URI.
type CommitContext struct {
	Space  string
	Author string
	Rev    string
}

// CommitCtx is the short spelling used by the pinned TypeScript reference.
type CommitCtx = CommitContext

// SignedCommit is the signedCommit Lexicon object. It is serialized as a
// canonical DAG-CBOR map with keys ver/hash/ikm/sig/mac/rev.
type SignedCommit struct {
	Ver  uint64 `json:"ver"`
	Hash []byte `json:"hash"`
	IKM  []byte `json:"ikm"`
	Sig  []byte `json:"sig"`
	MAC  []byte `json:"mac"`
	Rev  string `json:"rev"`
}

type lexBytesJSON struct {
	Bytes string `json:"$bytes"`
}

type signedCommitJSON struct {
	Ver  uint64       `json:"ver"`
	Hash lexBytesJSON `json:"hash"`
	IKM  lexBytesJSON `json:"ikm"`
	Sig  lexBytesJSON `json:"sig"`
	MAC  lexBytesJSON `json:"mac"`
	Rev  string       `json:"rev"`
}

func encodeLexBytesJSON(value []byte) lexBytesJSON {
	return lexBytesJSON{Bytes: base64.RawURLEncoding.EncodeToString(value)}
}

func decodeLexBytesJSON(value lexBytesJSON) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value.Bytes)
}

// MarshalJSON uses the atproto Lexicon bytes encoding. JSON bytes are
// {$bytes:<raw-base64url>}, not encoding/json's default base64 string.
func (c SignedCommit) MarshalJSON() ([]byte, error) {
	return json.Marshal(signedCommitJSON{
		Ver:  c.Ver,
		Hash: encodeLexBytesJSON(c.Hash),
		IKM:  encodeLexBytesJSON(c.IKM),
		Sig:  encodeLexBytesJSON(c.Sig),
		MAC:  encodeLexBytesJSON(c.MAC),
		Rev:  c.Rev,
	})
}

func (c *SignedCommit) UnmarshalJSON(data []byte) error {
	var wire signedCommitJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	hash, err := decodeLexBytesJSON(wire.Hash)
	if err != nil {
		return err
	}
	ikm, err := decodeLexBytesJSON(wire.IKM)
	if err != nil {
		return err
	}
	sig, err := decodeLexBytesJSON(wire.Sig)
	if err != nil {
		return err
	}
	mac, err := decodeLexBytesJSON(wire.MAC)
	if err != nil {
		return err
	}
	*c = SignedCommit{Ver: wire.Ver, Hash: hash, IKM: ikm, Sig: sig, MAC: mac, Rev: wire.Rev}
	return nil
}

// CommitSigner and CommitVerifier are small adapters satisfied by Indigo's
// atcrypto.PrivateKey and atcrypto.PublicKey. They also allow callers to adapt
// a persistence model without importing that model into this package.
type CommitSigner interface {
	HashAndSign(content []byte) ([]byte, error)
}

type CommitVerifier interface {
	HashAndVerify(content, sig []byte) error
}

// SignOptions makes signing deterministic in tests. IKM must be exactly 32
// bytes when supplied. Otherwise Rand is read for a fresh IKM; nil uses
// crypto/rand.Reader.
type SignOptions struct {
	IKM  []byte
	Rand io.Reader
}

type CommitSignOptions = SignOptions

// EncodeCommitContext implements the pinned context encoding:
//
//	"atproto-space-v1" || u16be(len(space)) || space
//	|| u16be(len(author)) || author
//	|| u16be(len(rev)) || rev
//	|| u16be(len(ikm)) || ikm
//
// Lengths are UTF-8 byte lengths.
func EncodeCommitContext(ctx CommitContext, ikm []byte) ([]byte, error) {
	fields := [][]byte{[]byte(ctx.Space), []byte(ctx.Author), []byte(ctx.Rev), ikm}
	size := len(commitDomain)
	for _, field := range fields {
		if len(field) > MaxCommitContextFieldBytes {
			return nil, fmt.Errorf("commit context field exceeds uint16 length prefix: %d", len(field))
		}
		size += 2 + len(field)
	}
	out := make([]byte, size)
	copy(out, commitDomain)
	offset := len(commitDomain)
	for _, field := range fields {
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(field)))
		offset += 2
		copy(out[offset:], field)
		offset += len(field)
	}
	return out, nil
}

func EncodeCommitCtx(ctx CommitContext, ikm []byte) ([]byte, error) {
	return EncodeCommitContext(ctx, ikm)
}

// RepoCommit tracks the LtHash of a repo's collection/rkey/CID set.
type RepoCommit struct {
	SetHash *LtHash
}

func NewRepoCommit() *RepoCommit {
	h, _ := NewLtHash()
	return &RepoCommit{SetHash: h}
}

func (r *RepoCommit) ensureHash() *LtHash {
	if r.SetHash == nil {
		r.SetHash, _ = NewLtHash()
	}
	return r.SetHash
}

// Add incorporates a record identity. The interface permits cid.Cid and other
// CID adapters without coupling the value helper to one concrete CID type.
func (r *RepoCommit) Add(collection, rkey string, recordCID interface{ String() string }) *RepoCommit {
	r.ensureHash().Add(FormatElement(collection, rkey, recordCID.String()))
	return r
}

func (r *RepoCommit) Remove(collection, rkey string, recordCID interface{ String() string }) *RepoCommit {
	r.ensureHash().Remove(FormatElement(collection, rkey, recordCID.String()))
	return r
}

func (r *RepoCommit) Hash() []byte {
	if r == nil {
		return nil
	}
	return r.ensureHash().Digest()
}

// Matches only compares the set hash; authenticate the commit first.
func (r *RepoCommit) Matches(commit SignedCommit) bool {
	return bytes.Equal(r.Hash(), commit.Hash)
}

// Sign signs only the encoded context, then MACs the current repo hash.
func (r *RepoCommit) Sign(ctx CommitContext, signer CommitSigner, opts ...SignOptions) (SignedCommit, error) {
	return signHash(r.Hash(), ctx, signer, opts...)
}

// SignCommit signs a precomputed repo hash. RepoCommit.Sign is preferred when
// the caller has the record set available.
func SignCommit(hash []byte, ctx CommitContext, signer CommitSigner, opts ...SignOptions) (SignedCommit, error) {
	return signHash(hash, ctx, signer, opts...)
}

func signHash(hash []byte, ctx CommitContext, signer CommitSigner, opts ...SignOptions) (SignedCommit, error) {
	if signer == nil {
		return SignedCommit{}, errors.New("commit signer is nil")
	}
	if len(hash) != CommitHashBytes {
		return SignedCommit{}, fmt.Errorf("commit hash must be %d bytes, got %d", CommitHashBytes, len(hash))
	}
	if len(opts) > 1 {
		return SignedCommit{}, errors.New("at most one sign options value is allowed")
	}
	var options SignOptions
	if len(opts) == 1 {
		options = opts[0]
	}
	ikm := make([]byte, CommitIKMBytes)
	if options.IKM != nil {
		if len(options.IKM) != CommitIKMBytes {
			return SignedCommit{}, fmt.Errorf("commit IKM must be %d bytes, got %d", CommitIKMBytes, len(options.IKM))
		}
		copy(ikm, options.IKM)
	} else {
		reader := options.Rand
		if reader == nil {
			reader = rand.Reader
		}
		if _, err := io.ReadFull(reader, ikm); err != nil {
			return SignedCommit{}, fmt.Errorf("generate commit IKM: %w", err)
		}
	}
	ctxBytes, err := EncodeCommitContext(ctx, ikm)
	if err != nil {
		return SignedCommit{}, err
	}
	sig, err := signer.HashAndSign(ctxBytes)
	if err != nil {
		return SignedCommit{}, fmt.Errorf("sign commit context: %w", err)
	}
	if len(sig) != MaxCommitSignatureBytes {
		return SignedCommit{}, fmt.Errorf("commit signature must be %d bytes, got %d", MaxCommitSignatureBytes, len(sig))
	}
	mac, err := ComputeCommitMAC(ikm, ctxBytes, hash)
	if err != nil {
		return SignedCommit{}, err
	}
	return SignedCommit{
		Ver:  CommitVersion,
		Hash: append([]byte(nil), hash...),
		IKM:  ikm,
		Sig:  append([]byte(nil), sig...),
		MAC:  mac,
		Rev:  ctx.Rev,
	}, nil
}

// ComputeCommitMAC follows the pinned @atproto/crypto helper exactly:
// hkdfSha256(ikm, ctx) is HKDF-Expand-only with ikm directly as the SHA-256
// PRK and ctx as info, followed by HMAC-SHA256(key, hash). It intentionally
// does not use x/crypto/hkdf, which performs an Extract step first.
func ComputeCommitMAC(ikm, ctx, hash []byte) ([]byte, error) {
	if len(ikm) != CommitIKMBytes {
		return nil, fmt.Errorf("commit IKM must be %d bytes, got %d", CommitIKMBytes, len(ikm))
	}
	if len(hash) != CommitHashBytes {
		return nil, fmt.Errorf("commit hash must be %d bytes, got %d", CommitHashBytes, len(hash))
	}
	key, err := hkdfExpandSHA256(ikm, ctx, CommitMACBytes)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(hash)
	return mac.Sum(nil), nil
}

func CommitMAC(ikm, ctx, hash []byte) []byte {
	mac, err := ComputeCommitMAC(ikm, ctx, hash)
	if err != nil {
		return nil
	}
	return mac
}

func hkdfExpandSHA256(prk, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*sha256.Size {
		return nil, errors.New("HKDF-SHA256 output length is out of range")
	}
	out := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		out = append(out, previous...)
	}
	return out[:length], nil
}

func (c SignedCommit) Validate() error {
	if c.Ver != CommitVersion {
		return fmt.Errorf("unsupported commit version %d", c.Ver)
	}
	if len(c.Hash) != CommitHashBytes {
		return fmt.Errorf("commit hash must be %d bytes, got %d", CommitHashBytes, len(c.Hash))
	}
	if len(c.IKM) != CommitIKMBytes {
		return fmt.Errorf("commit IKM must be %d bytes, got %d", CommitIKMBytes, len(c.IKM))
	}
	if len(c.MAC) != CommitMACBytes {
		return fmt.Errorf("commit MAC must be %d bytes, got %d", CommitMACBytes, len(c.MAC))
	}
	if len(c.Sig) != MaxCommitSignatureBytes {
		return fmt.Errorf("commit signature must be %d bytes, got %d", MaxCommitSignatureBytes, len(c.Sig))
	}
	if len([]byte(c.Rev)) > MaxCommitContextFieldBytes {
		return errors.New("commit revision exceeds uint16 length prefix")
	}
	return nil
}

// EncodeSignedCommit returns canonical DAG-CBOR bytes for c.
func EncodeSignedCommit(c SignedCommit) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return cbor.Encode(map[string]interface{}{
		"ver":  c.Ver,
		"hash": append([]byte(nil), c.Hash...),
		"ikm":  append([]byte(nil), c.IKM...),
		"sig":  append([]byte(nil), c.Sig...),
		"mac":  append([]byte(nil), c.MAC...),
		"rev":  c.Rev,
	})
}

// DecodeSignedCommit parses and validates canonical DAG-CBOR bytes. Re-encoding
// rejects non-canonical map encodings and unknown fields.
func DecodeSignedCommit(data []byte) (SignedCommit, error) {
	var raw map[string]interface{}
	if err := cbor.DecodeInto(data, &raw); err != nil {
		return SignedCommit{}, fmt.Errorf("decode signed commit: %w", err)
	}
	if len(raw) != 6 {
		return SignedCommit{}, errors.New("signed commit must contain exactly six fields")
	}
	for _, name := range []string{"ver", "hash", "ikm", "sig", "mac", "rev"} {
		if _, ok := raw[name]; !ok {
			return SignedCommit{}, fmt.Errorf("signed commit missing %q", name)
		}
	}
	ver, ok := asUint64(raw["ver"])
	if !ok {
		return SignedCommit{}, errors.New("signed commit ver is not an unsigned integer")
	}
	hash, ok := raw["hash"].([]byte)
	if !ok {
		return SignedCommit{}, errors.New("signed commit hash is not bytes")
	}
	ikm, ok := raw["ikm"].([]byte)
	if !ok {
		return SignedCommit{}, errors.New("signed commit ikm is not bytes")
	}
	sig, ok := raw["sig"].([]byte)
	if !ok {
		return SignedCommit{}, errors.New("signed commit sig is not bytes")
	}
	mac, ok := raw["mac"].([]byte)
	if !ok {
		return SignedCommit{}, errors.New("signed commit mac is not bytes")
	}
	rev, ok := raw["rev"].(string)
	if !ok {
		return SignedCommit{}, errors.New("signed commit rev is not a string")
	}
	commit := SignedCommit{Ver: ver, Hash: append([]byte(nil), hash...), IKM: append([]byte(nil), ikm...), Sig: append([]byte(nil), sig...), MAC: append([]byte(nil), mac...), Rev: rev}
	canonical, err := EncodeSignedCommit(commit)
	if err != nil {
		return SignedCommit{}, err
	}
	if !bytes.Equal(canonical, data) {
		return SignedCommit{}, errors.New("signed commit is not canonical DAG-CBOR")
	}
	return commit, nil
}

func asUint64(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint8:
		return uint64(v), true
	case int:
		return uint64(v), v >= 0
	case int64:
		return uint64(v), v >= 0
	case int32:
		return uint64(v), v >= 0
	default:
		return 0, false
	}
}

// VerifyCommit verifies version/revision, MAC, and an atproto DID-key
// signature. It returns false for malformed or unauthenticated commits.
func VerifyCommit(commit SignedCommit, ctx CommitContext, didKey string) bool {
	verifier, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return false
	}
	return VerifyCommitWithVerifier(commit, ctx, verifier)
}

func VerifyCommitWithVerifier(commit SignedCommit, ctx CommitContext, verifier CommitVerifier) bool {
	if verifier == nil || commit.Rev != ctx.Rev {
		return false
	}
	if err := commit.Validate(); err != nil {
		return false
	}
	ctxBytes, err := EncodeCommitContext(ctx, commit.IKM)
	if err != nil {
		return false
	}
	mac, err := ComputeCommitMAC(commit.IKM, ctxBytes, commit.Hash)
	if err != nil || !hmac.Equal(mac, commit.MAC) {
		return false
	}
	return verifier.HashAndVerify(ctxBytes, commit.Sig) == nil
}

func VerifyCommitWithPublicKey(commit SignedCommit, ctx CommitContext, verifier CommitVerifier) bool {
	return VerifyCommitWithVerifier(commit, ctx, verifier)
}

// VerifyCommitError is an error-returning companion for trust boundaries.
func VerifyCommitError(commit SignedCommit, ctx CommitContext, didKey string) error {
	if err := commit.Validate(); err != nil {
		return err
	}
	if commit.Rev != ctx.Rev {
		return errors.New("commit revision does not match context")
	}
	verifier, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return fmt.Errorf("parse commit DID key: %w", err)
	}
	ctxBytes, err := EncodeCommitContext(ctx, commit.IKM)
	if err != nil {
		return err
	}
	mac, err := ComputeCommitMAC(commit.IKM, ctxBytes, commit.Hash)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, commit.MAC) {
		return errors.New("commit MAC verification failed")
	}
	if err := verifier.HashAndVerify(ctxBytes, commit.Sig); err != nil {
		return fmt.Errorf("commit signature verification failed: %w", err)
	}
	return nil
}
