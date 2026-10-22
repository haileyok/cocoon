package space

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// The key encapsulation mechanism (KEM) that establishes the shared secret a
// syncer and repo host use to MAC a response: ECDH on P-256, with the secret
// derived as in DHKEM(P-256, HKDF-SHA256) from RFC 9180 §4.1. Follows
// @atproto/space's kem.ts.

// Encapsulation is a syncer's side of one request: the ephemeral public key
// to send as key_share, and the secret it shares with the repo host.
type Encapsulation struct {
	KeyShare     string
	SharedSecret []byte
}

// Encapsulate generates a fresh ephemeral keypair and derives a shared secret
// against the author's #atproto_kem key (a P-256 did:key). Use a new one for
// every request.
func Encapsulate(authorKemKey string) (*Encapsulation, error) {
	authorPub, err := p256DIDKey(authorKemKey)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dh, err := eph.ECDH(authorPub)
	if err != nil {
		return nil, &MacError{Message: "invalid KEM key", Cause: err}
	}
	ephPub, err := atcrypto.ParsePublicUncompressedBytesP256(eph.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	secret, err := deriveSharedSecret(dh, eph.PublicKey().Bytes(), authorPub.Bytes())
	if err != nil {
		return nil, err
	}
	return &Encapsulation{KeyShare: ephPub.DIDKey(), SharedSecret: secret}, nil
}

// Decapsulate derives, on the repo host, the shared secret for a syncer's
// key_share using the author's KEM private key.
func Decapsulate(authorKem *atcrypto.PrivateKeyP256, keyShare string) ([]byte, error) {
	syncerPub, err := p256DIDKey(keyShare)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.P256().NewPrivateKey(authorKem.Bytes())
	if err != nil {
		return nil, err
	}
	dh, err := priv.ECDH(syncerPub)
	if err != nil {
		return nil, &MacError{Message: "invalid KEM key", Cause: err}
	}
	return deriveSharedSecret(dh, syncerPub.Bytes(), priv.PublicKey().Bytes())
}

// kemPrefix is "HPKE-v1" || "KEM" || uint16be(0x0010), 0x0010 naming
// DHKEM(P-256, HKDF-SHA256).
var kemPrefix = []byte("HPKE-v1KEM\x00\x10")

// deriveSharedSecret takes uncompressed public keys (0x04 || x || y):
//
//	input  = prefix || "eae_prk" || dh
//	info   = uint16be(32) || prefix || "shared_secret" || syncer_pub || author_pub
//	secret = HKDF-SHA256(input, salt="", info, 32)
func deriveSharedSecret(dh, syncerPub, authorPub []byte) ([]byte, error) {
	input := append(append(append([]byte{}, kemPrefix...), "eae_prk"...), dh...)
	info := append([]byte{0, 32}, kemPrefix...)
	info = append(info, "shared_secret"...)
	info = append(info, syncerPub...)
	info = append(info, authorPub...)
	return hkdf.Key(sha256.New, input, nil, string(info), 32)
}

// p256DIDKey parses a P-256 did:key as an ECDH public key.
func p256DIDKey(didKey string) (*ecdh.PublicKey, error) {
	pub, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return nil, &MacError{Message: "invalid KEM key", Cause: err}
	}
	p, ok := pub.(*atcrypto.PublicKeyP256)
	if !ok {
		return nil, macErr("KEM key must be a P-256 did:key")
	}
	k, err := ecdh.P256().NewPublicKey(p.UncompressedBytes())
	if err != nil {
		return nil, &MacError{Message: "invalid KEM key", Cause: err}
	}
	return k, nil
}
