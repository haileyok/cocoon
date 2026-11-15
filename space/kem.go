package space

import (
	"crypto/ecdh"
	"crypto/hpke"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// The shared secret a syncer and repo host use to MAC a response comes from
// the secret export feature of HPKE (RFC 9180 §6.2), in base mode with
// DHKEM(P-256, HKDF-SHA256) (0x0010), HKDF-SHA256 (0x0001) and the
// Export-only AEAD (0xFFFF), so nothing is encrypted:
//
//	enc, secret = SendExportBase(author_kem_public_key, info="atproto-mac", exporter_context="", L=32)
//	secret      = ReceiveExportBase(enc, author_kem_private_key, info="atproto-mac", exporter_context="", L=32)
//
// Follows @atproto/space's kem.ts, which spells out the same steps.

var hpkeInfo = []byte("atproto-mac")

const hpkeSecretLen = 32

// KemError is an invalid KEM key: not a P-256 did:key, or not a point on the
// curve (InvalidSpaceMac).
type KemError struct {
	Message string
	Cause   error
}

func (e *KemError) Error() string { return e.Message }
func (e *KemError) Unwrap() error { return e.Cause }

// Encapsulation is a syncer's side of one request: the ephemeral public key
// (HPKE's enc) as a did:key to send as the keyid of its MAC request, and the
// secret it shares with the repo host.
type Encapsulation struct {
	KeyShare     string
	SharedSecret []byte
}

// Encapsulate generates a fresh ephemeral key and derives a shared secret
// against the author's #atproto_kem key (a P-256 did:key). Use a new one for
// every request.
func Encapsulate(authorKemKey string) (*Encapsulation, error) {
	pub, err := p256DIDKey(authorKemKey)
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, &KemError{Message: "invalid KEM key", Cause: err}
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.ExportOnly(), hpkeInfo)
	if err != nil {
		return nil, err
	}
	secret, err := sender.Export("", hpkeSecretLen)
	if err != nil {
		return nil, err
	}
	// HPKE encodes enc uncompressed, did:key compressed.
	encPub, err := atcrypto.ParsePublicUncompressedBytesP256(enc)
	if err != nil {
		return nil, err
	}
	return &Encapsulation{KeyShare: encPub.DIDKey(), SharedSecret: secret}, nil
}

// Decapsulate derives, on the repo host, the shared secret for a syncer's
// key share using the author's KEM private key.
func Decapsulate(authorKem *atcrypto.PrivateKeyP256, keyShare string) ([]byte, error) {
	encPub, err := p256DIDKey(keyShare)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.P256().NewPrivateKey(authorKem.Bytes())
	if err != nil {
		return nil, &KemError{Message: "invalid KEM key", Cause: err}
	}
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, &KemError{Message: "invalid KEM key", Cause: err}
	}
	r, err := hpke.NewRecipient(encPub.Bytes(), sk, hpke.HKDFSHA256(), hpke.ExportOnly(), hpkeInfo)
	if err != nil {
		return nil, &KemError{Message: "invalid KEM key", Cause: err}
	}
	return r.Export("", hpkeSecretLen)
}

// p256DIDKey parses a P-256 did:key as an ECDH public key.
func p256DIDKey(didKey string) (*ecdh.PublicKey, error) {
	pub, err := atcrypto.ParsePublicDIDKey(didKey)
	if err != nil {
		return nil, &KemError{Message: "invalid KEM key", Cause: err}
	}
	p, ok := pub.(*atcrypto.PublicKeyP256)
	if !ok {
		return nil, &KemError{Message: "KEM key must be a P-256 did:key"}
	}
	k, err := ecdh.P256().NewPublicKey(p.UncompressedBytes())
	if err != nil {
		return nil, &KemError{Message: "invalid KEM key", Cause: err}
	}
	return k, nil
}
