// Package yubiotp validates Yubico OTPs locally, without YubiCloud.
//
// A Yubico OTP is an optional modhex public identity followed by 32 modhex
// characters: one AES-128-ECB encrypted 16-byte block. The server must hold
// the AES key the YubiKey slot was programmed with (for example via
// `ykman otp yubiotp`). Fields inside the block are little-endian; see
// https://developers.yubico.com/OTP/OTPs_Explained.html.
package yubiotp

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	KeySize        = 16
	blockChars     = 32
	maxPublicChars = 32
	crcOKResidue   = 0xf0b8
	modhexAlphabet = "cbdefghijklnrtuv"
)

var (
	ErrFormat = errors.New("yubiotp: malformed otp")
	ErrBadCRC = errors.New("yubiotp: checksum mismatch (wrong key or corrupt otp)")
)

// OTP is a decrypted Yubico OTP.
type OTP struct {
	PublicID   string
	PrivateID  [6]byte
	Counter    uint16 // session counter, with the caps-lock flag removed
	SessionUse uint8
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// LooksLikeOTP reports whether s has the shape of a Yubico OTP, so callers
// can tell it apart from other kinds of codes before trying any keys.
func LooksLikeOTP(s string) bool {
	s = normalize(s)
	if len(s) < blockChars || len(s) > blockChars+maxPublicChars || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(modhexAlphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

func ModhexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, ErrFormat
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := strings.IndexByte(modhexAlphabet, s[i])
		lo := strings.IndexByte(modhexAlphabet, s[i+1])
		if hi < 0 || lo < 0 {
			return nil, ErrFormat
		}
		out[i/2] = byte(hi<<4 | lo)
	}
	return out, nil
}

func modhexEncode(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(modhexAlphabet[c>>4])
		sb.WriteByte(modhexAlphabet[c&0x0f])
	}
	return sb.String()
}

func crc16(b []byte) uint16 {
	crc := uint16(0xffff)
	for _, c := range b {
		crc ^= uint16(c)
		for i := 0; i < 8; i++ {
			j := crc & 1
			crc >>= 1
			if j != 0 {
				crc ^= 0x8408
			}
		}
	}
	return crc
}

// PublicID returns the public identity prefix of an OTP without decrypting.
func PublicID(s string) string {
	s = normalize(s)
	if len(s) < blockChars {
		return ""
	}
	return s[:len(s)-blockChars]
}

// Parse decrypts and checksums an OTP with key. It does not check the
// private ID or replay; callers compare those against stored state.
func Parse(s string, key []byte) (OTP, error) {
	if len(key) != KeySize {
		return OTP{}, fmt.Errorf("yubiotp: key must be %d bytes", KeySize)
	}
	s = normalize(s)
	if !LooksLikeOTP(s) {
		return OTP{}, ErrFormat
	}
	ct, err := ModhexDecode(s[len(s)-blockChars:])
	if err != nil {
		return OTP{}, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return OTP{}, err
	}
	var pt [16]byte
	c.Decrypt(pt[:], ct)
	if crc16(pt[:]) != crcOKResidue {
		return OTP{}, ErrBadCRC
	}

	var o OTP
	o.PublicID = s[:len(s)-blockChars]
	copy(o.PrivateID[:], pt[0:6])
	o.Counter = binary.LittleEndian.Uint16(pt[6:8]) & 0x7fff
	o.SessionUse = pt[11]
	return o, nil
}

// MatchesPrivateID compares in constant time.
func (o OTP) MatchesPrivateID(id []byte) bool {
	return subtle.ConstantTimeCompare(o.PrivateID[:], id) == 1
}

// IsNewer reports whether o comes strictly after the last accepted
// (counter, session use) pair. Anything else is a replay.
func IsNewer(o OTP, lastCounter uint16, lastUse uint8) bool {
	if o.Counter != lastCounter {
		return o.Counter > lastCounter
	}
	return o.SessionUse > lastUse
}

// Generate builds an OTP the way a YubiKey would. It is used for tests and
// is not needed for validation.
func Generate(publicID string, key []byte, privateID [6]byte, counter uint16, use uint8) (string, error) {
	if len(key) != KeySize {
		return "", fmt.Errorf("yubiotp: key must be %d bytes", KeySize)
	}
	var pt [16]byte
	copy(pt[0:6], privateID[:])
	binary.LittleEndian.PutUint16(pt[6:8], counter)
	pt[11] = use
	crc := ^crc16(pt[:14])
	binary.LittleEndian.PutUint16(pt[14:16], crc)
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	var ct [16]byte
	c.Encrypt(ct[:], pt[:])
	return publicID + modhexEncode(ct[:]), nil
}
