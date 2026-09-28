// Package totp implements RFC 6238 time-based one-time passwords with the
// parameters every mainstream authenticator app supports: HMAC-SHA1,
// 6 digits, 30 second period.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Period     = 30 * time.Second
	Digits     = 6
	SecretSize = 20
	// Skew is how many periods either side of the current one are accepted,
	// to tolerate clock drift between the server and the authenticator.
	Skew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func GenerateSecret() ([]byte, error) {
	b := make([]byte, SecretSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// EncodeSecret returns the base32 form shown to users for manual entry.
func EncodeSecret(secret []byte) string {
	return b32.EncodeToString(secret)
}

// DecodeSecret parses the base32 form produced by EncodeSecret.
func DecodeSecret(s string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.TrimSpace(s)))
}

func step(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

func codeAt(secret []byte, s int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(s))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", bin%1_000_000)
}

// Code returns the code for the period containing t.
func Code(secret []byte, t time.Time) string {
	return codeAt(secret, step(t))
}

// Validate checks code against the periods around now. lastStep is the step
// of the most recently accepted code for this secret (0 if none); only
// strictly newer steps are accepted, so a code can never be used twice. On
// success the matched step is returned and should be persisted as the new
// lastStep.
func Validate(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}

	cur := step(now)
	matched := int64(0)
	for s := cur - Skew; s <= cur+Skew; s++ {
		// Check every candidate step so timing doesn't reveal which matched.
		if subtle.ConstantTimeCompare([]byte(codeAt(secret, s)), []byte(code)) == 1 && s > lastStep {
			matched = s
		}
	}
	return matched, matched != 0
}

// URI builds the otpauth:// URI that authenticator apps read from a QR code.
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
