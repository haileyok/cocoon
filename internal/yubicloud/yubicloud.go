// Package yubicloud checks YubiKey OTPs with Yubico's YubiCloud service, so
// keys work as they come from the factory: the secret behind a factory
// YubiKey's OTPs is known only to Yubico.
//
// Protocol: https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
package yubicloud

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/haileyok/cocoon/internal/yubiotp"
)

const DefaultURL = "https://api.yubico.com/wsapi/2.0/verify"

type Client struct {
	id   string
	key  []byte
	url  string
	http *http.Client
}

type Option func(*Client)

// WithURL points the client at another validation endpoint (used in tests).
func WithURL(u string) Option { return func(c *Client) { c.url = u } }

// New builds a client from the client ID and base64 API key issued at
// https://upgrade.yubico.com/getapikey/.
func New(clientID, apiKey string, opts ...Option) (*Client, error) {
	if clientID == "" {
		return nil, errors.New("yubicloud: client id is required")
	}
	key, err := base64.StdEncoding.DecodeString(apiKey)
	if err != nil || len(key) == 0 {
		return nil, errors.New("yubicloud: api key must be the base64 key from Yubico")
	}
	c := &Client{id: clientID, key: key, url: DefaultURL, http: &http.Client{Timeout: 10 * time.Second}}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// sign computes the protocol's HMAC-SHA1 over all parameters except h,
// sorted by key and joined as k=v&k=v.
func (c *Client) sign(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k != "h" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + params[k]
	}
	mac := hmac.New(sha1.New, c.key)
	mac.Write([]byte(strings.Join(parts, "&")))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Verify reports whether otp is a valid, never-before-used OTP. A false
// result with a nil error means YubiCloud genuinely rejected the OTP
// (malformed, unknown key, or already used), in a signed reply about this
// request. An error means no trustworthy answer was
// obtained, for example a network failure, a bad API key, or a response
// whose signature, otp, or nonce doesn't check out; callers should treat
// that as a service problem rather than a wrong code.
func (c *Client) Verify(ctx context.Context, otp string) (bool, error) {
	otp = strings.ToLower(strings.TrimSpace(otp))
	if !yubiotp.LooksLikeOTP(otp) {
		return false, nil
	}

	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return false, err
	}
	nonce := hex.EncodeToString(nb) // 32 characters; the protocol allows 16-40

	params := map[string]string{"id": c.id, "otp": otp, "nonce": nonce}
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	q.Set("h", c.sign(params))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("yubicloud: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("yubicloud: unexpected http status %d", resp.StatusCode)
	}

	fields := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<10))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimRight(sc.Text(), "\r"), "=")
		if ok && k != "" {
			fields[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("yubicloud: reading response: %w", err)
	}

	status := fields["status"]
	switch status {
	case "OK", "REPLAYED_OTP", "REPLAYED_REQUEST", "BAD_OTP":
		// These answers decide the result: OK grants access and the others
		// count as a wrong code, so each must be genuine and about this
		// request. Yubico signs all of them; it echoes otp and nonce in all
		// but BAD_OTP.
		if !hmac.Equal([]byte(fields["h"]), []byte(c.sign(fields))) {
			return false, fmt.Errorf("yubicloud: %s response signature is invalid (check the API key)", status)
		}
		echoRequired := status != "BAD_OTP"
		if !echoMatches(fields, "otp", otp, echoRequired) || !echoMatches(fields, "nonce", nonce, echoRequired) {
			return false, fmt.Errorf("yubicloud: %s response does not match the request", status)
		}
		// Without the nonce echoed, nothing ties the reply to this request,
		// so an old signed reply could be played back. Require its signed
		// timestamp to be current instead. If the clock is off, the worst
		// case is reporting "couldn't check" for a genuinely bad OTP.
		if _, hasNonce := fields["nonce"]; !hasNonce && !freshTimestamp(fields["t"], time.Now()) {
			return false, fmt.Errorf("yubicloud: %s response isn't tied to this request and its timestamp %q isn't current", status, fields["t"])
		}
		return status == "OK", nil
	case "":
		return false, errors.New("yubicloud: response has no status")
	default:
		return false, fmt.Errorf("yubicloud: validation failed with status %s", status)
	}
}

// maxResponseAge bounds how far a reply's timestamp may be from our clock
// when that timestamp is the only thing showing the reply is current.
const maxResponseAge = 5 * time.Minute

// freshTimestamp reports whether a YubiCloud "t" value, such as
// 2008-11-21T06:11:55Z0711 (UTC seconds, then "0" and milliseconds), is
// within maxResponseAge of now.
func freshTimestamp(t string, now time.Time) bool {
	const layout = "2006-01-02T15:04:05Z"
	if len(t) < len(layout) {
		return false
	}
	ts, err := time.Parse(layout, t[:len(layout)])
	if err != nil {
		return false
	}
	d := now.Sub(ts)
	return d <= maxResponseAge && d >= -maxResponseAge
}

func echoMatches(fields map[string]string, key, want string, required bool) bool {
	got, ok := fields[key]
	if !ok {
		return !required
	}
	return got == want
}
