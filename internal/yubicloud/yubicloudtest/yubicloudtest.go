// Package yubicloudtest provides a fake YubiCloud validation server for tests.
//
// It follows https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html:
// requests must carry a valid signature and a 16-40 character nonce, each
// well-formed OTP is accepted once (then REPLAYED_OTP), and responses are
// signed with the client's API key.
package yubicloudtest

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	ClientID = "12345"
	// APIKey is the base64 API key the fake signs with.
	APIKey = "c2VjcmV0LWFwaS1rZXktZm9yLXRlc3Rz"
)

type Server struct {
	*httptest.Server

	mu   sync.Mutex
	seen map[string]bool

	// Knobs for failure tests. Zero values give a well-behaved server.
	ForceStatus  string // respond with this status instead of the real one
	BadSignature bool   // sign responses with the wrong key
	Unsigned     bool   // omit the response signature
	WrongOTP     bool   // echo a different otp
	WrongNonce   bool   // echo a different nonce
	OmitEcho     bool   // leave otp and nonce out, as Yubico does for BAD_OTP
	Timestamp    string // use this value for the response's t field
	HTTPStatus   int    // respond with this HTTP status and no body
	Requests     int
}

func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{seen: map[string]bool{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func sign(key []byte, params map[string]string) string {
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
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(strings.Join(parts, "&")))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func wellFormed(otp string) bool {
	if len(otp) < 32 || len(otp) > 48 {
		return false
	}
	for _, c := range otp {
		if !strings.ContainsRune("cbdefghijklnrtuv", c) {
			return false
		}
	}
	return true
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests++

	if s.HTTPStatus != 0 {
		w.WriteHeader(s.HTTPStatus)
		return
	}

	key, _ := base64.StdEncoding.DecodeString(APIKey)
	q := r.URL.Query()
	req := map[string]string{}
	for k := range q {
		req[k] = q.Get(k)
	}
	otp, nonce := req["otp"], req["nonce"]

	status := "OK"
	switch {
	case req["id"] != ClientID:
		status = "NO_SUCH_CLIENT"
	case otp == "" || nonce == "":
		status = "MISSING_PARAMETER"
	case req["h"] != "" && !hmac.Equal([]byte(req["h"]), []byte(sign(key, req))):
		status = "BAD_SIGNATURE"
	case len(nonce) < 16 || len(nonce) > 40:
		status = "MISSING_PARAMETER"
	case !wellFormed(otp):
		status = "BAD_OTP"
	case s.seen[otp]:
		status = "REPLAYED_OTP"
	}
	if status == "OK" {
		s.seen[otp] = true
	}
	if s.ForceStatus != "" {
		status = s.ForceStatus
	}

	resp := map[string]string{
		// Yubico's format: RFC 3339 seconds, then "0" and milliseconds.
		"t":      time.Now().UTC().Format("2006-01-02T15:04:05Z0") + "123",
		"otp":    otp,
		"nonce":  nonce,
		"sl":     "100",
		"status": status,
	}
	if s.WrongOTP {
		resp["otp"] = "cccccccccccbdefghijklnrtuvcbdefghijklnrtuv"
	}
	if s.WrongNonce {
		resp["nonce"] = "0000000000000000"
	}
	if s.Timestamp != "" {
		resp["t"] = s.Timestamp
	}
	if s.OmitEcho {
		delete(resp, "otp")
		delete(resp, "nonce")
	}
	if !s.Unsigned {
		signKey := key
		if s.BadSignature {
			signKey = []byte("not-the-api-key")
		}
		resp["h"] = sign(signKey, resp)
	}

	w.Header().Set("Content-Type", "text/plain")
	for _, k := range []string{"h", "t", "otp", "nonce", "sl", "status"} {
		if v, ok := resp[k]; ok {
			fmt.Fprintf(w, "%s=%s\r\n", k, v)
		}
	}
}
