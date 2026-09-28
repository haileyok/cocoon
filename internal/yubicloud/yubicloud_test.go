package yubicloud_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/haileyok/cocoon/internal/yubicloud"
	"github.com/haileyok/cocoon/internal/yubicloud/yubicloudtest"
)

const otp = "cccccccccccbdvgtiblfkbgturecfllberrvkinnctnn"

func client(t *testing.T, fake *yubicloudtest.Server) *yubicloud.Client {
	t.Helper()
	c, err := yubicloud.New(yubicloudtest.ClientID, yubicloudtest.APIKey, yubicloud.WithURL(fake.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := yubicloud.New("", yubicloudtest.APIKey); err == nil {
		t.Error("empty client id accepted")
	}
	if _, err := yubicloud.New("1", "not base64!"); err == nil {
		t.Error("non-base64 api key accepted")
	}
	if _, err := yubicloud.New("1", ""); err == nil {
		t.Error("empty api key accepted")
	}
}

func TestVerifyOKThenReplayed(t *testing.T) {
	fake := yubicloudtest.New(t)
	c := client(t, fake)
	ok, err := c.Verify(context.Background(), otp)
	if err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v", ok, err)
	}
	ok, err = c.Verify(context.Background(), otp)
	if err != nil || ok {
		t.Fatalf("replay should be a plain rejection: ok=%v err=%v", ok, err)
	}
}

func TestVerifyBadOTPIsRejection(t *testing.T) {
	fake := yubicloudtest.New(t)
	fake.ForceStatus = "BAD_OTP"
	ok, err := client(t, fake).Verify(context.Background(), otp)
	if ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

// Yubico's reference server signs BAD_OTP replies but doesn't echo the otp
// and nonce in them; that's still a genuine rejection.
func TestVerifyBadOTPWithoutEcho(t *testing.T) {
	fake := yubicloudtest.New(t)
	fake.ForceStatus = "BAD_OTP"
	fake.OmitEcho = true
	ok, err := client(t, fake).Verify(context.Background(), otp)
	if ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestFreshTimestampFormat(t *testing.T) {
	now := time.Date(2008, 11, 21, 6, 11, 55, 0, time.UTC)
	if !yubicloud.FreshTimestamp("2008-11-21T06:11:55Z0711", now) {
		t.Error("Yubico's documented example format not parsed")
	}
	if yubicloud.FreshTimestamp("2008-11-21T06:21:55Z0711", now) {
		t.Error("timestamp 10 minutes ahead accepted")
	}
}

func TestVerifyMalformedOTPNotSent(t *testing.T) {
	fake := yubicloudtest.New(t)
	ok, err := client(t, fake).Verify(context.Background(), "123456")
	if ok || err != nil || fake.Requests != 0 {
		t.Fatalf("ok=%v err=%v requests=%d", ok, err, fake.Requests)
	}
}

func TestVerifyNormalizesCase(t *testing.T) {
	fake := yubicloudtest.New(t)
	ok, err := client(t, fake).Verify(context.Background(), "  CCCCCCCCCCCBDVGTIBLFKBGTURECFLLBERRVKINNCTNN ")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

// Anything that means the answer can't be trusted must not be reported as
// a valid OTP.
func TestVerifyUntrustworthyResponses(t *testing.T) {
	cases := map[string]func(*yubicloudtest.Server){
		"bad signature":   func(s *yubicloudtest.Server) { s.BadSignature = true },
		"unsigned":        func(s *yubicloudtest.Server) { s.Unsigned = true },
		"wrong otp":       func(s *yubicloudtest.Server) { s.WrongOTP = true },
		"wrong nonce":     func(s *yubicloudtest.Server) { s.WrongNonce = true },
		"http 500":        func(s *yubicloudtest.Server) { s.HTTPStatus = http.StatusInternalServerError },
		"backend error":   func(s *yubicloudtest.Server) { s.ForceStatus = "BACKEND_ERROR" },
		"no client":       func(s *yubicloudtest.Server) { s.ForceStatus = "NO_SUCH_CLIENT" },
		"bad req sig":     func(s *yubicloudtest.Server) { s.ForceStatus = "BAD_SIGNATURE" },
		"unknown":         func(s *yubicloudtest.Server) { s.ForceStatus = "SOMETHING_NEW" },
		"ok without echo": func(s *yubicloudtest.Server) { s.OmitEcho = true },
		// Rejections count toward a lockout, so they must be genuine too.
		"unsigned replay":    func(s *yubicloudtest.Server) { s.ForceStatus = "REPLAYED_OTP"; s.Unsigned = true },
		"forged replay":      func(s *yubicloudtest.Server) { s.ForceStatus = "REPLAYED_OTP"; s.BadSignature = true },
		"replay other otp":   func(s *yubicloudtest.Server) { s.ForceStatus = "REPLAYED_OTP"; s.WrongOTP = true },
		"replay no echo":     func(s *yubicloudtest.Server) { s.ForceStatus = "REPLAYED_REQUEST"; s.OmitEcho = true },
		"unsigned bad otp":   func(s *yubicloudtest.Server) { s.ForceStatus = "BAD_OTP"; s.Unsigned = true },
		"forged bad otp":     func(s *yubicloudtest.Server) { s.ForceStatus = "BAD_OTP"; s.BadSignature = true },
		"bad otp wrong echo": func(s *yubicloudtest.Server) { s.ForceStatus = "BAD_OTP"; s.WrongNonce = true },
		// Without echoes, only the signed timestamp shows a BAD_OTP reply is
		// current rather than an old one played back.
		"stale bad otp": func(s *yubicloudtest.Server) {
			s.ForceStatus = "BAD_OTP"
			s.OmitEcho = true
			s.Timestamp = time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05Z0") + "000"
		},
		"bad otp no timestamp": func(s *yubicloudtest.Server) {
			s.ForceStatus = "BAD_OTP"
			s.OmitEcho = true
			s.Timestamp = "garbage"
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			fake := yubicloudtest.New(t)
			setup(fake)
			ok, err := client(t, fake).Verify(context.Background(), otp)
			if ok {
				t.Fatal("untrustworthy response treated as valid")
			}
			if err == nil {
				t.Fatal("expected an error so the caller can report a service problem")
			}
		})
	}
}

func TestVerifyWrongAPIKeyCaught(t *testing.T) {
	fake := yubicloudtest.New(t)
	// Same client id, different key: our request signature is wrong and we
	// can't verify the reply either.
	c, err := yubicloud.New(yubicloudtest.ClientID, "b3RoZXIta2V5", yubicloud.WithURL(fake.URL))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Verify(context.Background(), otp); ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestVerifyTimeout(t *testing.T) {
	fake := yubicloudtest.New(t)
	c, _ := yubicloud.New(yubicloudtest.ClientID, yubicloudtest.APIKey, yubicloud.WithURL(fake.URL))
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if ok, err := c.Verify(ctx, otp); ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
