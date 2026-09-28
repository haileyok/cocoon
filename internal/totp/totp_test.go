package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (SHA1 seed), truncated to 6 digits.
var rfcSecret = []byte("12345678901234567890")

func TestCodeRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tc := range cases {
		if got := Code(rfcSecret, time.Unix(tc.unix, 0)); got != tc.want {
			t.Errorf("Code(t=%d) = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestValidateAcceptsDriftWindow(t *testing.T) {
	now := time.Unix(1234567890, 0)
	for _, off := range []time.Duration{-Period, 0, Period} {
		code := Code(rfcSecret, now.Add(off))
		if _, ok := Validate(rfcSecret, code, now, 0); !ok {
			t.Errorf("expected code at offset %v to validate", off)
		}
	}
	far := Code(rfcSecret, now.Add(3*Period))
	if _, ok := Validate(rfcSecret, far, now, 0); ok {
		t.Errorf("code 3 periods ahead must not validate")
	}
}

func TestValidateRejectsReplay(t *testing.T) {
	now := time.Unix(1234567890, 0)
	code := Code(rfcSecret, now)
	step, ok := Validate(rfcSecret, code, now, 0)
	if !ok {
		t.Fatal("first use should validate")
	}
	if _, ok := Validate(rfcSecret, code, now, step); ok {
		t.Fatal("same code must not validate twice")
	}
	// A code from an earlier step than the last used one is also rejected.
	prev := Code(rfcSecret, now.Add(-Period))
	if _, ok := Validate(rfcSecret, prev, now, step); ok {
		t.Fatal("older code must not validate after a newer one was used")
	}
}

func TestValidateNormalizesInput(t *testing.T) {
	now := time.Unix(1234567890, 0)
	if _, ok := Validate(rfcSecret, "005 924", now, 0); !ok {
		t.Error("spaces should be ignored")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "00592x"} {
		if _, ok := Validate(rfcSecret, bad, now, 0); ok {
			t.Errorf("%q must not validate", bad)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateSecret()
	if len(a) != SecretSize || string(a) == string(b) {
		t.Fatalf("secrets should be %d random bytes", SecretSize)
	}
}

func TestURI(t *testing.T) {
	u, err := url.Parse(URI("pds.example.com", "alice.example.com", rfcSecret))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("bad uri %s", u)
	}
	if !strings.HasPrefix(u.Path, "/pds.example.com:alice.example.com") {
		t.Fatalf("bad label %q", u.Path)
	}
	q := u.Query()
	if q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("issuer") != "pds.example.com" {
		t.Fatalf("bad query %v", q)
	}
}
