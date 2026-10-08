package yubiotp

import (
	"encoding/hex"
	"errors"
	"testing"
)

// Vectors from Yubico's yubico-c test-vectors.txt and tests/selftest.c.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestModhexDecode(t *testing.T) {
	cases := map[string]string{
		"dteffuje":                         "2d344e83",
		"hknhfjbrjnlnldnhcujvddbikngjrtgh": "69b6481c8baba2b60e8f22179b58cd56",
		"urtubjtnuihvntcreeeecvbregfjibtn": "ecde18dbe76fbd0c33330f1c354871db",
		"ifhgieif":                         "74657374",
	}
	for in, want := range cases {
		got, err := ModhexDecode(in)
		if err != nil {
			t.Fatalf("decode %s: %v", in, err)
		}
		if hex.EncodeToString(got) != want {
			t.Errorf("decode %s = %x, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"abc", "zz", "c"} {
		if _, err := ModhexDecode(bad); err == nil {
			t.Errorf("expected error decoding %q", bad)
		}
	}
}

func TestParseTestVectorsTxt(t *testing.T) {
	key := mustHex(t, "ecde18dbe76fbd0c33330f1c354871db")
	otp, err := Parse("dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", key)
	if err != nil {
		t.Fatal(err)
	}
	if otp.PublicID != "dteffuje" {
		t.Errorf("public id %q", otp.PublicID)
	}
	if hex.EncodeToString(otp.PrivateID[:]) != "8792ebfe26cc" {
		t.Errorf("private id %x", otp.PrivateID)
	}
	if otp.Counter != 0x13 || otp.SessionUse != 0x11 {
		t.Errorf("counter %d use %d", otp.Counter, otp.SessionUse)
	}
}

func TestParseSelftestVectors(t *testing.T) {
	cases := []struct {
		key, otp, uid string
		ctr           uint16
		use           uint8
	}{
		{"000102030405060708090a0b0c0d0e0f", "dvgtiblfkbgturecfllberrvkinnctnn", "010203040506", 1, 1},
		{"000102030405060708090a0b0c0d0e0f", "rnibcnfhdninbrdebccrndfhjgnhftee", "010203040506", 1, 2},
		{"000102030405060708090a0b0c0d0e0f", "iikkijbdknrrdhfdrjltvgrbkkjblcbh", "010203040506", 0xfff, 1},
		{"c4422890653076cde73d449b191b416a", "iucvrkjiegbhidrcicvlgrcgkgurhjnj", "33c69e7f249e", 1, 0},
	}
	for i, tc := range cases {
		key := mustHex(t, tc.key)
		otp, err := Parse(tc.otp, key)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if hex.EncodeToString(otp.PrivateID[:]) != tc.uid || otp.Counter != tc.ctr || otp.SessionUse != tc.use {
			t.Errorf("vector %d: got uid=%x ctr=%d use=%d", i, otp.PrivateID, otp.Counter, otp.SessionUse)
		}
		if otp.PublicID != "" {
			t.Errorf("vector %d: expected empty public id", i)
		}
	}
}

func TestParseWrongKeyFailsCRC(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	_, err := Parse("dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", key)
	if !errors.Is(err, ErrBadCRC) {
		t.Fatalf("expected ErrBadCRC, got %v", err)
	}
}

func TestParseCapsLockFlagMasked(t *testing.T) {
	// Round-trip through Generate with the caps-lock bit set on the counter.
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	s, err := Generate("cccccccccccb", key, [6]byte{1, 2, 3, 4, 5, 6}, 0x8000|42, 3)
	if err != nil {
		t.Fatal(err)
	}
	otp, err := Parse(s, key)
	if err != nil {
		t.Fatal(err)
	}
	if otp.Counter != 42 || otp.PublicID != "cccccccccccb" {
		t.Fatalf("got ctr=%d pub=%s", otp.Counter, otp.PublicID)
	}
}

func TestLooksLikeOTP(t *testing.T) {
	yes := []string{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", "dvgtiblfkbgturecfllberrvkinnctnn", "DTEFFUJEHKNHFJBRJNLNLDNHCUJVDDBIKNGJRTGH"}
	no := []string{"123456", "abcde-fghij", "dvgtiblfkbgturecfllberrvkinnctn", "dvgtiblfkbgturecfllberrvkinnctnnx"}
	for _, s := range yes {
		if !LooksLikeOTP(s) {
			t.Errorf("%q should look like an OTP", s)
		}
	}
	for _, s := range no {
		if LooksLikeOTP(s) {
			t.Errorf("%q should not look like an OTP", s)
		}
	}
}

func TestIsNewer(t *testing.T) {
	if !IsNewer(OTP{Counter: 2, SessionUse: 0}, 1, 200) {
		t.Error("higher counter is newer")
	}
	if !IsNewer(OTP{Counter: 1, SessionUse: 5}, 1, 4) {
		t.Error("same counter higher use is newer")
	}
	if IsNewer(OTP{Counter: 1, SessionUse: 4}, 1, 4) {
		t.Error("identical is a replay")
	}
	if IsNewer(OTP{Counter: 0, SessionUse: 9}, 1, 0) {
		t.Error("lower counter is a replay")
	}
}
