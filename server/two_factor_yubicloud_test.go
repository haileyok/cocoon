package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/internal/yubicloud"
	"github.com/haileyok/cocoon/internal/yubicloud/yubicloudtest"
	"github.com/haileyok/cocoon/internal/yubiotp"
	"github.com/haileyok/cocoon/models"
)

// factoryOTP returns a distinct well-formed OTP for a factory key with the
// given 12-character public ID. The fake YubiCloud doesn't decrypt, so any
// AES key works here.
func factoryOTP(t *testing.T, publicID string, n uint16) string {
	t.Helper()
	otp, err := yubiotp.Generate(publicID, make([]byte, 16), [6]byte{}, n, 0)
	if err != nil {
		t.Fatal(err)
	}
	return otp
}

const factoryPublicID = "ccccccfvdgrb"

func withYubiCloud(t *testing.T, s *Server) *yubicloudtest.Server {
	t.Helper()
	fake := yubicloudtest.New(t)
	c, err := yubicloud.New(yubicloudtest.ClientID, yubicloudtest.APIKey, yubicloud.WithURL(fake.URL))
	if err != nil {
		t.Fatal(err)
	}
	s.yubiCloud = c
	return fake
}

func (s *Server) insertYubiCloudKey(t *testing.T, did, publicID string) {
	t.Helper()
	cred := models.TwoFactorCredential{Did: did, Type: models.TwoFactorCredentialYubicoOTP, Name: "key", PublicID: publicID}
	if err := s.db.Create(context.Background(), &cred, nil).Error; err != nil {
		t.Fatal(err)
	}
}

func TestNewYubiCloudFromConfig(t *testing.T) {
	c, err := newYubiCloudFromConfig("", "")
	if c != nil || err != nil {
		t.Fatalf("unset config should leave YubiCloud off: %v %v", c, err)
	}
	if _, err := newYubiCloudFromConfig("123", ""); err == nil {
		t.Error("client id without api key accepted")
	}
	if _, err := newYubiCloudFromConfig("", yubicloudtest.APIKey); err == nil {
		t.Error("api key without client id accepted")
	}
	if _, err := newYubiCloudFromConfig("123", "%%%"); err == nil {
		t.Error("malformed api key accepted")
	}
	if c, err := newYubiCloudFromConfig("123", yubicloudtest.APIKey); c == nil || err != nil {
		t.Fatalf("valid config: %v %v", c, err)
	}
}

func TestYubiCloudRegisterByTapping(t *testing.T) {
	s, acct, cookie := manageServer(t)
	withYubiCloud(t, s)

	page := browserDo(s, cookie, "GET", "/account/2fa/yubikey", nil).Body.String()
	if strings.Contains(page, "ykman") || strings.Contains(page, `name="aes_key"`) {
		t.Fatal("with YubiCloud configured, setup should just ask for a tap")
	}

	otp := factoryOTP(t, factoryPublicID, 1)
	w := browserDo(s, cookie, "POST", "/account/2fa/yubikey", url.Values{"name": {"Blue key"}, "otp": {otp}, "password": {acct.Password}})
	if w.Code != 200 {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	if len(backupCodePattern.FindAllString(w.Body.String(), -1)) != backupCodeCount {
		t.Fatal("first method should show backup codes")
	}
	creds, _ := s.getTwoFactorCredentials(context.Background(), acct.Did)
	if len(creds) != 1 || creds[0].PublicID != factoryPublicID || len(creds[0].Secret) != 0 || creds[0].Name != "Blue key" {
		t.Fatalf("stored credential: %+v", creds)
	}
	// The registration tap was spent with Yubico.
	if rec := createSessionWith(t, s, acct, ptr(otp)); rec.Code == http.StatusOK {
		t.Fatal("registration OTP reusable")
	}
}

func TestYubiCloudSignIn(t *testing.T) {
	s, acct := recoveryServer(t)
	withYubiCloud(t, s)
	s.insertYubiCloudKey(t, acct.Did, factoryPublicID)

	otp := factoryOTP(t, factoryPublicID, 2)
	if rec := createSessionWith(t, s, acct, ptr(otp)); rec.Code != http.StatusOK {
		t.Fatalf("app sign-in: %d %s", rec.Code, rec.Body.String())
	}
	if rec := createSessionWith(t, s, acct, ptr(otp)); rec.Code == http.StatusOK {
		t.Fatal("replayed OTP accepted")
	}
	w := signinPost(s, url.Values{"username": {acct.Handle}, "password": {acct.Password}, "token": {factoryOTP(t, factoryPublicID, 3)}})
	if w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatalf("signin page: %d %s", w.Code, w.Header().Get("Location"))
	}
	creds, _ := s.getTwoFactorCredentials(context.Background(), acct.Did)
	if creds[0].LastUsedAt == nil {
		t.Fatal("last used time not recorded")
	}
}

func TestYubiCloudOtherKeyNotSentToYubico(t *testing.T) {
	s := newTestServer(t)
	fake := withYubiCloud(t, s)
	acct := s.createTestAccount(t, "otherkey.pds.test")
	s.insertYubiCloudKey(t, acct.Did, factoryPublicID)

	// Valid for Yubico, but from a key this account never registered.
	if rec := createSessionWith(t, s, acct, ptr(factoryOTP(t, "ccccccbbbbbb", 1))); rec.Code == http.StatusOK {
		t.Fatal("unregistered key accepted")
	}
	if fake.Requests != 0 {
		t.Fatalf("unregistered key's OTP was sent to Yubico (%d requests)", fake.Requests)
	}
}

func TestYubiCloudUnavailable(t *testing.T) {
	s, acct := recoveryServer(t)
	fake := withYubiCloud(t, s)
	fake.HTTPStatus = http.StatusServiceUnavailable
	s.insertYubiCloudKey(t, acct.Did, factoryPublicID)

	rec := createSessionWith(t, s, acct, ptr(factoryOTP(t, factoryPublicID, 1)))
	if rec.Code == http.StatusOK || rec.Code < 500 {
		t.Fatalf("expected a server error, got %d", rec.Code)
	}
	var body struct{ Error string }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !strings.Contains(body.Error, "YubiKey") {
		t.Fatalf("error should explain the YubiKey couldn't be checked: %s", rec.Body.String())
	}
	repo, _ := s.getRepoActorByDid(context.Background(), acct.Did)
	if repo.TwoFactorFailedAttempts != 0 {
		t.Fatal("an outage must not count as a wrong code")
	}

	w := signinPost(s, url.Values{"username": {acct.Handle}, "password": {acct.Password}, "token": {factoryOTP(t, factoryPublicID, 2)}})
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/account/signin") {
		t.Fatalf("signin page should redirect back with a message: %d", w.Code)
	}
}

func TestYubiCloudRejectedAtRegistration(t *testing.T) {
	s, acct, cookie := manageServer(t)
	fake := withYubiCloud(t, s)
	fake.ForceStatus = "REPLAYED_OTP"
	w := browserDo(s, cookie, "POST", "/account/2fa/yubikey", url.Values{"otp": {factoryOTP(t, factoryPublicID, 1)}, "password": {acct.Password}})
	if w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("rejected OTP registered a key: %d", w.Code)
	}
}

func TestYubiCloudRegistrationChecks(t *testing.T) {
	s, acct, cookie := manageServer(t)
	fake := withYubiCloud(t, s)

	w := browserDo(s, cookie, "POST", "/account/2fa/yubikey", url.Values{"otp": {factoryOTP(t, factoryPublicID, 1)}, "password": {"wrong"}})
	if w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("wrong password registered a key: %d", w.Code)
	}
	if fake.Requests != 0 {
		t.Fatal("a mistyped password shouldn't use up the tap")
	}

	// No public ID: can't tell keys apart at sign-in.
	bare := factoryOTP(t, "", 2)
	w = browserDo(s, cookie, "POST", "/account/2fa/yubikey", url.Values{"otp": {bare}, "password": {acct.Password}})
	if w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("OTP without a public ID registered: %d", w.Code)
	}

	for _, bad := range []string{"", "123456", "not a yubikey"} {
		before := fake.Requests
		w = browserDo(s, cookie, "POST", "/account/2fa/yubikey", url.Values{"otp": {bad}, "password": {acct.Password}})
		if w.Code != 400 || fake.Requests != before {
			t.Fatalf("%q: %d, requests %d->%d", bad, w.Code, before, fake.Requests)
		}
	}

	s.insertYubiCloudKey(t, acct.Did, factoryPublicID)
	if _, err := s.regenerateBackupCodes(context.Background(), acct.Did); err != nil {
		t.Fatal(err)
	}
	w = browserDo(s, cookie, "POST", "/account/2fa/yubikey", url.Values{
		"otp": {factoryOTP(t, factoryPublicID, 3)}, "password": {acct.Password}, "current_code": {factoryOTP(t, factoryPublicID, 4)},
	})
	if w.Code != 400 || s.countCreds(t, acct.Did) != 1 || !strings.Contains(w.Body.String(), "already") {
		t.Fatalf("same key registered twice: %d", w.Code)
	}
}

func TestYubiKeyWithoutYubiCloudConfigured(t *testing.T) {
	s, acct, cookie := manageServer(t)
	page := browserDo(s, cookie, "GET", "/account/2fa/yubikey", nil).Body.String()
	if !strings.Contains(page, "ykman") || !strings.Contains(page, `name="aes_key"`) {
		t.Fatal("without YubiCloud, setup should fall back to programming a slot")
	}
	w := browserDo(s, cookie, "POST", "/account/2fa/yubikey", url.Values{"otp": {factoryOTP(t, factoryPublicID, 1)}, "password": {acct.Password}})
	if w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("tap-only registration without YubiCloud: %d", w.Code)
	}

	// A key registered while YubiCloud was on can't be checked now. That's
	// a server problem, not a wrong code, so it mustn't lead to a lockout.
	s.insertYubiCloudKey(t, acct.Did, factoryPublicID)
	for i := uint16(0); i < maxSecondFactorAttempts+1; i++ {
		rec := createSessionWith(t, s, acct, ptr(factoryOTP(t, factoryPublicID, 2+i)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 when YubiCloud isn't configured, got %d %s", rec.Code, rec.Body.String())
		}
	}
	repo, _ := s.getRepoActorByDid(context.Background(), acct.Did)
	if repo.TwoFactorFailedAttempts != 0 || repo.TwoFactorLockedUntil != nil {
		t.Fatalf("missing YubiCloud config counted as wrong codes: %d attempts", repo.TwoFactorFailedAttempts)
	}
}
