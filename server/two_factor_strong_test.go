package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/internal/totp"
	"github.com/haileyok/cocoon/internal/yubiotp"
	"github.com/haileyok/cocoon/models"
)

var (
	testYubiKey       = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	testYubiPrivateID = [6]byte{1, 2, 3, 4, 5, 6}
	testYubiPublicID  = "cccccccccccb"
)

func (s *Server) addTOTP(t *testing.T, did string) []byte {
	t.Helper()
	secret, _ := totp.GenerateSecret()
	cred := models.TwoFactorCredential{Did: did, Type: models.TwoFactorCredentialTOTP, Name: "phone", Secret: secret}
	if err := s.db.Create(context.Background(), &cred, nil).Error; err != nil {
		t.Fatal(err)
	}
	return secret
}

func (s *Server) addYubiKey(t *testing.T, did string) {
	t.Helper()
	cred := models.TwoFactorCredential{
		Did: did, Type: models.TwoFactorCredentialYubicoOTP, Name: "key",
		Secret: testYubiKey, PublicID: testYubiPublicID, PrivateID: testYubiPrivateID[:],
		LastCounter: 1, LastUse: 0,
	}
	if err := s.db.Create(context.Background(), &cred, nil).Error; err != nil {
		t.Fatal(err)
	}
}

func yubiOTP(t *testing.T, ctr uint16, use uint8) string {
	t.Helper()
	otp, err := yubiotp.Generate(testYubiPublicID, testYubiKey, testYubiPrivateID, ctr, use)
	if err != nil {
		t.Fatal(err)
	}
	return otp
}

func createSessionWith(t *testing.T, s *Server, acct *testAccount, token *string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"identifier":%q,"password":%q}`, acct.Handle, acct.Password)
	if token != nil {
		body = fmt.Sprintf(`{"identifier":%q,"password":%q,"authFactorToken":%q}`, acct.Handle, acct.Password, *token)
	}
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createSession", body, nil)
	if err := s.handleCreateSession(c); err != nil {
		c.Error(err)
	}
	return rec
}

func errorName(rec *httptest.ResponseRecorder) string {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Error
}

func ptr(s string) *string { return &s }

func TestCreateSessionTOTPRequiredWithoutEmail(t *testing.T) {
	s := newTestServer(t) // s.mail is nil: any attempt to email a code fails the request
	acct := s.createTestAccount(t, "totp.pds.test")
	s.addTOTP(t, acct.Did)
	// Even with email 2FA also switched on, no email code is sent.
	s.setTwoFactor(t, acct.Did, "EMAIL-CODES", time.Now().Add(time.Hour))

	rec := createSessionWith(t, s, acct, nil)
	if rec.Code != http.StatusBadRequest || errorName(rec) != "AuthFactorTokenRequired" {
		t.Fatalf("expected AuthFactorTokenRequired, got %d %s", rec.Code, rec.Body.String())
	}

	rec = createSessionWith(t, s, acct, ptr("EMAIL-CODES"))
	if rec.Code == http.StatusOK {
		t.Fatal("emailed code must not be accepted once an authenticator is registered")
	}
}

func TestCreateSessionTOTPValidAndReplay(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "totp2.pds.test")
	secret := s.addTOTP(t, acct.Did)
	code := totp.Code(secret, time.Now())

	if rec := createSessionWith(t, s, acct, ptr(code)); rec.Code != http.StatusOK {
		t.Fatalf("valid TOTP rejected: %d %s", rec.Code, rec.Body.String())
	}
	if rec := createSessionWith(t, s, acct, ptr(code)); rec.Code == http.StatusOK {
		t.Fatal("replayed TOTP code accepted")
	}
}

func TestCreateSessionYubiKey(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "yubi.pds.test")
	s.addYubiKey(t, acct.Did)

	first := yubiOTP(t, 1, 1)
	if rec := createSessionWith(t, s, acct, ptr(first)); rec.Code != http.StatusOK {
		t.Fatalf("valid yubikey otp rejected: %d %s", rec.Code, rec.Body.String())
	}
	if rec := createSessionWith(t, s, acct, ptr(first)); rec.Code == http.StatusOK {
		t.Fatal("replayed yubikey otp accepted")
	}
	if rec := createSessionWith(t, s, acct, ptr(yubiOTP(t, 1, 0))); rec.Code == http.StatusOK {
		t.Fatal("older yubikey otp accepted")
	}
	if rec := createSessionWith(t, s, acct, ptr(yubiOTP(t, 2, 0))); rec.Code != http.StatusOK {
		t.Fatalf("newer yubikey otp rejected: %d", rec.Code)
	}

	// Right key, wrong private ID (e.g. a different slot sharing the key).
	forged, _ := yubiotp.Generate(testYubiPublicID, testYubiKey, [6]byte{9, 9, 9, 9, 9, 9}, 50, 0)
	if rec := createSessionWith(t, s, acct, ptr(forged)); rec.Code == http.StatusOK {
		t.Fatal("otp with wrong private id accepted")
	}
}

func TestCreateSessionYubiKeyOTPOfAnotherAccount(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice-yk.pds.test")
	bob := s.createTestAccount(t, "bob-yk.pds.test")
	s.addYubiKey(t, alice.Did)
	s.addTOTP(t, bob.Did)
	if rec := createSessionWith(t, s, bob, ptr(yubiOTP(t, 5, 0))); rec.Code == http.StatusOK {
		t.Fatal("alice's yubikey must not unlock bob's account")
	}
}

func TestCreateSessionBackupCodeSingleUse(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "backup.pds.test")
	s.addTOTP(t, acct.Did)
	codes, err := s.regenerateBackupCodes(context.Background(), acct.Did)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != backupCodeCount {
		t.Fatalf("got %d codes", len(codes))
	}
	if rec := createSessionWith(t, s, acct, ptr(strings.ToLower(codes[0]))); rec.Code != http.StatusOK {
		t.Fatalf("backup code rejected: %d %s", rec.Code, rec.Body.String())
	}
	if rec := createSessionWith(t, s, acct, ptr(codes[0])); rec.Code == http.StatusOK {
		t.Fatal("backup code reused")
	}
	if rec := createSessionWith(t, s, acct, ptr(codes[1])); rec.Code != http.StatusOK {
		t.Fatal("second backup code rejected")
	}
}

func TestCreateSessionSecondFactorLockout(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "lockout.pds.test")
	secret := s.addTOTP(t, acct.Did)

	for i := 0; i < maxSecondFactorAttempts; i++ {
		if rec := createSessionWith(t, s, acct, ptr("000000")); rec.Code == http.StatusOK {
			t.Fatal("wrong code accepted")
		}
	}
	rec := createSessionWith(t, s, acct, ptr(totp.Code(secret, time.Now())))
	if rec.Code == http.StatusOK {
		t.Fatal("correct code accepted while locked out")
	}
	if errorName(rec) != "RateLimitExceeded" {
		t.Fatalf("expected RateLimitExceeded, got %s", rec.Body.String())
	}

	// Once the lock expires the correct code works and the counter resets.
	if err := s.db.Exec(context.Background(), "UPDATE repos SET two_factor_locked_until = ? WHERE did = ?", nil, time.Now().Add(-time.Minute), acct.Did).Error; err != nil {
		t.Fatal(err)
	}
	if rec := createSessionWith(t, s, acct, ptr(totp.Code(secret, time.Now()))); rec.Code != http.StatusOK {
		t.Fatalf("correct code rejected after lock expired: %d %s", rec.Code, rec.Body.String())
	}
	repo, _ := s.getRepoActorByDid(context.Background(), acct.Did)
	if repo.TwoFactorFailedAttempts != 0 {
		t.Fatalf("failed attempts not reset: %d", repo.TwoFactorFailedAttempts)
	}
}

func TestCreateSessionReportsAuthFactorForTOTP(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "report.pds.test")
	secret := s.addTOTP(t, acct.Did)
	rec := createSessionWith(t, s, acct, ptr(totp.Code(secret, time.Now())))
	var body ComAtprotoServerCreateSessionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !body.EmailAuthFactor {
		t.Fatal("emailAuthFactor should be true when an authenticator is registered")
	}
}

// Signin page, which the OAuth authorize flow sends users through.

func signinPost(s *Server, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/account/signin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

func TestSigninPageTOTP(t *testing.T) {
	s, acct := recoveryServer(t)
	secret := s.addTOTP(t, acct.Did)
	base := url.Values{"username": {acct.Handle}, "password": {acct.Password}, "query_params": {"request_uri=abc"}}

	w := signinPost(s, base)
	if w.Code != 303 || w.Header().Get("Location") != "/account/signin/verify" {
		t.Fatalf("expected redirect to the code step, got %d %s", w.Code, w.Header().Get("Location"))
	}

	bad := url.Values{"token": {"000000"}}
	for k, v := range base {
		bad[k] = v
	}
	w = signinPost(s, bad)
	if w.Code != 303 || w.Header().Get("Location") != "/account/signin/verify" {
		t.Fatalf("wrong code should redirect to the code step with a message, got %d %s", w.Code, w.Header().Get("Location"))
	}

	good := url.Values{"token": {totp.Code(secret, time.Now())}}
	for k, v := range base {
		good[k] = v
	}
	w = signinPost(s, good)
	if w.Code != 303 || w.Header().Get("Location") != "/oauth/authorize?request_uri=abc" {
		t.Fatalf("expected redirect to authorize, got %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestSigninPageYubiKey(t *testing.T) {
	s, acct := recoveryServer(t)
	s.addYubiKey(t, acct.Did)
	w := signinPost(s, url.Values{"username": {acct.Handle}, "password": {acct.Password}, "token": {yubiOTP(t, 3, 0)}})
	if w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatalf("expected signin success, got %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestSigninPageWrongPasswordMessage(t *testing.T) {
	s, acct := recoveryServer(t)
	w := signinPost(s, url.Values{"username": {acct.Handle}, "password": {"nope"}})
	if w.Code != 303 {
		t.Fatalf("got %d", w.Code)
	}
	cookie := w.Result().Cookies()
	r := httptest.NewRequest("GET", "/account/signin", nil)
	for _, c := range cookie {
		r.AddCookie(c)
	}
	s.loadTemplates()
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "Handle or password is incorrect") {
		t.Fatalf("wrong password should say so, page was:\n%s", w.Body.String())
	}
}

func TestPasswordResetKeepsStrongSecondFactors(t *testing.T) {
	s, acct := recoveryServer(t)
	s.addTOTP(t, acct.Did)
	code := requestRecoveryCode(t, s, acct)
	if w := resetWithCode(s, code); w.Code != 200 {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}
	creds, err := s.getTwoFactorCredentials(context.Background(), acct.Did)
	if err != nil || len(creds) != 1 {
		t.Fatalf("password reset must not remove authenticators: %v %d", err, len(creds))
	}
}
