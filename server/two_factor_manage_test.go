package server

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/internal/totp"
	"github.com/haileyok/cocoon/models"
)

func manageServer(t *testing.T) (*Server, *testAccount, *http.Cookie) {
	t.Helper()
	s, acct := recoveryServer(t)
	s.loadTemplates()
	cookie := browserSignin(t, s, acct, acct.Password)
	return s, acct, cookie
}

func browserDo(s *Server, cookie *http.Cookie, method, path string, form url.Values) *httptest.ResponseRecorder {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

var secretField = regexp.MustCompile(`name="secret" value="([A-Z2-7]+)"`)
var backupCodePattern = regexp.MustCompile(`[A-Z2-7]{5}-[A-Z2-7]{5}`)

func startTOTPSetup(t *testing.T, s *Server, cookie *http.Cookie) (string, []byte) {
	t.Helper()
	w := browserDo(s, cookie, "GET", "/account/2fa/totp", nil)
	if w.Code != 200 {
		t.Fatalf("totp setup page: %d %s", w.Code, w.Body.String())
	}
	m := secretField.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no secret on setup page:\n%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "data:image/png;base64,") {
		t.Fatal("setup page should include a QR code")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return m[1], secret
}

func (s *Server) countCreds(t *testing.T, did string) int {
	t.Helper()
	creds, err := s.getTwoFactorCredentials(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	return len(creds)
}

func (s *Server) countBackupCodes(t *testing.T, did string) int64 {
	t.Helper()
	var n int64
	if err := s.db.Raw(context.Background(), "SELECT COUNT(*) FROM two_factor_backup_codes WHERE did = ?", nil, did).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTwoFactorPagesRequireSignin(t *testing.T) {
	s, _, _ := manageServer(t)
	for _, p := range []string{"/account/2fa", "/account/2fa/totp", "/account/2fa/yubikey"} {
		w := browserDo(s, nil, "GET", p, nil)
		if w.Code != 303 || w.Header().Get("Location") != "/account/signin" {
			t.Errorf("%s: expected redirect to signin, got %d", p, w.Code)
		}
	}
	w := browserDo(s, nil, "POST", "/account/2fa/totp", url.Values{"secret": {"AAAA"}})
	if w.Code != 303 || w.Header().Get("Location") != "/account/signin" {
		t.Errorf("POST without session: got %d", w.Code)
	}
}

func TestAddTOTP(t *testing.T) {
	s, acct, cookie := manageServer(t)
	encoded, secret := startTOTPSetup(t, s, cookie)
	code := totp.Code(secret, time.Now())

	w := browserDo(s, cookie, "POST", "/account/2fa/totp", url.Values{"secret": {encoded}, "name": {"phone"}, "code": {code}, "password": {"wrong"}})
	if w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("wrong password must not add an authenticator: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), encoded) {
		t.Fatal("error page should keep the same secret so the user needn't rescan")
	}

	w = browserDo(s, cookie, "POST", "/account/2fa/totp", url.Values{"secret": {encoded}, "name": {"phone"}, "code": {"000000"}, "password": {acct.Password}})
	if w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("wrong code must not add an authenticator: %d", w.Code)
	}

	w = browserDo(s, cookie, "POST", "/account/2fa/totp", url.Values{"secret": {encoded}, "name": {"phone"}, "code": {code}, "password": {acct.Password}})
	if w.Code != 200 || s.countCreds(t, acct.Did) != 1 {
		t.Fatalf("valid setup failed: %d %s", w.Code, w.Body.String())
	}
	codes := backupCodePattern.FindAllString(w.Body.String(), -1)
	if len(codes) != backupCodeCount || s.countBackupCodes(t, acct.Did) != backupCodeCount {
		t.Fatalf("first method should show %d backup codes, got %d", backupCodeCount, len(codes))
	}

	// The confirmation code was consumed; it can't then be used to sign in.
	if rec := createSessionWith(t, s, acct, ptr(code)); rec.Code == http.StatusOK {
		t.Fatal("setup code must not be reusable for sign-in")
	}
}

func TestAddFirstMethodWithEmailTwoFactorNeedsEmailedCode(t *testing.T) {
	s, acct, cookie := manageServer(t)
	// Turn on email 2FA after signing in (so the helper needn't handle it).
	if err := s.db.Exec(context.Background(), "UPDATE repos SET two_factor_type = ? WHERE did = ?", nil, models.TwoFactorTypeEmail, acct.Did).Error; err != nil {
		t.Fatal(err)
	}
	encoded, secret := startTOTPSetup(t, s, cookie)
	form := url.Values{"secret": {encoded}, "code": {totp.Code(secret, time.Now())}, "password": {acct.Password}}
	if page := browserDo(s, cookie, "GET", "/account/2fa/yubikey", nil).Body.String(); !strings.Contains(page, "Email me a code") || !strings.Contains(page, `name="current_code"`) {
		t.Fatal("setup page should offer an emailed code to email-2FA accounts")
	}

	if w := browserDo(s, cookie, "POST", "/account/2fa/totp", form); w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("password alone must not replace email 2FA: %d", w.Code)
	}

	// Stand in for the "send me a code" email.
	s.setTwoFactor(t, acct.Did, "ABCDE-FGHIJ", time.Now().Add(10*time.Minute))
	form.Set("current_code", "WRONG-CODES")
	if w := browserDo(s, cookie, "POST", "/account/2fa/totp", form); w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("wrong emailed code accepted: %d", w.Code)
	}

	s.setTwoFactor(t, acct.Did, "ABCDE-FGHIJ", time.Now().Add(-time.Minute))
	form.Set("current_code", "ABCDE-FGHIJ")
	if w := browserDo(s, cookie, "POST", "/account/2fa/totp", form); w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("expired emailed code accepted: %d", w.Code)
	}

	s.setTwoFactor(t, acct.Did, "ABCDE-FGHIJ", time.Now().Add(10*time.Minute))
	if w := browserDo(s, cookie, "POST", "/account/2fa/totp", form); w.Code != 200 || s.countCreds(t, acct.Did) != 1 {
		t.Fatalf("valid emailed code rejected: %d %s", w.Code, w.Body.String())
	}
	if s.twoFactorCode(t, acct.Did) != nil {
		t.Fatal("emailed code should be used up")
	}
}

func TestSendEmailCodeForTwoFactorSetup(t *testing.T) {
	s, acct, cookie := manageServer(t)
	// No email 2FA: nothing to send, and nothing is stored.
	w := browserDo(s, cookie, "POST", "/account/2fa/email-code", url.Values{"next": {"/account/2fa/totp"}})
	if w.Code != 303 || s.twoFactorCode(t, acct.Did) != nil {
		t.Fatalf("got %d", w.Code)
	}
	// Only local setup pages are valid redirect targets.
	w = browserDo(s, cookie, "POST", "/account/2fa/email-code", url.Values{"next": {"https://evil.example/"}})
	if w.Header().Get("Location") != "/account/2fa" {
		t.Fatalf("open redirect: %s", w.Header().Get("Location"))
	}
}

func TestAddSecondMethodRequiresCurrentCode(t *testing.T) {
	s, acct, cookie := manageServer(t)
	existing := s.addTOTP(t, acct.Did)
	if _, err := s.regenerateBackupCodes(context.Background(), acct.Did); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"name": {"key"}, "password": {acct.Password},
		"aes_key": {hex.EncodeToString(testYubiKey)}, "otp": {yubiOTP(t, 1, 1)},
	}
	w := browserDo(s, cookie, "POST", "/account/2fa/yubikey", form)
	if w.Code != 400 || s.countCreds(t, acct.Did) != 1 {
		t.Fatalf("adding a second method without a current code must fail: %d", w.Code)
	}

	form.Set("current_code", totp.Code(existing, time.Now()))
	w = browserDo(s, cookie, "POST", "/account/2fa/yubikey", form)
	if w.Code != 303 || s.countCreds(t, acct.Did) != 2 {
		t.Fatalf("adding yubikey failed: %d %s", w.Code, w.Body.String())
	}

	creds, _ := s.getTwoFactorCredentials(context.Background(), acct.Did)
	yk := creds[1]
	if yk.Type != models.TwoFactorCredentialYubicoOTP || yk.PublicID != testYubiPublicID ||
		hex.EncodeToString(yk.PrivateID) != hex.EncodeToString(testYubiPrivateID[:]) || yk.LastCounter != 1 || yk.LastUse != 1 {
		t.Fatalf("bad stored yubikey: %+v", yk)
	}
	// The enrolment OTP counts as used.
	if rec := createSessionWith(t, s, acct, ptr(form.Get("otp"))); rec.Code == http.StatusOK {
		t.Fatal("enrolment otp reusable")
	}
	if n := s.countBackupCodes(t, acct.Did); n != backupCodeCount {
		t.Fatalf("adding a second method must not replace backup codes, have %d", n)
	}
}

func TestAddYubiKeyRejectsMismatchedKey(t *testing.T) {
	s, acct, cookie := manageServer(t)
	form := url.Values{
		"name": {"key"}, "password": {acct.Password},
		"aes_key": {"ffffffffffffffffffffffffffffffff"}, "otp": {yubiOTP(t, 1, 1)},
	}
	if w := browserDo(s, cookie, "POST", "/account/2fa/yubikey", form); w.Code != 400 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("otp from a different key must be rejected: %d", w.Code)
	}
	form.Set("aes_key", "not-hex")
	if w := browserDo(s, cookie, "POST", "/account/2fa/yubikey", form); w.Code != 400 {
		t.Fatalf("malformed key must be rejected: %d", w.Code)
	}
}

func TestRemoveTwoFactorCredential(t *testing.T) {
	s, acct, cookie := manageServer(t)
	secret := s.addTOTP(t, acct.Did)
	if _, err := s.regenerateBackupCodes(context.Background(), acct.Did); err != nil {
		t.Fatal(err)
	}
	creds, _ := s.getTwoFactorCredentials(context.Background(), acct.Did)
	id := fmt.Sprint(creds[0].ID)

	// Another account can't remove it, even with its own valid credentials.
	other := s.createTestAccount(t, "other-2fa.pds.test")
	otherCookie := browserSignin(t, s, other, other.Password)
	browserDo(s, otherCookie, "POST", "/account/2fa/remove", url.Values{"id": {id}, "password": {other.Password}})
	if s.countCreds(t, acct.Did) != 1 {
		t.Fatal("another account removed this credential")
	}

	w := browserDo(s, cookie, "POST", "/account/2fa/remove", url.Values{"id": {id}, "password": {acct.Password}})
	if s.countCreds(t, acct.Did) != 1 {
		t.Fatalf("removal without a current code must fail: %d", w.Code)
	}

	w = browserDo(s, cookie, "POST", "/account/2fa/remove", url.Values{"id": {id}, "password": {acct.Password}, "current_code": {totp.Code(secret, time.Now())}})
	if w.Code != 303 || s.countCreds(t, acct.Did) != 0 {
		t.Fatalf("removal failed: %d %s", w.Code, w.Body.String())
	}
	if n := s.countBackupCodes(t, acct.Did); n != 0 {
		t.Fatalf("backup codes should be deleted with the last method, have %d", n)
	}
	// Signing in no longer asks for a code.
	if rec := createSessionWith(t, s, acct, nil); rec.Code != http.StatusOK {
		t.Fatalf("sign in after removal: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRegenerateBackupCodes(t *testing.T) {
	s, acct, cookie := manageServer(t)
	secret := s.addTOTP(t, acct.Did)
	old, _ := s.regenerateBackupCodes(context.Background(), acct.Did)

	w := browserDo(s, cookie, "POST", "/account/2fa/backup-codes", url.Values{"password": {acct.Password}, "current_code": {totp.Code(secret, time.Now())}})
	if w.Code != 200 {
		t.Fatalf("regenerate: %d %s", w.Code, w.Body.String())
	}
	codes := backupCodePattern.FindAllString(w.Body.String(), -1)
	if len(codes) != backupCodeCount {
		t.Fatalf("expected %d new codes, got %d", backupCodeCount, len(codes))
	}
	if rec := createSessionWith(t, s, acct, ptr(old[0])); rec.Code == http.StatusOK {
		t.Fatal("old backup code still works after regenerating")
	}
	if rec := createSessionWith(t, s, acct, ptr(codes[0])); rec.Code != http.StatusOK {
		t.Fatal("new backup code rejected")
	}
}

func TestTwoFactorOverviewPage(t *testing.T) {
	s, acct, cookie := manageServer(t)
	w := browserDo(s, cookie, "GET", "/account/2fa", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/account/2fa/totp") {
		t.Fatalf("overview: %d", w.Code)
	}
	cred := models.TwoFactorCredential{Did: acct.Did, Type: models.TwoFactorCredentialTOTP, Name: `<script>x</script>`, Secret: []byte("s")}
	if err := s.db.Create(context.Background(), &cred, nil).Error; err != nil {
		t.Fatal(err)
	}
	w = browserDo(s, cookie, "GET", "/account/2fa", nil)
	if strings.Contains(w.Body.String(), "<script>x</script>") || !strings.Contains(w.Body.String(), "Authenticator app") {
		t.Fatal("credential name must be escaped and the type shown")
	}
	if strings.Contains(w.Body.String(), "/account/2fa/totp\"") == false {
		t.Fatal("overview should link to add another method")
	}
}
