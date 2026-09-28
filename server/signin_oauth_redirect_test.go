package server

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/internal/totp"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"gorm.io/gorm"
)

var queryParamsField = regexp.MustCompile(`name="query_params"[^>]*value="([^"]*)"`)

func sessionCookieFrom(s *Server, w *httptest.ResponseRecorder, fallback *http.Cookie) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == s.config.SessionCookieKey {
			return c
		}
	}
	return fallback
}

func sameOriginPost(s *Server, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+r.Host)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

func addTestTOTP(t *testing.T, s *Server, did string) []byte {
	t.Helper()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	cred := models.TwoFactorCredential{Did: did, Type: models.TwoFactorCredentialTOTP, Name: "phone", Secret: secret}
	if err := s.db.Create(context.Background(), &cred, nil).Error; err != nil {
		t.Fatal(err)
	}
	return secret
}

var testOAuthQuery = url.Values{
	"client_id":   {"https://app.example/client-metadata.json"},
	"request_uri": {"urn:ietf:params:oauth:request_uri:req-abc123"},
}.Encode()

// passwordStep runs the first half of a 2FA sign-in from the OAuth flow and
// returns the cookie holding the pending sign-in.
func passwordStep(t *testing.T, s *Server, acct *testAccount) *http.Cookie {
	t.Helper()
	w := browserDo(s, nil, "GET", "/account/signin?"+testOAuthQuery, nil)
	if w.Code != 200 {
		t.Fatalf("signin page: %d", w.Code)
	}
	cookie := sessionCookieFrom(s, w, nil)
	m := queryParamsField.FindStringSubmatch(w.Body.String())
	if m == nil || html.UnescapeString(m[1]) != testOAuthQuery {
		t.Fatalf("signin page lost the oauth query: %v", m)
	}

	w = browserDo(s, cookie, "POST", "/account/signin", url.Values{
		"username":     {acct.Handle},
		"password":     {acct.Password},
		"query_params": {html.UnescapeString(m[1])},
	})
	if w.Code != 303 || w.Header().Get("Location") != "/account/signin/verify" {
		t.Fatalf("password step: %d %q", w.Code, w.Header().Get("Location"))
	}
	return sessionCookieFrom(s, w, cookie)
}

// Signing in from the OAuth flow with a second factor must end up back on
// /oauth/authorize, without asking for the password again on the code page.
func TestSigninWithSecondFactorKeepsOAuthRequest(t *testing.T) {
	s, acct := recoveryServer(t)
	s.loadTemplates()
	secret := addTestTOTP(t, s, acct.Did)

	cookie := passwordStep(t, s, acct)

	w := browserDo(s, cookie, "GET", "/account/signin/verify", nil)
	if w.Code != 200 {
		t.Fatalf("code page: %d %s", w.Code, w.Header().Get("Location"))
	}
	cookie = sessionCookieFrom(s, w, cookie)
	body := w.Body.String()
	if !strings.Contains(body, `name="token"`) || strings.Contains(body, `name="password"`) {
		t.Fatalf("code page should ask only for a code:\n%s", body)
	}
	if !strings.Contains(body, acct.Handle) {
		t.Fatalf("code page should say which account is signing in")
	}

	// A wrong code stays on the code page and keeps the pending sign-in.
	w = browserDo(s, cookie, "POST", "/account/signin/verify", url.Values{"token": {"000000"}})
	if w.Code != 303 || w.Header().Get("Location") != "/account/signin/verify" {
		t.Fatalf("wrong code: %d %q", w.Code, w.Header().Get("Location"))
	}
	cookie = sessionCookieFrom(s, w, cookie)

	w = browserDo(s, cookie, "POST", "/account/signin/verify", url.Values{"token": {totp.Code(secret, time.Now())}})
	if w.Code != 303 {
		t.Fatalf("code step: %d %s", w.Code, w.Body.String())
	}
	if got, want := w.Header().Get("Location"), "/oauth/authorize?"+testOAuthQuery; got != want {
		t.Fatalf("after the code, Location = %q, want %q", got, want)
	}
	cookie = sessionCookieFrom(s, w, cookie)

	// Now signed in: the account page loads, and the code page is done.
	if w := browserDo(s, cookie, "GET", "/account", nil); w.Code != 200 {
		t.Fatalf("account page after sign-in: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := browserDo(s, cookie, "GET", "/account/signin/verify", nil); w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/account/signin") {
		t.Fatalf("code page after sign-in should restart: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestSigninVerifyWithoutPendingSigninRestarts(t *testing.T) {
	s, _ := recoveryServer(t)
	s.loadTemplates()
	w := browserDo(s, nil, "POST", "/account/signin/verify", url.Values{"token": {"123456"}})
	if w.Code != 303 || w.Header().Get("Location") != "/account/signin" {
		t.Fatalf("got %d %q", w.Code, w.Header().Get("Location"))
	}
}

// A password reset between the two steps cancels the pending sign-in, and
// the user goes back to the start of the same OAuth request.
func TestSigninVerifyCancelledBySessionVersionChange(t *testing.T) {
	s, acct := recoveryServer(t)
	s.loadTemplates()
	secret := addTestTOTP(t, s, acct.Did)
	cookie := passwordStep(t, s, acct)

	if err := s.db.Exec(context.Background(), "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, acct.Did).Error; err != nil {
		t.Fatal(err)
	}

	w := browserDo(s, cookie, "POST", "/account/signin/verify", url.Values{"token": {totp.Code(secret, time.Now())}})
	if want := "/account/signin?" + testOAuthQuery; w.Code != 303 || w.Header().Get("Location") != want {
		t.Fatalf("got %d %q, want %q", w.Code, w.Header().Get("Location"), want)
	}
	cookie = sessionCookieFrom(s, w, cookie)
	if w := browserDo(s, cookie, "GET", "/account", nil); w.Code != 303 {
		t.Fatalf("should not be signed in, got %d", w.Code)
	}
}

func TestPendingSigninExpires(t *testing.T) {
	sess := sessions.NewSession(nil, "test")
	now := time.Now()
	setPendingSignin(sess, pendingSignin{Did: "did:plc:abc", SessionVersion: 2, Return: "request_uri=x"}, now)

	if p, ok := getPendingSignin(sess, now.Add(pendingSigninLifetime-time.Second)); !ok || p.Did != "did:plc:abc" || p.SessionVersion != 2 {
		t.Fatalf("pending sign-in should still be valid: %+v %v", p, ok)
	}
	p, ok := getPendingSignin(sess, now.Add(pendingSigninLifetime+time.Second))
	if ok {
		t.Fatal("pending sign-in should have expired")
	}
	if p.Return != "request_uri=x" {
		t.Fatal("an expired sign-in should still report where it was headed")
	}

	clearPendingSignin(sess)
	if _, ok := getPendingSignin(sess, now); ok {
		t.Fatal("cleared sign-in is still pending")
	}
}

func TestOauthReturnQuery(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "",
		"add=1":                "",
		"?request_uri=abc":     "request_uri=abc",
		"client_id=x&state=%3": "",
		"client_id=x&state=y":  "client_id=x&state=y",
	} {
		if got := oauthReturnQuery(in); got != want {
			t.Errorf("oauthReturnQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

// "Add another account" from the dashboard must reach the sign-in form while
// signed in, and land back on the dashboard rather than /oauth/authorize.
func TestSigninAddAccountFromDashboard(t *testing.T) {
	s, acct, cookie := manageServer(t)
	other := s.createTestAccount(t, "second.pds.test")

	w := browserDo(s, cookie, "GET", "/account/signin?add=1", nil)
	if w.Code != 200 {
		t.Fatalf("add account page: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = browserDo(s, cookie, "POST", "/account/signin", url.Values{
		"username": {other.Handle}, "password": {other.Password}, "query_params": {"add=1"},
	})
	if w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatalf("got %d %q", w.Code, w.Header().Get("Location"))
	}
	cookie = sessionCookieFrom(s, w, cookie)
	body := browserDo(s, cookie, "GET", "/account", nil).Body.String()
	if !strings.Contains(body, acct.Handle) || !strings.Contains(body, other.Handle) {
		t.Fatal("both accounts should be in the switcher")
	}
}

func insertOauthToken(t *testing.T, s *Server, tok provider.OauthToken) provider.OauthToken {
	t.Helper()
	if tok.Token == "" {
		tok.Token = "at-" + oauth.GenerateTokenId()
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = oauth.GenerateRefreshToken()
	}
	if tok.ClientAuth.Method == "" {
		tok.ClientAuth.Method = "private_key_jwt"
	}
	if err := s.db.Create(context.Background(), &tok, nil).Error; err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestLiveOauthTokensSkipsDeadSessions(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	now := time.Now()
	day := 24 * time.Hour

	live := insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now.Add(-30 * day), UpdatedAt: now.Add(-day)}})
	livePublic := insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://b.example/c.json", ClientAuth: provider.ClientAuth{Method: "none"}, Model: gorm.Model{CreatedAt: now.Add(-3 * day), UpdatedAt: now.Add(-time.Hour)}})
	// Public client past its two-week lifetime.
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://b.example/c.json", ClientAuth: provider.ClientAuth{Method: "none"}, Model: gorm.Model{CreatedAt: now.Add(-20 * day), UpdatedAt: now.Add(-time.Hour)}})
	// Not refreshed in over three months.
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now.Add(-200 * day), UpdatedAt: now.Add(-100 * day)}})
	// From before a password reset.
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://a.example/c.json", SessionVersion: -1, Model: gorm.Model{CreatedAt: now.Add(-day), UpdatedAt: now}})
	// Someone else's.
	insertOauthToken(t, s, provider.OauthToken{Sub: "did:plc:someoneelse", ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now.Add(-day), UpdatedAt: now}})

	got, err := s.liveOauthTokens(context.Background(), acct.Did, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != livePublic.ID || got[1].ID != live.ID {
		ids := []uint{}
		for _, g := range got {
			ids = append(ids, g.ID)
		}
		t.Fatalf("live tokens = %v, want [%d %d]", ids, livePublic.ID, live.ID)
	}
}

func TestLoadAccountAppsGroupsByClient(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	repo, err := s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)}})
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://b.example/c.json", Model: gorm.Model{CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute)}})
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour)}})

	// No client manager: names fall back to hostnames without any lookups.
	apps, err := s.loadAccountApps(context.Background(), repo, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 {
		t.Fatalf("got %d apps, want 2", len(apps))
	}
	if apps[0].Name != "b.example" || len(apps[0].Sessions) != 1 {
		t.Fatalf("most recently used app should be first: %+v", apps[0])
	}
	if apps[1].Name != "a.example" || len(apps[1].Sessions) != 2 || apps[1].Initial != "A" {
		t.Fatalf("a.example should hold both of its sessions: %+v", apps[1])
	}
}

func TestPruneOauthTokens(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	now := time.Now()
	day := 24 * time.Hour
	keep := insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "c", Model: gorm.Model{CreatedAt: now.Add(-day), UpdatedAt: now}})
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "c", Model: gorm.Model{CreatedAt: now.Add(-800 * day), UpdatedAt: now}})
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "c", Model: gorm.Model{CreatedAt: now.Add(-100 * day), UpdatedAt: now.Add(-95 * day)}})
	insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "c", SessionVersion: -1, Model: gorm.Model{CreatedAt: now.Add(-day), UpdatedAt: now}})

	n, err := s.pruneOauthTokens(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("pruned %d, want 3", n)
	}
	var ids []uint
	if err := s.db.Raw(context.Background(), "SELECT id FROM oauth_tokens", nil).Scan(&ids).Error; err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != keep.ID {
		t.Fatalf("remaining tokens = %v, want [%d]", ids, keep.ID)
	}
}

func TestAccountRevokeOnlyTouchesOwnSessions(t *testing.T) {
	s, acct, cookie := manageServer(t)
	now := time.Now()
	mine := insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now, UpdatedAt: now}})
	mine2 := insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now, UpdatedAt: now}})
	theirs := insertOauthToken(t, s, provider.OauthToken{Sub: "did:plc:someoneelse", ClientId: "https://a.example/c.json", Model: gorm.Model{CreatedAt: now, UpdatedAt: now}})

	count := func(id uint) int64 {
		var n int64
		s.db.Raw(context.Background(), "SELECT COUNT(*) FROM oauth_tokens WHERE id = ?", nil, id).Scan(&n)
		return n
	}

	// Cross-site posts are refused.
	if w := browserDo(s, cookie, "POST", "/account/revoke", url.Values{"id": {itoa(mine.ID)}}); w.Code != 403 || count(mine.ID) != 1 {
		t.Fatalf("cross-site revoke: %d", w.Code)
	}

	if w := sameOriginPost(s, cookie, "/account/revoke", url.Values{"id": {itoa(theirs.ID)}}); w.Code != 303 || count(theirs.ID) != 1 {
		t.Fatal("revoking another account's session must do nothing")
	}
	if w := sameOriginPost(s, cookie, "/account/revoke", url.Values{"id": {itoa(mine.ID)}}); w.Code != 303 || count(mine.ID) != 0 || count(mine2.ID) != 1 {
		t.Fatal("revoke by id should remove exactly that session")
	}
	if w := sameOriginPost(s, cookie, "/account/revoke", url.Values{"client_id": {"https://a.example/c.json"}}); w.Code != 303 || count(mine2.ID) != 0 || count(theirs.ID) != 1 {
		t.Fatal("revoke by app should remove only this account's sessions for it")
	}
}

func itoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }

func insertAuthRequest(t *testing.T, s *Server, id string) {
	t.Helper()
	req := provider.OauthAuthorizationRequest{
		RequestId: id,
		ClientId:  "https://app.example/client-metadata.json",
		Parameters: provider.ParRequest{
			ResponseType: "code",
			RedirectURI:  "https://app.example/callback",
			State:        "state-123",
			Scope:        "atproto",
		},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := s.db.Create(context.Background(), &req, nil).Error; err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeRejectRedirectsToAppWithAccessDenied(t *testing.T) {
	s, _, cookie := manageServer(t)
	insertAuthRequest(t, s, "req-reject")

	w := browserDo(s, cookie, "POST", "/oauth/authorize", url.Values{
		"request_uri":      {oauth.EncodeRequestUri("req-reject")},
		"accept_or_reject": {"reject"},
	})
	if w.Code != 303 {
		t.Fatalf("reject: %d %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if loc.Host != "app.example" || loc.Path != "/callback" || q.Get("error") != "access_denied" || q.Get("state") != "state-123" || q.Get("iss") != "https://"+testHostname {
		t.Fatalf("reject redirect = %s", loc)
	}
	var n int64
	s.db.Raw(context.Background(), "SELECT COUNT(*) FROM oauth_authorization_requests WHERE request_id = ?", nil, "req-reject").Scan(&n)
	if n != 0 {
		t.Fatal("a rejected request should not be usable afterwards")
	}
}

func TestAuthorizePostWhenSignedOutKeepsRequest(t *testing.T) {
	s, _ := recoveryServer(t)
	s.loadTemplates()
	insertAuthRequest(t, s, "req-signed-out")
	reqURI := oauth.EncodeRequestUri("req-signed-out")

	w := browserDo(s, nil, "POST", "/oauth/authorize", url.Values{"request_uri": {reqURI}, "accept_or_reject": {"accept"}})
	want := "/account/signin?" + url.Values{"client_id": {"https://app.example/client-metadata.json"}, "request_uri": {reqURI}}.Encode()
	if w.Code != 303 || w.Header().Get("Location") != want {
		t.Fatalf("got %d %q, want %q", w.Code, w.Header().Get("Location"), want)
	}
}

func TestAuthorizeAcceptOnlyOnce(t *testing.T) {
	s, _, cookie := manageServer(t)
	insertAuthRequest(t, s, "req-once")
	form := url.Values{"request_uri": {oauth.EncodeRequestUri("req-once")}, "accept_or_reject": {"accept"}}

	w := browserDo(s, cookie, "POST", "/oauth/authorize", form)
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "https://app.example/callback?") {
		t.Fatalf("accept: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := browserDo(s, cookie, "POST", "/oauth/authorize", form); w.Code != 400 {
		t.Fatalf("second accept should fail, got %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestDescribeScopes(t *testing.T) {
	perms := describeScopes("atproto transition:generic repo:app.bsky.feed.post bogus::")
	var titles []string
	for _, p := range perms {
		titles = append(titles, p.Title)
	}
	got := strings.Join(titles, "|")
	want := "Know who you are|Full access to your account|Change your data|Other permissions"
	if got != want {
		t.Fatalf("titles = %q, want %q", got, want)
	}
	if !perms[1].Sensitive || perms[0].Sensitive {
		t.Fatal("full access should be marked sensitive, identity should not")
	}
}
