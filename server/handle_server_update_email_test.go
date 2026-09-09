package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
)

// updateEmail security rules under test:
//
//  1. Changing a *confirmed* email address requires the emailed token
//     (requestEmailUpdate delivers it to the current address). Without this,
//     any holder of an access token could swap the account email and then
//     chain the unauthenticated password-reset flow to take over the
//     account, defeating email 2FA.
//  2. Disabling the email auth factor on a 2FA-enabled account requires the
//     token (existing behavior, kept).
//  3. Changing an *unconfirmed* email stays token-free (registration-style
//     correction of a typo'd address) — the address was never proven, so
//     there is nothing to defend.

const updateEmailTestToken = "ABCDE-FGHIJ"

// setEmailConfirmed flips the account's email confirmation state.
func (s *Server) setEmailConfirmed(t *testing.T, did string, confirmed bool) {
	t.Helper()
	ts := time.Now().Add(-time.Hour)
	var val *time.Time
	if confirmed {
		val = &ts
	}
	if err := s.db.Exec(context.Background(), "UPDATE repos SET email_confirmed_at = ? WHERE did = ?", nil, val, did).Error; err != nil {
		t.Fatalf("set email_confirmed_at: %v", err)
	}
}

// setEmailUpdateCode seeds a valid emailed update token on the account.
func (s *Server) setEmailUpdateCode(t *testing.T, did, code string) {
	t.Helper()
	eat := time.Now().Add(10 * time.Minute).UTC()
	if err := s.db.Exec(context.Background(), "UPDATE repos SET email_update_code = ?, email_update_code_expires_at = ? WHERE did = ?", nil, code, eat, did).Error; err != nil {
		t.Fatalf("set email_update_code: %v", err)
	}
}

func callUpdateEmail(t *testing.T, s *Server, acct *testAccount, body string) (int, string) {
	t.Helper()
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.updateEmail", body, nil)
	repo, err := s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	c.Set("repo", repo)
	if err := s.handleServerUpdateEmail(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

func (s *Server) currentEmail(t *testing.T, did string) string {
	t.Helper()
	repo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	return repo.Repo.Email
}

// TestUpdateEmailConfirmedChangeRequiresToken: with a confirmed email, an
// address change without the emailed token must be rejected.
func TestUpdateEmailConfirmedChangeRequiresToken(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)

	code, _ := callUpdateEmail(t, s, acct, `{"email":"attacker@evil.example","emailAuthFactor":true}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for confirmed-email change without token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != acct.Email {
		t.Fatalf("email was changed without a token: %q", got)
	}
}

// TestUpdateEmailConfirmedChangeWithTokenSucceeds: the same change with a
// valid emailed token succeeds.
func TestUpdateEmailConfirmedChangeWithTokenSucceeds(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	s.setEmailUpdateCode(t, acct.Did, updateEmailTestToken)

	code, _ := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":"newaddr@example.com","emailAuthFactor":true,"token":%q}`, updateEmailTestToken))
	if code != http.StatusOK {
		t.Fatalf("expected 200 for confirmed-email change with valid token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != "newaddr@example.com" {
		t.Fatalf("email not updated: %q", got)
	}
}

// TestUpdateEmailDisableAuthFactorStillRequiresToken: 2FA-disable keeps
// requiring the token (existing behavior).
func TestUpdateEmailDisableAuthFactorStillRequiresToken(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	if err := s.db.Exec(context.Background(), "UPDATE repos SET two_factor_type = ? WHERE did = ?", nil, models.TwoFactorTypeEmail, acct.Did).Error; err != nil {
		t.Fatalf("set 2fa: %v", err)
	}

	// Same address, disabling the factor, no token -> rejected.
	code, _ := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":%q,"emailAuthFactor":false}`, acct.Email))
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 2FA-disable without token, got %d", code)
	}

	// With the token it succeeds.
	s.setEmailUpdateCode(t, acct.Did, updateEmailTestToken)
	code, _ = callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":%q,"emailAuthFactor":false,"token":%q}`, acct.Email, updateEmailTestToken))
	if code != http.StatusOK {
		t.Fatalf("expected 200 for 2FA-disable with token, got %d", code)
	}
}

// TestUpdateEmailUnconfirmedChangeWithoutToken: changing an unconfirmed
// address stays token-free.
func TestUpdateEmailUnconfirmedChangeWithoutToken(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, false)

	code, _ := callUpdateEmail(t, s, acct, `{"email":"fixed-typo@example.com","emailAuthFactor":true}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for unconfirmed-email change without token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != "fixed-typo@example.com" {
		t.Fatalf("email not updated: %q", got)
	}
}

// TestUpdateEmailWrongTokenRejected: a bad token must not authorize the change.
func TestUpdateEmailWrongTokenRejected(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	s.setEmailUpdateCode(t, acct.Did, updateEmailTestToken)

	code, _ := callUpdateEmail(t, s, acct, `{"email":"attacker@evil.example","emailAuthFactor":true,"token":"WRONG-CODE"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != acct.Email {
		t.Fatalf("email was changed with a wrong token: %q", got)
	}
}
