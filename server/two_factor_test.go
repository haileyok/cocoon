package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
)

func (s *Server) setTwoFactor(t *testing.T, did, code string, expiresAt time.Time) {
	t.Helper()
	if err := s.db.Exec(context.Background(),
		"UPDATE repos SET two_factor_type = ?, two_factor_code = ?, two_factor_code_expires_at = ? WHERE did = ?",
		nil, models.TwoFactorTypeEmail, code, expiresAt, did,
	).Error; err != nil {
		t.Fatalf("set two factor: %v", err)
	}
}

func (s *Server) twoFactorCode(t *testing.T, did string) *string {
	t.Helper()
	var repo models.Repo
	if err := s.db.Raw(context.Background(), "SELECT * FROM repos WHERE did = ?", nil, did).Scan(&repo).Error; err != nil {
		t.Fatalf("read repo: %v", err)
	}
	return repo.TwoFactorCode
}

func TestCreateSessionTwoFactorClearedOnSuccess(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	const code = "ABCDE-FGHIJ"
	s.setTwoFactor(t, acct.Did, code, time.Now().Add(10*time.Minute))

	body := fmt.Sprintf(`{"identifier":%q,"password":%q,"authFactorToken":%q}`, acct.Handle, acct.Password, code)
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createSession", body, nil)

	if err := s.handleCreateSession(c); err != nil {
		c.Error(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with a valid 2FA code, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.twoFactorCode(t, acct.Did); got != nil {
		t.Fatalf("two_factor_code should be cleared after a successful login, still set to %q", *got)
	}
}

func TestCreateSessionTwoFactorWrongCode(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "bob.pds.test")
	const code = "ABCDE-FGHIJ"
	s.setTwoFactor(t, acct.Did, code, time.Now().Add(10*time.Minute))

	body := fmt.Sprintf(`{"identifier":%q,"password":%q,"authFactorToken":%q}`, acct.Handle, acct.Password, "WRONG-CODES")
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createSession", body, nil)

	if err := s.handleCreateSession(c); err != nil {
		c.Error(err)
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("expected rejection for a wrong 2FA code, got 200")
	}
	if got := s.twoFactorCode(t, acct.Did); got == nil || *got != code {
		t.Fatalf("two_factor_code must remain set after a failed attempt, got %v", got)
	}
}
