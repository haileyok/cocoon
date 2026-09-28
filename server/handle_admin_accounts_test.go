package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func adminAuthHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin-test-password"))
}

// callAdminGet drives a middleware-wrapped admin GET endpoint. Empty auth
// sends no Authorization header.
func callAdminGet(t *testing.T, s *Server, handler echo.HandlerFunc, target, auth string) *httptest.ResponseRecorder {
	t.Helper()

	headers := map[string]string{}
	if auth != "" {
		headers["Authorization"] = auth
	}
	c, rec := newRequestContext(http.MethodGet, target, "", headers)

	h := s.handleAdminMiddleware(handler)
	if err := h(c); err != nil {
		c.Error(err)
	}
	return rec
}

// TestAdminAccountsList verifies the list endpoint returns seeded accounts
// with the documented fields, in a JSON array.
func TestAdminAccountsList(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")
	s.createTestAccount(t, "bob.pds.test")

	rec := callAdminGet(t, s, s.handleAdminAccounts, "/admin/accounts", adminAuthHeader())
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body %s)", rec.Code, rec.Body.String())
	}

	var accounts []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(accounts))
	}

	// Ordering is deterministic enough to require the fields; find alice.
	var found map[string]any
	for _, a := range accounts {
		if a["handle"] == alice.Handle {
			found = a
		}
	}
	if found == nil {
		t.Fatalf("alice not in list: %s", rec.Body.String())
	}
	for _, key := range []string{"did", "handle", "email", "active", "status", "createdAt"} {
		if _, ok := found[key]; !ok {
			t.Fatalf("expected key %q in %v", key, found)
		}
	}
	if found["did"] != alice.Did {
		t.Fatalf("expected did %q, got %v", alice.Did, found["did"])
	}
	if found["email"] != alice.Email {
		t.Fatalf("expected email %q, got %v", alice.Email, found["email"])
	}
	if found["active"] != true {
		t.Fatalf("expected active true, got %v", found["active"])
	}
	if found["status"] != nil && found["status"] != "" {
		t.Fatalf("expected empty status, got %v", found["status"])
	}
}

// TestAdminAccountsListPagination verifies limit and offset behave.
func TestAdminAccountsListPagination(t *testing.T) {
	s := newTestServer(t)
	s.createTestAccount(t, "alice.pds.test")
	s.createTestAccount(t, "bob.pds.test")
	s.createTestAccount(t, "carol.pds.test")

	names := func(rec *httptest.ResponseRecorder) []string {
		t.Helper()
		var accounts []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &accounts); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		out := []string{}
		for _, a := range accounts {
			out = append(out, a["handle"].(string))
		}
		return out
	}

	rec := callAdminGet(t, s, s.handleAdminAccounts, "/admin/accounts?limit=1", adminAuthHeader())
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := names(rec); len(got) != 1 {
		t.Fatalf("expected 1 account with limit=1, got %d (%v)", len(got), got)
	}

	all := names(callAdminGet(t, s, s.handleAdminAccounts, "/admin/accounts", adminAuthHeader()))
	if len(all) != 3 {
		t.Fatalf("expected 3 accounts, got %v", all)
	}

	skipped := names(callAdminGet(t, s, s.handleAdminAccounts, "/admin/accounts?limit=1&offset=1", adminAuthHeader()))
	if len(skipped) != 1 || skipped[0] != all[1] {
		t.Fatalf("expected offset=1 to skip first account: all=%v skipped=%v", all, skipped)
	}
}

// TestAdminAccountsListAuthRejection verifies missing/wrong Basic auth is a
// 400 InputError per handleAdminMiddleware's existing behavior.
func TestAdminAccountsListAuthRejection(t *testing.T) {
	s := newTestServer(t)
	s.createTestAccount(t, "alice.pds.test")

	for name, auth := range map[string]string{
		"missing auth":   "",
		"wrong password": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:nope")),
	} {
		t.Run(name, func(t *testing.T) {
			rec := callAdminGet(t, s, s.handleAdminAccounts, "/admin/accounts", auth)
			if rec.Code != 400 {
				t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAdminAccountsListInvalidParams verifies negative limit/offset are input
// errors, not 500s.
func TestAdminAccountsListInvalidParams(t *testing.T) {
	s := newTestServer(t)

	for _, target := range []string{"/admin/accounts?limit=-1", "/admin/accounts?offset=-5", "/admin/accounts?limit=abc"} {
		t.Run(target, func(t *testing.T) {
			rec := callAdminGet(t, s, s.handleAdminAccounts, target, adminAuthHeader())
			if rec.Code != 400 {
				t.Fatalf("expected 400 for %s, got %d (body %s)", target, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAdminAccountDetail verifies the detail endpoint returns the full record
// including derived active/status, for a known DID.
func TestAdminAccountDetail(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")

	// set email confirmed so the derived field is observable
	now := time.Now()
	if err := s.db.Exec(t.Context(), "UPDATE repos SET email_confirmed_at = ? WHERE did = ?", nil, now, alice.Did).Error; err != nil {
		t.Fatalf("set email confirmed: %v", err)
	}

	rec := callAdminGet(t, s, s.handleAdminAccount, "/admin/account?did="+alice.Did, adminAuthHeader())
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body %s)", rec.Code, rec.Body.String())
	}

	var acct map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &acct); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if acct["did"] != alice.Did {
		t.Fatalf("expected did %q, got %v", alice.Did, acct["did"])
	}
	if acct["handle"] != alice.Handle {
		t.Fatalf("expected handle %q, got %v", alice.Handle, acct["handle"])
	}
	if acct["email"] != alice.Email {
		t.Fatalf("expected email %q, got %v", alice.Email, acct["email"])
	}
	if acct["emailConfirmed"] != true {
		t.Fatalf("expected emailConfirmed true, got %v", acct["emailConfirmed"])
	}
	if acct["active"] != true {
		t.Fatalf("expected active true, got %v", acct["active"])
	}
	if acct["twoFactorType"] != string(models.TwoFactorTypeNone) {
		t.Fatalf("expected twoFactorType %q, got %v", models.TwoFactorTypeNone, acct["twoFactorType"])
	}
	for _, key := range []string{"status", "createdAt", "rev"} {
		if _, ok := acct[key]; !ok {
			t.Fatalf("expected key %q in %v", key, acct)
		}
	}
}

// TestAdminAccountDetailStatusDerived verifies a deactivated repo reports
// status "deactivated" and active false.
func TestAdminAccountDetailStatusDerived(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")

	if err := s.db.Exec(t.Context(), "UPDATE repos SET deactivated = true WHERE did = ?", nil, alice.Did).Error; err != nil {
		t.Fatalf("deactivate repo: %v", err)
	}

	rec := callAdminGet(t, s, s.handleAdminAccount, "/admin/account?did="+alice.Did, adminAuthHeader())
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body %s)", rec.Code, rec.Body.String())
	}

	var acct map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &acct); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if acct["status"] != "deactivated" {
		t.Fatalf("expected status deactivated, got %v", acct["status"])
	}
	if acct["active"] != false {
		t.Fatalf("expected active false, got %v", acct["active"])
	}
}

// TestAdminAccountDetailErrors verifies unknown DID, missing did param, and
// auth rejection.
func TestAdminAccountDetailErrors(t *testing.T) {
	s := newTestServer(t)
	alice := s.createTestAccount(t, "alice.pds.test")

	t.Run("unknown did", func(t *testing.T) {
		rec := callAdminGet(t, s, s.handleAdminAccount, "/admin/account?did=did:plc:doesnotexistaaaaaaaaaaa", adminAuthHeader())
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing did", func(t *testing.T) {
		rec := callAdminGet(t, s, s.handleAdminAccount, "/admin/account", adminAuthHeader())
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid did", func(t *testing.T) {
		rec := callAdminGet(t, s, s.handleAdminAccount, "/admin/account?did=not-a-did", adminAuthHeader())
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing auth", func(t *testing.T) {
		rec := callAdminGet(t, s, s.handleAdminAccount, "/admin/account?did="+alice.Did, "")
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
	})
}
