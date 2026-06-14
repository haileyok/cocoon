package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
)

// runAccessMiddleware drives handleLegacySessionMiddleware for a bearer access
// token against a non-refresh protected route, reporting whether the wrapped
// handler ran and the resulting status code.
func runAccessMiddleware(t *testing.T, s *Server, token string) (called bool, code int) {
	t.Helper()

	next := func(c echo.Context) error {
		called = true
		return c.String(http.StatusOK, "ok")
	}

	c, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.server.getSession", "", map[string]string{
		"authorization": "Bearer " + token,
	})
	if err := s.handleLegacySessionMiddleware(next)(c); err != nil {
		c.Error(err)
	}
	return called, rec.Code
}

// TestLegacyMiddlewareAccessTokenRevocation verifies that deleting a session's
// access-token row (as signout / refresh rotation do) actually invalidates the
// access JWT, rather than leaving it usable until expiry.
func TestLegacyMiddlewareAccessTokenRevocation(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	ra, err := s.getRepoActorByDid(ctx, acct.Did)
	if err != nil {
		t.Fatalf("load repo: %v", err)
	}

	sess, err := s.createSession(ctx, &ra.Repo)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	t.Run("live access token accepted", func(t *testing.T) {
		called, code := runAccessMiddleware(t, s, sess.AccessToken)
		if !called {
			t.Fatal("next handler not reached for a live session")
		}
		if code != http.StatusOK {
			t.Fatalf("got status %d, want 200", code)
		}
	})

	t.Run("revoked access token rejected", func(t *testing.T) {
		if err := s.db.Exec(ctx, "DELETE FROM tokens WHERE token = ?", nil, sess.AccessToken).Error; err != nil {
			t.Fatalf("delete token row: %v", err)
		}

		called, code := runAccessMiddleware(t, s, sess.AccessToken)
		if called {
			t.Fatal("next handler reached for a revoked access token")
		}
		if code == http.StatusOK {
			t.Fatalf("expected rejection status, got %d", code)
		}
	})
}
