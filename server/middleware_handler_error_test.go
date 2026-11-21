package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// TestLegacyMiddlewarePassesHandlerErrorsThrough guards against reporting a
// handler failure as an auth failure. The middleware used to replace any error
// from the wrapped handler with 400 InvalidToken, so a proxied request that
// timed out upstream told the client its session was bad and dropped the real
// error before echo could log it.
func TestLegacyMiddlewarePassesHandlerErrorsThrough(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	acct := s.createTestAccount(t, "bob.pds.test")
	ra, err := s.getRepoActorByDid(ctx, acct.Did)
	if err != nil {
		t.Fatalf("load repo: %v", err)
	}
	sess, err := s.createSession(ctx, &ra.Repo)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	upstreamErr := errors.New(`Get "https://api.bsky.app/xrpc/app.bsky.notification.getUnreadCount": http2: timeout awaiting response headers`)
	for _, tc := range []struct {
		name     string
		err      error
		wantCode int
	}{
		{"upstream failure", upstreamErr, http.StatusInternalServerError},
		{"http error", echo.NewHTTPError(http.StatusNotFound), http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := newRequestContext(http.MethodGet, "/xrpc/app.bsky.notification.getUnreadCount", "", map[string]string{
				"authorization": "Bearer " + sess.AccessToken,
			})
			err := s.handleLegacySessionMiddleware(func(echo.Context) error { return tc.err })(c)
			if !errors.Is(err, tc.err) {
				t.Errorf("middleware returned %v, want the handler's error", err)
			}
			if err != nil {
				c.Error(err)
			}
			if rec.Code != tc.wantCode || strings.Contains(rec.Body.String(), "InvalidToken") {
				t.Fatalf("got %d %s, want %d without InvalidToken", rec.Code, rec.Body.String(), tc.wantCode)
			}
		})
	}
}
