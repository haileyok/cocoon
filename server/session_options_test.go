package server

import (
	"net/http"
	"testing"

	"github.com/gorilla/sessions"
)

func TestApplyAccountSessionOptions(t *testing.T) {
	s := newTestServer(t) // Version "test" -> non-dev

	sess := &sessions.Session{}
	s.applyAccountSessionOptions(sess, 3600)

	if sess.Options == nil {
		t.Fatal("options were not set")
	}
	if !sess.Options.Secure {
		t.Fatal("Secure must be set for non-dev builds")
	}
	if !sess.Options.HttpOnly {
		t.Fatal("HttpOnly must remain set")
	}
	if sess.Options.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", sess.Options.SameSite)
	}
	if sess.Options.MaxAge != 3600 {
		t.Fatalf("MaxAge = %d, want 3600", sess.Options.MaxAge)
	}

	// Plain local dev (default Version "dev") serves over http, so Secure must
	// stay off there or the cookie would never be sent.
	s.config.Version = "dev"
	devSess := &sessions.Session{}
	s.applyAccountSessionOptions(devSess, 3600)
	if devSess.Options.Secure {
		t.Fatal("Secure must be off in dev mode")
	}
}
