package server

import (
	"net/http"

	"github.com/gorilla/sessions"
)

func applyAccountSessionOptions(sess *sessions.Session, maxAge int) {
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}
