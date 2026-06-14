package server

import (
	"net/http"

	"github.com/gorilla/sessions"
)

func (s *Server) applyAccountSessionOptions(sess *sessions.Session, maxAge int) {
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.config.Version != "dev",
		SameSite: http.SameSiteLaxMode,
	}
}
