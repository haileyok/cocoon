package server

import (
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleOauthSignout(e echo.Context) error {
	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	sess.Values = map[any]any{}

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	reqUri := e.QueryParam("request_uri")

	redirect := "/account/signin"
	if reqUri != "" {
		redirect += "?" + e.QueryParams().Encode()
	}

	return e.Redirect(303, redirect)
}
