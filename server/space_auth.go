package server

import (
	"strings"

	"github.com/labstack/echo/v4"
)

const spaceCredentialScheme = "Atproto-Space"

// spaceReadMiddleware authenticates a space read: a request presenting a
// space credential (Authorization: Atproto-Space ...) is verified by the
// handler, anything else goes through the account session middlewares.
func (s *Server) spaceReadMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	session := s.handleLegacySessionMiddleware(s.handleOauthSessionMiddleware(next))
	return func(e echo.Context) error {
		if isSpaceCredentialRequest(e) {
			return next(e)
		}
		return session(e)
	}
}

func isSpaceCredentialRequest(e echo.Context) bool {
	for _, v := range e.Request().Header.Values("Authorization") {
		if scheme, _, ok := strings.Cut(v, " "); ok && strings.EqualFold(scheme, spaceCredentialScheme) {
			return true
		}
	}
	return false
}

// spaceAuthFromRequest returns the caller of a space read: a verified space
// credential, or an account session.
func (s *Server) spaceAuthFromRequest(e echo.Context) (*spaceAuth, error) {
	if isSpaceCredentialRequest(e) {
		cred, err := s.verifySpaceCredentialRequest(e)
		if err != nil {
			return nil, err
		}
		return &spaceAuth{credential: cred}, nil
	}
	return accountAuth(e)
}
