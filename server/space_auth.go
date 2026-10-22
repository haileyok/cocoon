package server

import (
	"strings"

	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
)

// spaceReadMiddleware authenticates a space read: a request presenting a
// space credential (Authorization: Atproto-Space-Credential ...) is verified by the
// handler, anything else goes through the account session middlewares.
func (s *Server) spaceReadMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	session := s.handleLegacySessionMiddleware(s.handleOauthSessionMiddleware(next))
	return func(e echo.Context) error {
		if err := checkAuthScheme(e); err != nil {
			return writeSpaceResult(e, nil, err)
		}
		if isSpaceCredentialRequest(e) {
			return next(e)
		}
		return session(e)
	}
}

// checkAuthScheme refuses an authorization scheme a space request can't use,
// as the reference's parseAuthorizationHeader does. This includes the
// Atproto-Space scheme that credentials were presented with before the
// October 22, 2026 alpha.
func checkAuthScheme(e echo.Context) error {
	v := e.Request().Header.Get("Authorization")
	if v == "" {
		return nil
	}
	scheme, _, ok := strings.Cut(v, " ")
	if !ok {
		return errInvalid("InvalidToken", "Malformed authorization header")
	}
	for _, known := range []string{"Basic", "Bearer", "DPoP", space.CredentialScheme} {
		if strings.EqualFold(scheme, known) {
			return nil
		}
	}
	return errInvalid("InvalidToken", "Unsupported authorization type: %s", scheme)
}

func isSpaceCredentialRequest(e echo.Context) bool {
	for _, v := range e.Request().Header.Values("Authorization") {
		if scheme, _, ok := strings.Cut(v, " "); ok && strings.EqualFold(scheme, space.CredentialScheme) {
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
