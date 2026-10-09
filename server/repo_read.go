package server

import (
	"errors"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func (s *Server) handleRepoReadMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		ctx := e.Request().Context()
		syncRead := strings.HasPrefix(e.Request().URL.Path, "/xrpc/com.atproto.sync.")
		did := e.QueryParam("did")
		if !syncRead {
			did = e.QueryParam("repo")
			if did != "" && !strings.HasPrefix(did, "did:") {
				actor, err := s.getActorByHandle(ctx, did)
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return next(e)
				}
				if err != nil {
					return helpers.ServerError(e, nil)
				}
				did = actor.Did
			}
		}
		if did == "" {
			return next(e)
		}
		repo, err := s.getRepoActorByDid(ctx, did)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return next(e)
		}
		if err != nil {
			return helpers.ServerError(e, nil)
		}
		if repo.Active() {
			return next(e)
		}

		deny := func() error { return helpers.InputError(e, to.StringPtr("RepoDeactivated")) }
		if !syncRead || e.Request().Header.Get("Authorization") == "" {
			return deny()
		}
		allow := func(e echo.Context) error {
			e.Set("inactiveRepoRead", did)
			return next(e)
		}
		if username, password, ok := e.Request().BasicAuth(); ok {
			if s.config.AdminPassword != "" && username == "admin" && password == s.config.AdminPassword {
				return allow(e)
			}
			return deny()
		}
		parts := strings.Split(e.Request().Header.Get("Authorization"), " ")
		if len(parts) != 2 || (!strings.EqualFold(parts[0], "Bearer") && parts[0] != "DPoP") {
			return helpers.InvalidTokenError(e)
		}
		// Only verified account sessions grant access to an inactive owner's data.
		owner := func(e echo.Context) error {
			kind := e.Get("credentialKind")
			if e.Get("did") != did || (kind != credentialLegacyAccess && kind != credentialOAuth) {
				return deny()
			}
			return allow(e)
		}
		return s.handleLegacySessionMiddleware(s.handleOauthSessionMiddleware(owner))(e)
	}
}
