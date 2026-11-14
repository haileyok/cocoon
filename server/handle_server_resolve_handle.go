package server

import (
	"context"
	"errors"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleResolveHandle(e echo.Context) error {
	logger := s.logger.With("name", "handleServerResolveHandle")

	type Resp struct {
		Did string `json:"did"`
	}

	handle := e.QueryParam("handle")

	if handle == "" {
		return helpers.InputError(e, to.StringPtr("Handle must be supplied in request."))
	}

	parsed, err := syntax.ParseHandle(handle)
	if err != nil {
		return helpers.InputError(e, to.StringPtr("Invalid handle."))
	}

	ctx := context.WithValue(e.Request().Context(), "skip-cache", true)
	did, err := s.passport.ResolveHandle(ctx, parsed.String())
	if err != nil {
		// A handle that nothing claims is the caller's mistake, not a server fault:
		// the reference PDS answers 400 InvalidRequest here. Returning 500 makes
		// clients retry a request that can never succeed and buries real failures
		// in the error log.
		if errors.Is(err, identity.ErrHandleNotFound) {
			logger.Debug("handle does not resolve", "handle", parsed.String(), "error", err)
			return helpers.InputError(e, to.StringPtr("Unable to resolve handle"))
		}
		logger.Error("error resolving handle", "handle", parsed.String(), "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, Resp{
		Did: did,
	})
}
