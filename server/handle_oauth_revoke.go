package server

import (
	"errors"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

type OauthRevokeRequest struct {
	provider.AuthenticateClientRequestBase
	Token         string  `form:"token" json:"token"`
	TokenTypeHint *string `form:"token_type_hint" json:"token_type_hint,omitempty"`
}

// handleOauthRevoke implements RFC 7009 token revocation. It removes the matching
// access/refresh token from the database and always responds 200, even when the
// token is unknown or the client cannot be authenticated, per RFC 7009 §2.2.
func (s *Server) handleOauthRevoke(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleOauthRevoke")

	var req OauthRevokeRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding revoke request", "error", err)
		return helpers.InputError(e, nil)
	}

	if req.Token == "" {
		return e.NoContent(200)
	}

	// Revocation must not hard-fail on a missing or malformed DPoP proof; the
	// client is authenticated as at the token endpoint, but a public client
	// (none + DPoP) may not present a usable proof here.
	proof, err := s.oauthProvider.DpopManager.CheckProof(e.Request().Method, e.Request().URL.String(), e.Request().Header, nil)
	if err != nil && !errors.Is(err, dpop.ErrUseDpopNonce) {
		logger.Warn("ignoring dpop proof error during revocation", "error", err)
		proof = nil
	}

	client, _, authErr := s.oauthProvider.AuthenticateClient(ctx, req.AuthenticateClientRequestBase, proof, &provider.AuthenticateClientOptions{
		AllowMissingDpopProof: true,
	})

	query := "DELETE FROM oauth_tokens WHERE (token = ? OR refresh_token = ?)"
	args := []any{req.Token, req.Token}
	if authErr == nil && client != nil {
		query += " AND client_id = ?"
		args = append(args, client.Metadata.ClientID)
	} else if authErr != nil {
		logger.Warn("could not authenticate client during revocation", "error", authErr)
	}

	if err := s.db.Exec(ctx, query, nil, args...).Error; err != nil {
		logger.Error("error deleting token during revocation", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
