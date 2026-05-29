package server

import (
	"errors"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

// OauthRevokeRequest is the body of an RFC 7009 token revocation request. The
// embedded AuthenticateClientRequestBase carries the client authentication
// fields (client_id, optional client_assertion).
type OauthRevokeRequest struct {
	provider.AuthenticateClientRequestBase
	Token         string `form:"token" json:"token" query:"token"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint" query:"token_type_hint"`
}

// handleOauthRevoke implements the RFC 7009 token revocation endpoint. The
// client is authenticated, and any access or refresh token matching the
// supplied value that was issued to that client is deleted. Per RFC 7009 2.2
// the server responds 200 whether or not the token existed; only a malformed
// request or failed client authentication produces an error.
func (s *Server) handleOauthRevoke(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleOauthRevoke")

	var req OauthRevokeRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding revoke request", "error", err)
		return helpers.InvalidRequestOauthError(e, "could not parse request")
	}

	// DPoP is optional for this endpoint. CheckProof returns (nil, nil) when no
	// DPoP header is present, in which case we authenticate the client without a
	// proof (AllowMissingDpopProof). Mirror the token endpoint's nonce handling
	// for clients that do choose to send a proof.
	proof, err := s.oauthProvider.DpopManager.CheckProof(e.Request().Method, e.Request().URL.String(), e.Request().Header, nil)
	if err != nil {
		if errors.Is(err, dpop.ErrUseDpopNonce) {
			nonce := s.oauthProvider.NextNonce()
			if nonce != "" {
				e.Response().Header().Set("DPoP-Nonce", nonce)
				e.Response().Header().Add("access-control-expose-headers", "DPoP-Nonce")
			}
			return e.JSON(400, map[string]string{
				"error": "use_dpop_nonce",
			})
		}
		logger.Error("error checking dpop proof", "error", err)
		return helpers.InvalidRequestOauthError(e, "invalid dpop proof")
	}

	client, _, err := s.oauthProvider.AuthenticateClient(ctx, req.AuthenticateClientRequestBase, proof, &provider.AuthenticateClientOptions{
		AllowMissingDpopProof: true,
	})
	if err != nil {
		logger.Error("error authenticating client", "client_id", req.ClientID, "error", err)
		return helpers.InvalidRequestOauthError(e, err.Error())
	}

	// Delete the token if a value was supplied. Scoping by client_id satisfies
	// RFC 7009's requirement that the token was issued to the requesting client.
	// A missing or unknown token is a no-op and still returns 200.
	if req.Token != "" {
		if err := s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE client_id = ? AND (token = ? OR refresh_token = ?)", nil, client.Metadata.ClientID, req.Token, req.Token).Error; err != nil {
			logger.Error("error deleting token", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	return e.NoContent(200)
}
