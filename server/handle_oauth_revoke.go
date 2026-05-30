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

	// Mirror the token endpoint's DPoP nonce handling. The proof is checked
	// without an access-token hash because RFC 7009 clients authenticate to the
	// endpoint rather than presenting the token as a resource-server bearer token.
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
		// Failed client authentication is invalid_client (401) per RFC 6749 5.2.
		logger.Error("error authenticating client", "client_id", req.ClientID, "error", err)
		return helpers.InvalidClientOauthError(e, err.Error())
	}

	// RFC 7009 2.1 requires the "token" parameter. An omitted parameter is a
	// malformed request (distinct from a valid revocation of an unknown token).
	if req.Token == "" {
		return helpers.InvalidRequestOauthError(e, "`token` is required")
	}

	// atproto clients are DPoP-bound. Require possession of the client's DPoP key
	// before deleting any known token, rather than treating a leaked token string
	// as enough authority to revoke a session.
	if client.Metadata.DpopBoundAccessTokens && proof == nil {
		return helpers.InvalidRequestOauthError(e, "dpop proof is required")
	}

	var oauthToken provider.OauthToken
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_tokens WHERE client_id = ? AND (token = ? OR refresh_token = ?)", nil, client.Metadata.ClientID, req.Token, req.Token).Scan(&oauthToken).Error; err != nil {
		logger.Error("error looking up token", "error", err)
		return helpers.ServerError(e, nil)
	}

	// Unknown token values are a no-op and still return 200 per RFC 7009.
	if oauthToken.Token == "" {
		return e.NoContent(200)
	}

	if client.Metadata.DpopBoundAccessTokens {
		if oauthToken.Parameters.DpopJkt == nil || *oauthToken.Parameters.DpopJkt != proof.JKT {
			return helpers.OauthInvalidTokenError(e)
		}
	}

	if err := s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE id = ?", nil, oauthToken.ID).Error; err != nil {
		logger.Error("error deleting token", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
