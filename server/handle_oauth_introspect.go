package server

import (
	"errors"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

// OauthIntrospectRequest is the body of an RFC 7662 token introspection request.
type OauthIntrospectRequest struct {
	provider.AuthenticateClientRequestBase
	Token         string `form:"token" json:"token" query:"token"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint" query:"token_type_hint"`
}

// handleOauthIntrospect implements the RFC 7662 token introspection endpoint
// advertised in the authorization-server metadata. The client is authenticated
// and asked about a token it was issued. Active tokens return their claims;
// unknown, expired, or revoked tokens return {"active": false}.
func (s *Server) handleOauthIntrospect(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleOauthIntrospect")

	var req OauthIntrospectRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding introspect request", "error", err)
		return helpers.InvalidRequestOauthError(e, "could not parse request")
	}

	// DPoP is optional here, mirroring the token/revoke endpoints.
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

	inactive := map[string]any{"active": false}

	if req.Token == "" {
		return e.JSON(200, inactive)
	}

	// Only reveal tokens that were issued to the requesting client.
	var oauthToken provider.OauthToken
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_tokens WHERE client_id = ? AND (token = ? OR refresh_token = ?)", nil, client.Metadata.ClientID, req.Token, req.Token).Scan(&oauthToken).Error; err != nil {
		logger.Error("error looking up token", "error", err)
		return helpers.ServerError(e, nil)
	}

	if oauthToken.Token == "" || time.Now().After(oauthToken.ExpiresAt) {
		return e.JSON(200, inactive)
	}

	tokenType := "Bearer"
	if oauthToken.Parameters.DpopJkt != nil {
		tokenType = "DPoP"
	}

	return e.JSON(200, map[string]any{
		"active":     true,
		"scope":      oauthToken.Parameters.Scope,
		"client_id":  oauthToken.ClientId,
		"token_type": tokenType,
		"sub":        oauthToken.Sub,
		"aud":        s.config.Did,
		"iat":        oauthToken.CreatedAt.Unix(),
		"exp":        oauthToken.ExpiresAt.Unix(),
	})
}
