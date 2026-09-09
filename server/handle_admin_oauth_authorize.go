package server

import (
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

// Admin-minted OAuth authorization.
//
// This endpoint exists so an operator (or an agent acting with operator
// authority) can complete the consent step of the atproto OAuth flow without a
// browser: instead of an HTML cookie session clicking "Accept" on
// /oauth/authorize, the admin supplies a pending PAR request_uri plus the DID
// of the account being authorized. It performs exactly what the human consent
// path performs (mints a code, persists sub/code/accepted) and nothing more:
// all client-side binding — DPoP jkt and PKCE verification — is still enforced
// at /oauth/token, untouched. The admin can authorize any account's grant;
// that is the intended operator-owns-everything model for self-hosted
// single-operator PDSes.
//
// This is a plain /admin/* route (Basic auth via handleAdminMiddleware, the
// same gate as the admin invite-code XRPCs) rather than an XRPC, because
// com.atproto.* is the protocol-owned namespace and this is a management
// operation, not a protocol one.
type AdminOauthAuthorizeRequest struct {
	RequestUri string `json:"requestUri" validate:"required"`
	Did        string `json:"did" validate:"required,atproto-did"`
}

type AdminOauthAuthorizeResponse struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectUri string `json:"redirectUri"`
	Iss         string `json:"iss"`
}

func (s *Server) handleAdminOauthAuthorize(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAdminOauthAuthorize")

	var req AdminOauthAuthorizeRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding request", "error", err)
		return helpers.InputError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		logger.Error("error validating request", "error", err)
		return helpers.InputError(e, nil)
	}

	reqId, err := oauth.DecodeRequestUri(req.RequestUri)
	if err != nil {
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	var authReq provider.OauthAuthorizationRequest
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&authReq).Error; err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}
	if authReq.RequestId == "" {
		return helpers.InputError(e, to.StringPtr("no authorization request found for the supplied request uri"))
	}

	if time.Now().After(authReq.ExpiresAt) {
		return helpers.InputError(e, to.StringPtr("the request has expired"))
	}

	if authReq.Sub != nil || authReq.Code != nil {
		return helpers.InputError(e, to.StringPtr("this request was already authorized"))
	}

	// Unlike the human consent path we deliberately do not look the client up
	// here: the token endpoint re-authenticates the client on exchange, and
	// admin Basic auth is the authority boundary for this endpoint.

	repo, err := s.getRepoActorByDid(ctx, req.Did)
	if err != nil {
		return helpers.InputError(e, to.StringPtr("unable to find actor"))
	}

	code := oauth.GenerateCode()

	if err := s.db.Exec(ctx, "UPDATE oauth_authorization_requests SET sub = ?, code = ?, accepted = ?, ip = ? WHERE request_id = ?", nil, repo.Repo.Did, code, true, e.RealIP(), reqId).Error; err != nil {
		logger.Error("error updating authorization request", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, AdminOauthAuthorizeResponse{
		Code:        code,
		State:       authReq.Parameters.State,
		RedirectUri: authReq.Parameters.RedirectURI,
		Iss:         "https://" + s.config.Hostname,
	})
}
