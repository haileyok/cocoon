package server

import (
	"errors"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

type OauthParResponse struct {
	ExpiresIn  int64  `json:"expires_in"`
	RequestURI string `json:"request_uri"`
}

func (s *Server) handleOauthPar(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleOauthPar")

	var parRequest provider.ParRequest
	if err := e.Bind(&parRequest); err != nil {
		logger.Error("error binding for par request", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(parRequest); err != nil {
		logger.Error("missing parameters for par request", "error", err)
		return helpers.InputError(e, nil)
	}

	// TODO: this seems wrong. should be a way to get the entire request url i believe, but this will work for now
	dpopProof, err := s.oauthProvider.DpopManager.CheckProof(e.Request().Method, "https://"+s.config.Hostname+e.Request().URL.String(), e.Request().Header, nil)
	if err != nil {
		if errors.Is(err, dpop.ErrUseDpopNonce) {
			nonce := s.oauthProvider.NextNonce()
			if nonce != "" {
				e.Response().Header().Set("DPoP-Nonce", nonce)
				e.Response().Header().Add("access-control-expose-headers", "DPoP-Nonce")
			}
			logger.Error("nonce error: use_dpop_nonce", "headers", e.Request().Header)
			return e.JSON(400, map[string]string{
				"error": "use_dpop_nonce",
			})
		}
		logger.Error("error getting dpop proof", "error", err)
		return helpers.InputError(e, nil)
	}

	client, clientAuth, err := s.oauthProvider.AuthenticateClient(e.Request().Context(), parRequest.AuthenticateClientRequestBase, dpopProof, &provider.AuthenticateClientOptions{
		// rfc9449
		// https://github.com/bluesky-social/atproto/blob/main/packages/oauth/oauth-provider/src/oauth-provider.ts#L473
		AllowMissingDpopProof: true,
	})
	if err != nil {
		logger.Error("error authenticating client", "client_id", parRequest.ClientID, "error", err)
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	if parRequest.DpopJkt == nil {
		if client.Metadata.DpopBoundAccessTokens {
			parRequest.DpopJkt = to.StringPtr(dpopProof.JKT)
		}
	} else {
		if !client.Metadata.DpopBoundAccessTokens {
			msg := "dpop bound access tokens are not enabled for this client"
			logger.Error(msg)
			return helpers.InputError(e, &msg)
		}

		if dpopProof.JKT != *parRequest.DpopJkt {
			msg := "supplied dpop jkt does not match header dpop jkt"
			logger.Error(msg)
			return helpers.InputError(e, &msg)
		}
	}

	eat := time.Now().Add(constants.ParExpiresIn)
	id := oauth.GenerateRequestId()

	authRequest := &provider.OauthAuthorizationRequest{
		RequestId:  id,
		ClientId:   client.Metadata.ClientID,
		ClientAuth: *clientAuth,
		Parameters: parRequest,
		ExpiresAt:  eat,
	}

	if err := s.db.Create(ctx, authRequest, nil).Error; err != nil {
		logger.Error("error creating auth request in db", "error", err)
		return helpers.ServerError(e, nil)
	}

	uri := oauth.EncodeRequestUri(id)

	return e.JSON(201, OauthParResponse{
		ExpiresIn:  int64(constants.ParExpiresIn.Seconds()),
		RequestURI: uri,
	})
}
