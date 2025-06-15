package server

import (
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
)

type OauthParRequest struct {
	ResponseType        string   `form:"response_type" validate:"required"`
	CodeChallenge       string   `form:"code_challenge" validate:"required"`
	CodeChallengeMethod string   `form:"code_challenge_method" validate:"required"`
	ClientID            string   `form:"client_id" validate:"required"`
	State               string   `form:"state" validate:"required"`
	RedirectURI         string   `form:"redirect_uri" validate:"required"`
	Scope               []string `form:"scope" validate:"required"`
	ClientAssertionType *string  `form:"client_assertion_type"`
	ClientAssertion     *string  `form:"client_assertion"`
	LoginHint           *string  `form:"login_hint"`
}

type OauthParResponse struct {
	ExpiresIn   float64 `json:"expires_in"`
	RequrestURI string  `json:"request_uri"`
}

func (s *Server) handleOauthPar(e echo.Context) error {
	var parRequest OauthParRequest
	if err := e.Bind(&parRequest); err != nil {
		s.logger.Error("error binding for par request", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(parRequest); err != nil {
		s.logger.Error("missing parameters for par request", "error", err)
		return helpers.InputError(e, nil)
	}

	dpopProof, err := s.oauthCheckDpopProof(e.Request().Method, e.Request().URL.String(), e.Request().Header, nil)
	if err != nil {
		s.logger.Error("error getting dpop proof", "error", err)
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	// do the thing

	return e.JSON(200, OauthParResponse{
		ExpiresIn:   0,
		RequrestURI: "https://google.com",
	})
}
