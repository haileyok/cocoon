package server

import (
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleOauthAuthorize(e echo.Context) error {
	reqUri := e.QueryParam("request_uri")
	if reqUri == "" {
		return helpers.InputError(e, to.StringPtr("no request uri"))
	}

	reqId, err := decodeRequestUri(reqUri)
	if err != nil {
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	var req models.OauthAuthorizationRequest
	if err := s.db.Raw("SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&req).Error; err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	clientId := e.QueryParam("client_id")
	if clientId != req.ClientId {
		return helpers.InputError(e, to.StringPtr("client id does not match the client id for the supplied request"))
	}

	client, err := s.oauthClientMan.GetClient(e.Request().Context(), req.ClientId)
	if err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	scopes := strings.Split(req.Parameters.Scope, " ")
	appName := client.Metadata.ClientName

	data := map[string]any{
		"Scopes":  scopes,
		"AppName": appName,
	}

	return e.Render(200, "signin.html", data)
}
