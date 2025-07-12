package server

import (
	"net/url"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleOauthAuthorizeGet(e echo.Context) error {
	reqUri := e.QueryParam("request_uri")
	if reqUri == "" {
		// render page for logged out dev
		if s.config.Version == "dev" {
			return e.Render(200, "authorize.html", map[string]any{
				"Scopes":     []string{"atproto", "transition:generic"},
				"AppName":    "DEV MODE AUTHORIZATION PAGE",
				"Handle":     "paula.cocoon.social",
				"RequestUri": "",
			})
		}
		return helpers.InputError(e, to.StringPtr("no request uri"))
	}

	repo, _, err := s.getSessionRepoOrErr(e)
	if err != nil {
		return e.Redirect(303, "/account/signin?"+e.QueryParams().Encode())
	}

	reqId, err := oauth.DecodeRequestUri(reqUri)
	if err != nil {
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	var req provider.OauthAuthorizationRequest
	if err := s.db.Raw("SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&req).Error; err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	clientId := e.QueryParam("client_id")
	if clientId != req.ClientId {
		return helpers.InputError(e, to.StringPtr("client id does not match the client id for the supplied request"))
	}

	client, err := s.oauthProvider.ClientManager.GetClient(e.Request().Context(), req.ClientId)
	if err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	scopes := strings.Split(req.Parameters.Scope, " ")
	appName := client.Metadata.ClientName

	data := map[string]any{
		"Scopes":      scopes,
		"AppName":     appName,
		"RequestUri":  reqUri,
		"QueryParams": e.QueryParams().Encode(),
		"Handle":      repo.Actor.Handle,
	}

	return e.Render(200, "authorize.html", data)
}

type OauthAuthorizePostRequest struct {
	RequestUri    string `form:"request_uri"`
	AcceptOrRejct string `form:"accept_or_reject"`
}

func (s *Server) handleOauthAuthorizePost(e echo.Context) error {
	repo, _, err := s.getSessionRepoOrErr(e)
	if err != nil {
		return e.Redirect(303, "/account/signin")
	}

	var req OauthAuthorizePostRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding authorize post request", "error", err)
		return helpers.InputError(e, nil)
	}

	reqId, err := oauth.DecodeRequestUri(req.RequestUri)
	if err != nil {
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	var authReq provider.OauthAuthorizationRequest
	if err := s.db.Raw("SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&authReq).Error; err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	client, err := s.oauthProvider.ClientManager.GetClient(e.Request().Context(), authReq.ClientId)
	if err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	// TODO: figure out how im supposed to actually redirect
	if req.AcceptOrRejct == "reject" {
		return e.Redirect(303, client.Metadata.ClientURI)
	}

	if time.Now().After(authReq.ExpiresAt) {
		return helpers.InputError(e, to.StringPtr("the request has expired"))
	}

	if authReq.Sub != nil || authReq.Code != nil {
		return helpers.InputError(e, to.StringPtr("this request was already authorized"))
	}

	code := oauth.GenerateCode()

	if err := s.db.Exec("UPDATE oauth_authorization_requests SET sub = ?, code = ?, accepted = ?, ip = ? WHERE request_id = ?", nil, repo.Repo.Did, code, true, e.RealIP(), reqId).Error; err != nil {
		s.logger.Error("error updating authorization request", "error", err)
		return helpers.ServerError(e, nil)
	}

	q := url.Values{}
	q.Set("state", authReq.Parameters.State)
	q.Set("iss", "https://"+s.config.Hostname)
	q.Set("code", code)

	hashOrQuestion := "?"
	if authReq.ClientAuth.Method != "private_key_jwt" {
		hashOrQuestion = "#"
	}

	return e.Redirect(303, authReq.Parameters.RedirectURI+hashOrQuestion+q.Encode())
}
