package server

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

type HandleOauthAuthorizeGetInput struct {
	RequestUri string `query:"request_uri"`
}

func (s *Server) handleOauthAuthorizeGet(e echo.Context) error {
	ctx := e.Request().Context()

	logger := s.logger.With("name", "handleOauthAuthorizeGet")

	var input HandleOauthAuthorizeGetInput
	if err := e.Bind(&input); err != nil {
		logger.Error("error binding request", "err", err)
		return fmt.Errorf("error binding request")
	}

	var reqId string
	if input.RequestUri != "" {
		id, err := oauth.DecodeRequestUri(input.RequestUri)
		if err != nil {
			logger.Error("no request uri found in input", "url", e.Request().URL.String())
			return helpers.InputError(e, to.StringPtr("no request uri"))
		}
		reqId = id
	} else {
		var parRequest provider.ParRequest
		if err := e.Bind(&parRequest); err != nil {
			s.logger.Error("error binding for standard auth request", "error", err)
			return helpers.InputError(e, to.StringPtr("InvalidRequest"))
		}

		if err := e.Validate(parRequest); err != nil {
			// render page for logged out dev
			if s.config.Version == "dev" && parRequest.ClientID == "" {
				return e.Render(200, "authorize.html", map[string]any{
					"Scopes":       []string{"atproto", "transition:generic"},
					"Permissions":  describeScopes("atproto transition:generic"),
					"AppName":      "DEV MODE AUTHORIZATION PAGE",
					"Handle":       "paula.cocoon.social",
					"RequestUri":   "",
					"Accounts":     []string{},
					"ActiveDid":    "",
					"HasLoginHint": false,
				})
			}
			return helpers.InputError(e, to.StringPtr("no request uri and invalid parameters"))
		}

		client, clientAuth, err := s.oauthProvider.AuthenticateClient(ctx, parRequest.AuthenticateClientRequestBase, nil, &provider.AuthenticateClientOptions{
			AllowMissingDpopProof: true,
		})
		if err != nil {
			s.logger.Error("error authenticating client in standard request", "client_id", parRequest.ClientID, "error", err)
			return helpers.ServerError(e, to.StringPtr(err.Error()))
		}

		if !client.IsRedirectURIAllowed(parRequest.RedirectURI) {
			s.logger.Error("redirect_uri is not registered for client", "client_id", parRequest.ClientID, "redirect_uri", parRequest.RedirectURI)
			return helpers.InputError(e, to.StringPtr("invalid_request"))
		}

		if err := s.validateRequestedScopes(ctx, parRequest.Scope); err != nil {
			s.logger.Error("invalid requested scope", "client_id", parRequest.ClientID, "scope", parRequest.Scope, "error", err)
			return e.JSON(400, map[string]string{
				"error":             "invalid_scope",
				"error_description": err.Error(),
			})
		}

		if parRequest.DpopJkt == nil {
			if client.Metadata.DpopBoundAccessTokens {
			}
		} else {
			if !client.Metadata.DpopBoundAccessTokens {
				msg := "dpop bound access tokens are not enabled for this client"
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
			s.logger.Error("error creating auth request in db", "error", err)
			return helpers.ServerError(e, nil)
		}

		input.RequestUri = oauth.EncodeRequestUri(id)
		reqId = id

	}

	var req provider.OauthAuthorizationRequest
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&req).Error; err != nil {
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

	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	hasLoginHint := req.Parameters.LoginHint != nil && *req.Parameters.LoginHint != ""
	if hasLoginHint {
		did, err := s.resolveLoginHintToDid(ctx, *req.Parameters.LoginHint)
		if err != nil || !slices.Contains(getSessionDids(sess), did) {
			return e.Redirect(303, "/account/signin?"+e.QueryParams().Encode())
		}

		setActiveSessionDid(sess, did)
		s.applyAccountSessionOptions(sess, int(AccountSessionMaxAge.Seconds()))
		if err := sess.Save(e.Request(), e.Response()); err != nil {
			return helpers.ServerError(e, to.StringPtr(err.Error()))
		}
	}

	repo, _, accounts, err := s.getSessionRepoAndAccountsFromSessionOrErr(e, ctx, sess)
	if err != nil {
		if !errors.Is(err, ErrSessionUnauthenticated) {
			return helpers.ServerError(e, to.StringPtr(err.Error()))
		}
		return e.Redirect(303, "/account/signin?"+e.QueryParams().Encode())
	}

	appName := strings.TrimSpace(client.Metadata.ClientName)
	if appName == "" {
		appName = clientHost(client.Metadata.ClientID)
	}

	if req.Sub != nil || req.Code != nil {
		return s.renderMessage(e, 400, "Already signed in", "This sign-in request has already been used. Go back to "+appName+" and start again.")
	}
	now := time.Now()
	if now.After(req.ExpiresAt) {
		return s.renderMessage(e, 400, "Sign-in request expired", "This sign-in request timed out. Go back to "+appName+" and start again.")
	}
	// The request stays valid while someone is working through sign-in and
	// consent, however long a second factor takes.
	if err := s.db.Exec(ctx, "UPDATE oauth_authorization_requests SET expires_at = ? WHERE request_id = ? AND sub IS NULL", nil, now.Add(constants.ParExpiresIn), reqId).Error; err != nil {
		logger.Error("extending authorization request", "error", err)
	}

	data := map[string]any{
		"Scopes":       strings.Fields(req.Parameters.Scope),
		"Permissions":  describeScopes(req.Parameters.Scope),
		"AppName":      appName,
		"AppHost":      clientHost(client.Metadata.ClientID),
		"AppURI":       safeClientURI(client.Metadata.ClientURI),
		"RequestUri":   input.RequestUri,
		"QueryParams":  e.QueryParams().Encode(),
		"Handle":       repo.Actor.Handle,
		"Accounts":     accounts,
		"ActiveDid":    repo.Repo.Did,
		"HasLoginHint": hasLoginHint,
		"Hostname":     s.config.Hostname,
	}

	return e.Render(200, "authorize.html", data)
}

// authorizeRedirectURL builds the redirect back to the client, using the
// response mode the client asked for.
func (s *Server) authorizeRedirectURL(authReq *provider.OauthAuthorizationRequest, q url.Values) string {
	q.Set("state", authReq.Parameters.State)
	q.Set("iss", "https://"+s.config.Hostname)

	hashOrQuestion := "?"
	if authReq.Parameters.ResponseMode != nil {
		switch *authReq.Parameters.ResponseMode {
		case "fragment":
			hashOrQuestion = "#"
		case "query":
		default:
			if authReq.Parameters.ResponseType != "code" {
				hashOrQuestion = "#"
			}
		}
	} else if authReq.Parameters.ResponseType != "code" {
		hashOrQuestion = "#"
	}
	if hashOrQuestion == "?" && strings.Contains(authReq.Parameters.RedirectURI, "?") {
		hashOrQuestion = "&"
	}
	return authReq.Parameters.RedirectURI + hashOrQuestion + q.Encode()
}

type OauthAuthorizePostRequest struct {
	RequestUri    string `form:"request_uri"`
	AcceptOrRejct string `form:"accept_or_reject"`
}

func (s *Server) handleOauthAuthorizePost(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleOauthAuthorizePost")

	var req OauthAuthorizePostRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding authorize post request", "error", err)
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
		return s.renderMessage(e, 400, "Sign-in request not found", "This sign-in request doesn't exist or has already been used. Go back to the app and start again.")
	}

	repo, _, err := s.getSessionRepoOrErr(e)
	if err != nil {
		if !errors.Is(err, ErrSessionUnauthenticated) {
			return helpers.ServerError(e, to.StringPtr(err.Error()))
		}
		// Keep the OAuth request so signing in again returns to it.
		q := url.Values{"client_id": {authReq.ClientId}, "request_uri": {req.RequestUri}}
		return e.Redirect(303, "/account/signin?"+q.Encode())
	}

	if authReq.Sub != nil || authReq.Code != nil {
		return s.renderMessage(e, 400, "Already signed in", "This sign-in request has already been used. Go back to the app and start again.")
	}

	if req.AcceptOrRejct == "reject" {
		if err := s.db.Exec(ctx, "DELETE FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Error; err != nil {
			logger.Error("error deleting rejected authorization request", "error", err)
		}
		q := url.Values{}
		q.Set("error", "access_denied")
		q.Set("error_description", "The user denied the request")
		return e.Redirect(303, s.authorizeRedirectURL(&authReq, q))
	}

	if time.Now().After(authReq.ExpiresAt) {
		return s.renderMessage(e, 400, "Sign-in request expired", "This sign-in request timed out. Go back to the app and start again.")
	}

	code := oauth.GenerateCode()

	// Only the first accept wins, even if the form is submitted twice.
	res := s.db.Exec(ctx, "UPDATE oauth_authorization_requests SET sub = ?, session_version = ?, code = ?, accepted = ?, ip = ? WHERE request_id = ? AND sub IS NULL AND code IS NULL", nil, repo.Repo.Did, repo.SessionVersion, code, true, e.RealIP(), reqId)
	if res.Error != nil {
		logger.Error("error updating authorization request", "error", res.Error)
		return helpers.ServerError(e, nil)
	}
	if res.RowsAffected == 0 {
		return s.renderMessage(e, 400, "Already signed in", "This sign-in request has already been used. Go back to the app and start again.")
	}

	q := url.Values{}
	q.Set("code", code)
	return e.Redirect(303, s.authorizeRedirectURL(&authReq, q))
}
