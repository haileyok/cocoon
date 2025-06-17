package server

import (
	"net/url"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func (s *Server) handleOauthAuthorizeGet(e echo.Context) error {
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
		"Scopes":     scopes,
		"AppName":    appName,
		"RequestUri": reqUri,
	}

	return e.Render(200, "signin.html", data)
}

type OauthAuthorizePostRequest struct {
	Username   string `form:"username"`
	Password   string `form:"password"`
	RequestUri string `form:"request_uri"`
}

func (s *Server) handleOauthAuthorizePost(e echo.Context) error {
	var req OauthAuthorizePostRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding authorize post request", "error", err)
		return helpers.InputError(e, nil)
	}

	reqId, err := decodeRequestUri(req.RequestUri)
	if err != nil {
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	var authReq models.OauthAuthorizationRequest
	if err := s.db.Raw("SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&authReq).Error; err != nil {
		return helpers.ServerError(e, to.StringPtr(err.Error()))
	}

	req.Username = strings.ToLower(req.Username)
	var idtype string
	if _, err := syntax.ParseDID(req.Username); err == nil {
		idtype = "did"
	} else if _, err := syntax.ParseHandle(req.Username); err == nil {
		idtype = "handle"
	} else {
		idtype = "email"
	}

	// TODO: we should make this a helper since we do it for the base create_session as well
	var repo models.RepoActor
	switch idtype {
	case "did":
		err = s.db.Raw("SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?", nil, req.Username).Scan(&repo).Error
	case "handle":
		err = s.db.Raw("SELECT r.*, a.* FROM actors a LEFT JOIN repos r ON a.did = r.did WHERE a.handle = ?", nil, req.Username).Scan(&repo).Error
	case "email":
		err = s.db.Raw("SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email = ?", nil, req.Username).Scan(&repo).Error
	}

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return helpers.InputError(e, to.StringPtr("InvalidRequest"))
		}

		s.logger.Error("erorr looking up repo", "endpoint", "com.atproto.server.createSession", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			s.logger.Error("erorr comparing hash and password", "error", err)
		}
		return helpers.InputError(e, to.StringPtr("incorrect username or password"))
	}

	if time.Now().After(authReq.ExpiresAt) {
		return helpers.InputError(e, to.StringPtr("the request has expired"))
	}

	if authReq.Sub != nil || authReq.Code != nil {
		return helpers.InputError(e, to.StringPtr("this request was already authorized"))
	}

	code := generateCode()

	if err := s.db.Exec("UPDATE oauth_authorization_requests SET sub = ?, code = ?, accepted = ? WHERE request_id = ?", nil, repo.Repo.Did, code, true, reqId).Error; err != nil {
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
