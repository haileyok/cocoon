package server

import (
	"errors"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type OauthSigninRequest struct {
	Username   string `form:"username"`
	Password   string `form:"password"`
	RequestUri string `form:"request_uri"`
}

func (s *Server) getSessionRepoOrErr(e echo.Context) (*models.RepoActor, *sessions.Session, error) {
	sess, err := session.Get("session", e)
	if err != nil {
		return nil, nil, err
	}

	did, ok := sess.Values["did"].(string)
	if !ok {
		return nil, sess, errors.New("did was not set in session")
	}

	repo, err := s.getRepoActorByDid(did)
	if err != nil {
		return nil, sess, err
	}

	return repo, sess, nil
}

func getFlashesFromSession(e echo.Context, sess *sessions.Session) map[string]any {
	flashes := sess.Flashes("error")
	sess.Save(e.Request(), e.Response())
	return map[string]any{
		"errors": flashes,
	}
}

func (s *Server) handleOauthSigninGet(e echo.Context) error {
	_, sess, err := s.getSessionRepoOrErr(e)
	if err == nil {
		return e.Redirect(303, "/account")
	}

	return e.Render(200, "signin.html", map[string]any{
		"flashes":    getFlashesFromSession(e, sess),
		"RequestUri": e.QueryParam("request_uri"),
	})
}

func (s *Server) handleOauthSigninPost(e echo.Context) error {
	var req OauthSigninRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding sign in req", "error", err)
		return helpers.ServerError(e, nil)
	}

	sess, _ := session.Get("session", e)

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
	var err error
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
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/signin")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/signin")
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(AccountSessionMaxAge.Seconds()),
		HttpOnly: true,
	}

	sess.Values = map[any]any{}
	sess.Values["did"] = repo.Repo.Did

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	if req.RequestUri != "" {
		return e.Redirect(303, "/oauth/authorize?req_uri="+req.RequestUri)
	} else {
		return e.Redirect(303, "/account")
	}
}
