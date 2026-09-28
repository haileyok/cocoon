package server

import (
	"errors"
	"net/http"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// AccountRevokeInput names either one session (ID) or every session held by
// one app (ClientID).
type AccountRevokeInput struct {
	ID       uint   `form:"id"`
	ClientID string `form:"client_id"`
}

func (s *Server) handleAccountRevoke(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAccountRevoke")

	if !isSameOriginRequest(e) {
		return e.JSON(http.StatusForbidden, map[string]string{"error": "Forbidden"})
	}

	var req AccountRevokeInput
	if err := e.Bind(&req); err != nil {
		logger.Error("could not bind account revoke request", "error", err)
		return helpers.InputError(e, nil)
	}

	repo, sess, err := s.getSessionRepoOrErr(e)
	if err != nil {
		if !errors.Is(err, ErrSessionUnauthenticated) {
			return helpers.ServerError(e, nil)
		}
		return e.Redirect(303, "/account/signin")
	}

	var r *gorm.DB
	switch {
	case req.ID != 0:
		r = s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE sub = ? AND id = ?", nil, repo.Repo.Did, req.ID)
	case req.ClientID != "":
		r = s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE sub = ? AND client_id = ?", nil, repo.Repo.Did, req.ClientID)
	default:
		return helpers.InputError(e, nil)
	}
	affected := r.RowsAffected

	if r.Error != nil {
		logger.Error("couldnt delete oauth session for account", "did", repo.Repo.Did, "error", r.Error)
		sess.AddFlash("Unable to sign that app out. See server logs for more details.", "error")
	} else if affected == 0 {
		sess.AddFlash("That session was already signed out.", "success")
	} else if req.ClientID != "" {
		sess.AddFlash("Signed the app out everywhere.", "success")
	} else {
		sess.AddFlash("Session signed out.", "success")
	}
	sess.Save(e.Request(), e.Response())
	return e.Redirect(303, "/account")
}
