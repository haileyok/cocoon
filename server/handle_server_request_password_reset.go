package server

import (
	"fmt"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerRequestPasswordResetRequest struct {
	Email string `json:"email" validate:"required"`
}

func (s *Server) handleServerRequestPasswordReset(e echo.Context) error {
	ctx := e.Request().Context()

	urepo, ok := e.Get("repo").(*models.RepoActor)
	if !ok {
		var req ComAtprotoServerRequestPasswordResetRequest
		if err := e.Bind(&req); err != nil {
			return err
		}

		if err := e.Validate(req); err != nil {
			return err
		}

		murepo, err := s.getRepoActorByEmail(ctx, req.Email)
		if err != nil {
			return err
		}

		urepo = murepo
	}

	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	if err := s.db.Exec(ctx, "UPDATE repos SET password_reset_code = ?, password_reset_code_expires_at = ? WHERE did = ?", nil, code, eat, urepo.Repo.Did).Error; err != nil {
		s.logger.Error("error updating repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.sendPasswordReset(urepo.Email, urepo.Handle, code); err != nil {
		s.logger.Error("error sending email", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
