package server

import (
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type ComAtprotoServerResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (s *Server) handleServerResetPassword(e echo.Context) error {
	urepo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoServerResetPasswordRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	if urepo.PasswordResetCode == nil || urepo.PasswordResetCodeExpiresAt == nil {
		return helpers.InputError(e, to.StringPtr("InvalidToken"))
	}

	if *urepo.PasswordResetCode != req.Token {
		return helpers.InvalidTokenError(e)
	}

	if time.Now().UTC().After(*urepo.PasswordResetCodeExpiresAt) {
		return helpers.ExpiredTokenError(e)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		s.logger.Error("error creating hash", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("UPDATE repos SET password_reset_code = NULL, password_reset_code_expires_at = NULL, password = ? WHERE did = ?", nil, hash, urepo.Repo.Did).Error; err != nil {
		s.logger.Error("error updating repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
