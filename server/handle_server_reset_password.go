package server

import (
	"errors"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ComAtprotoServerResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (s *Server) handleServerResetPassword(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerResetPassword")

	var req ComAtprotoServerResetPasswordRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.InputError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	var repo models.Repo
	if err := s.db.First(ctx, &repo, "password_reset_code = ? AND password_reset_code_expires_at > ?", req.Token, time.Now().UTC()).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return helpers.InvalidTokenError(e)
		}
		logger.Error("error looking up reset code", "error", err)
		return helpers.ServerError(e, nil)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		logger.Error("error creating hash", "error", err)
		return helpers.ServerError(e, nil)
	}

	err = s.db.ResetPassword(ctx, repo.Did, string(hash), &req.Token)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return helpers.InvalidTokenError(e)
	}
	if err != nil {
		logger.Error("error resetting password", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
