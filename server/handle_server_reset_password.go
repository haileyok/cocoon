package server

import (
	"errors"
	"time"

	"github.com/haileyok/cocoon/internal/db"
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

	invalidToken := errors.New("reset token is no longer valid")
	err = s.db.Transaction(ctx, func(tx *db.DB) error {
		result := tx.Exec(ctx, `UPDATE repos SET password_reset_code = NULL, password_reset_code_expires_at = NULL,
			password = ?, session_version = session_version + 1,
			two_factor_code = NULL, two_factor_code_expires_at = NULL
			WHERE did = ? AND password_reset_code = ? AND password_reset_code_expires_at > ?`, nil, string(hash), repo.Did, req.Token, time.Now().UTC())
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return invalidToken
		}
		for _, query := range []string{
			"DELETE FROM tokens WHERE did = ?",
			"DELETE FROM refresh_tokens WHERE did = ?",
			"DELETE FROM oauth_tokens WHERE sub = ?",
			"DELETE FROM oauth_authorization_requests WHERE sub = ?",
		} {
			if err := tx.Exec(ctx, query, nil, repo.Did).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, invalidToken) {
		return helpers.InvalidTokenError(e)
	}
	if err != nil {
		logger.Error("error resetting password", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
