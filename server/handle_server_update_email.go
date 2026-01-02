package server

import (
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerUpdateEmailRequest struct {
	Email           string `json:"email" validate:"required"`
	EmailAuthFactor bool   `json:"emailAuthFactor"`
	Token           string `json:"token"`
}

func (s *Server) handleServerUpdateEmail(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerUpdateEmail")

	urepo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoServerUpdateEmailRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	// To disable email auth factor a token is required.
	// To enable email auth factor a token is not required.
	// If updating an email address, a token will be sent anyway
	if urepo.EmailAuthFactor && req.EmailAuthFactor == false && req.Token == "" {
		return helpers.InvalidTokenError(e)
	}

	if req.Token != "" {
		if urepo.EmailUpdateCode == nil || urepo.EmailUpdateCodeExpiresAt == nil {
			return helpers.InvalidTokenError(e)
		}

		if *urepo.EmailUpdateCode != req.Token {
			return helpers.InvalidTokenError(e)
		}

		if time.Now().UTC().After(*urepo.EmailUpdateCodeExpiresAt) {
			return helpers.ExpiredTokenError(e)
		}
	}

	query := "UPDATE repos SET email_update_code = NULL, email_update_code_expires_at = NULL, email_auth_factor = ?,  email = ?"

	if urepo.Email != req.Email {
		query += ",email_confirmed_at = NULL"
	}

	query += " WHERE did = ?"

	if err := s.db.Exec(ctx, query, nil, req.EmailAuthFactor, req.Email, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
