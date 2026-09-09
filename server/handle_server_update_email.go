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

	// A token is required to disable email auth factor, and — when the
	// current email address is confirmed — to change the address itself.
	// The emailed token is delivered to the *current* (confirmed) address
	// by requestEmailUpdate, proving control of it before the account is
	// re-pointed at a new address.
	if urepo.TwoFactorType != models.TwoFactorTypeNone && req.EmailAuthFactor == false && req.Token == "" {
		return helpers.InvalidTokenError(e)
	}

	emailChanging := urepo.Email != req.Email
	if emailChanging && urepo.EmailConfirmedAt != nil && req.Token == "" {
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

	twoFactorType := models.TwoFactorTypeNone
	if req.EmailAuthFactor {
		twoFactorType = models.TwoFactorTypeEmail
	}

	query := "UPDATE repos SET email_update_code = NULL, email_update_code_expires_at = NULL, two_factor_type = ?,  email = ?"

	if urepo.Email != req.Email {
		query += ",email_confirmed_at = NULL"
	}

	query += " WHERE did = ?"

	if err := s.db.Exec(ctx, query, nil, twoFactorType, req.Email, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
