package server

import (
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerConfirmEmailRequest struct {
	Email string `json:"email" validate:"required"`
	Token string `json:"token" validate:"required"`
}

func (s *Server) handleServerConfirmEmail(e echo.Context) error {
	urepo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoServerConfirmEmailRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	if urepo.EmailVerificationCode == nil {
		return helpers.InputError(e, to.StringPtr("ExpiredToken"))
	}

	if *urepo.EmailVerificationCode != req.Token {
		return helpers.InputError(e, to.StringPtr("InvalidToken"))
	}

	if err := s.db.Exec("UPDATE repos SET email_verification_token = NULL, email_confirmed_at = NOW() WHERE did = ?", urepo.Repo.Did).Error; err != nil {
		s.logger.Error("error updating user", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
