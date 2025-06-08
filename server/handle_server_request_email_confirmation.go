package server

import (
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleServerRequestEmailConfirmation(e echo.Context) error {
	urepo := e.Get("repo").(*models.RepoActor)

	if urepo.EmailConfirmedAt != nil {
		return helpers.InputError(e, to.StringPtr("InvalidRequest"))
	}

	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	if err := s.db.Exec("UPDATE repos SET email_verification_code = ?, email_verification_code_expires_at = ? WHERE did = ?", nil, code, eat, urepo.Repo.Did).Error; err != nil {
		s.logger.Error("error updating user", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.sendEmailVerification(urepo.Email, urepo.Handle, code); err != nil {
		s.logger.Error("error sending mail", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
