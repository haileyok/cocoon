package server

import (
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerGetSessionResponse struct {
	Handle          string  `json:"handle"`
	Did             string  `json:"did"`
	Email           *string `json:"email,omitempty"`
	EmailConfirmed  *bool   `json:"emailConfirmed,omitempty"`
	EmailAuthFactor *bool   `json:"emailAuthFactor,omitempty"`
	Active          bool    `json:"active"`
	Status          *string `json:"status,omitempty"`
}

func (s *Server) handleGetSession(e echo.Context) error {
	repo := e.Get("repo").(*models.RepoActor)

	response := ComAtprotoServerGetSessionResponse{
		Handle: repo.Handle,
		Did:    repo.Repo.Did,
		Active: repo.Active(),
		Status: repo.Status(),
	}
	if s.hasEndpointScope(e, "account:email") {
		response.Email = &repo.Email
		response.EmailConfirmed = to.BoolPtr(repo.EmailConfirmedAt != nil)
		hasSecondFactor, err := s.hasSecondFactor(e.Request().Context(), &repo.Repo)
		if err != nil {
			s.logger.Error("checking second factor", "error", err)
			return helpers.ServerError(e, nil)
		}
		// The protocol only knows about email 2FA; report any second factor
		// so clients show sign-in codes as enabled.
		response.EmailAuthFactor = to.BoolPtr(hasSecondFactor)
	}
	return e.JSON(200, response)
}
