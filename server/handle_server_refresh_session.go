package server

import (
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerRefreshSessionResponse struct {
	AccessJwt  string  `json:"accessJwt"`
	RefreshJwt string  `json:"refreshJwt"`
	Handle     string  `json:"handle"`
	Did        string  `json:"did"`
	Active     bool    `json:"active"`
	Status     *string `json:"status,omitempty"`
}

func (s *Server) handleRefreshSession(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerRefreshSession")

	token := e.Get("token").(string)
	repo := e.Get("repo").(*models.RepoActor)

	if err := s.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE token = ?", nil, token).Error; err != nil {
		logger.Error("error getting refresh token from db", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec(ctx, "DELETE FROM tokens WHERE refresh_token = ?", nil, token).Error; err != nil {
		logger.Error("error deleting access token from db", "error", err)
		return helpers.ServerError(e, nil)
	}

	sess, err := s.createSession(ctx, &repo.Repo)
	if err != nil {
		logger.Error("error creating new session for refresh", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, ComAtprotoServerRefreshSessionResponse{
		AccessJwt:  sess.AccessToken,
		RefreshJwt: sess.RefreshToken,
		Handle:     repo.Handle,
		Did:        repo.Repo.Did,
		Active:     repo.Active(),
		Status:     repo.Status(),
	})
}
