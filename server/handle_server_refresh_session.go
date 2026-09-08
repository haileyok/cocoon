package server

import (
	"errors"
	"time"

	"github.com/haileyok/cocoon/internal/db"
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

	if e.Get("legacyRefresh") != true {
		return helpers.InvalidTokenError(e)
	}
	token := e.Get("token").(string)
	repo := e.Get("repo").(*models.RepoActor)

	invalidRefresh := errors.New("refresh token is no longer valid")
	var sess *Session
	err := s.db.Transaction(ctx, func(tx *db.DB) error {
		// Consume once, including when concurrent requests both passed middleware.
		result := tx.Exec(ctx, "DELETE FROM refresh_tokens WHERE token = ? AND did = ? AND expires_at > ?", nil, token, repo.Repo.Did, time.Now())
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return invalidRefresh
		}
		if err := tx.Exec(ctx, "DELETE FROM tokens WHERE refresh_token = ?", nil, token).Error; err != nil {
			return err
		}
		var err error
		sess, err = s.createSessionWithDB(ctx, tx, &repo.Repo)
		return err
	})
	if errors.Is(err, invalidRefresh) {
		return helpers.InvalidTokenError(e)
	}
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
