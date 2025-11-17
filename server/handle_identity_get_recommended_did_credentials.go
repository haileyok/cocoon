package server

import (
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleGetRecommendedDidCredentials(e echo.Context) error {
	repo := e.Get("repo").(*models.RepoActor)

	k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		s.logger.Error("error parsing key", "error", err)
		return helpers.ServerError(e, nil)
	}

	creds, err := s.plcClient.CreateDidCredentials(k, "", repo.Actor.Handle)
	if err != nil {
		s.logger.Error("error crating did credentials", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, creds)
}
