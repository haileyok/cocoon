package server

import (
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleGetRecommendedDidCredentials(e echo.Context) error {
	logger := s.logger.With("name", "handleIdentityGetRecommendedDidCredentials")

	repo := e.Get("repo").(*models.RepoActor)
	k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		logger.Error("error parsing key", "error", err)
		return helpers.ServerError(e, nil)
	}
	// Includes the #atproto_kem key when the account has one, so a migration
	// or a self-managed DID document publishes it.
	kemDidKey, err := accountKemDIDKey(repo.Repo)
	if err != nil {
		logger.Error("error parsing kem key", "error", err)
		return helpers.ServerError(e, nil)
	}
	creds, err := s.plcClient.CreateDidCredentials(k, kemDidKey, "", repo.Actor.Handle)
	if err != nil {
		logger.Error("error crating did credentials", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, creds)
}
