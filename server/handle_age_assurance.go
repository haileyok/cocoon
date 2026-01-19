package server

import (
	"time"

	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleAgeAssurance(e echo.Context) error {
	repo := e.Get("repo").(*models.RepoActor)

	resp := map[string]any{
		"state": map[string]any{
			"status":          "assured",
			"access":          "full",
			"lastInitiatedAt": time.Now().Format(util.ISO8601),
		},
		"metadata": map[string]any{
			"accountCreatedAt": repo.CreatedAt.Format(util.ISO8601),
		},
	}

	return e.JSON(200, resp)
}
