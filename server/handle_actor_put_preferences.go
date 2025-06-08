package server

import (
	"encoding/json"

	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

// This is kinda lame. Not great to implement app.bsky in the pds, but alas

func (s *Server) handleActorPutPreferences(e echo.Context) error {
	repo := e.Get("repo").(*models.RepoActor)

	var prefs map[string]any
	if err := json.NewDecoder(e.Request().Body).Decode(&prefs); err != nil {
		return err
	}

	b, err := json.Marshal(prefs)
	if err != nil {
		return err
	}

	if err := s.db.Exec("UPDATE repos SET preferences = ? WHERE did = ?", nil, b, repo.Repo.Did).Error; err != nil {
		return err
	}

	return nil
}
