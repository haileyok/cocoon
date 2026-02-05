package server

import (
	"encoding/json"
	"fmt"

	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoUnspeccedGetPrivateRecordInput struct {
	Collection string `query:"collection"`
	Rkey       string `query:"rkey"`
}

func (s *Server) handleServerGetPrivate(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleGetPrivate")

	repo := e.Get("repo").(*models.RepoActor)

	var input ComAtprotoUnspeccedGetPrivateRecordInput
	if err := e.Bind(&input); err != nil {
		logger.Error("error binding", "err", err)
		return fmt.Errorf("error binding: %w", err)
	}

	var record models.PrivateRecord
	if err := s.db.Raw(ctx, "SELECT * FROM private_records WHERE did = ? AND nsid = ? AND rkey = ?", nil, repo.Repo.Did, input.Collection, input.Rkey).Scan(&record).Error; err != nil {
		logger.Error("error getting private record", "err", err)
		return fmt.Errorf("failed to get private record: %w", err)
	}

	var unmarshaled map[string]any
	if err := json.Unmarshal(record.Value, &unmarshaled); err != nil {
		logger.Error("error unmarshaling record", "err", err)
		return fmt.Errorf("failed to unmarshal record: %w", err)
	}

	return e.JSON(200, unmarshaled)
}
