package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoUnspeccedListPrivateRecordsInput struct {
	Collection string `query:"collection"`
	Limit      int    `query:"limit"`
	Cursor     string `query:"cursor"`
}

type ComAtprotoUnspeccedListPrivateRecordsResponse struct {
	Cursor  *string                                           `json:"cursor,omitempty"`
	Records []ComAtprotoUnspeccedListPrivateRecordsRecordItem `json:"records"`
}

type ComAtprotoUnspeccedListPrivateRecordsRecordItem struct {
	Uri   string         `json:"uri"`
	Value map[string]any `json:"value"`
}

func (s *Server) handleServerListPrivate(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleListPrivate")

	repo := e.Get("repo").(*models.RepoActor)

	var input ComAtprotoUnspeccedListPrivateRecordsInput
	if err := e.Bind(&input); err != nil {
		logger.Error("error binding", "err", err)
		return fmt.Errorf("error binding: %w", err)
	}

	limit, err := getLimitFromContext(e, 100)
	if err != nil {
		logger.Error("failed to parse limit from context", "err", err)
		return fmt.Errorf("failed to parse limit from context: %w", err)
	}

	if input.Cursor == "" {
		input.Cursor = time.Now().UTC().Format(time.RFC3339Nano)
	}

	var records []models.PrivateRecord
	if err := s.db.Raw(ctx, "SELECT * FROM private_records WHERE did = ? AND nsid = ? AND created_at < ORDER BY created_at DESC LIMIT ?", nil, repo.Repo.Did, input.Collection, input.Cursor, limit).Scan(&records).Error; err != nil {
		logger.Error("error getting private record", "err", err)
		return fmt.Errorf("failed to get private record: %w", err)
	}

	respRecords := make([]ComAtprotoUnspeccedListPrivateRecordsRecordItem, 0, len(records))

	for _, rec := range records {
		var unmarshaled map[string]any
		if err := json.Unmarshal(rec.Value, &unmarshaled); err != nil {
			logger.Error("failed to unmarshal record", "err", err)
			return fmt.Errorf("failed to unmarshal record: %w", err)
		}

		respRecords = append(respRecords, ComAtprotoUnspeccedListPrivateRecordsRecordItem{
			Uri:   fmt.Sprintf("at://%s/%s/%s", repo.Repo.Did, input.Collection, rec.Rkey),
			Value: unmarshaled,
		})
	}

	var newcursor *string
	if len(records) == limit {
		newcursor = to.StringPtr(records[len(records)-1].CreatedAt)
	}

	return e.JSON(200, ComAtprotoUnspeccedListPrivateRecordsResponse{
		Cursor:  newcursor,
		Records: respRecords,
	})
}
