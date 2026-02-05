package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoUnspeccedCreatePrivateRecordInput struct {
	Repo       string         `json:"repo" validate:"required,atproto-did"`
	Collection string         `json:"collection" validate:"required,atproto-nsid"`
	Rkey       *string        `json:"rkey,omitempty"`
	Validate   *bool          `json:"bool,omitempty"`
	Record     MarshalableMap `json:"record" validate:"required"`
}

func (s *Server) handleServerCreatePrivate(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleCreatePrivate")

	repo := e.Get("repo").(*models.RepoActor)

	var input ComAtprotoUnspeccedCreatePrivateRecordInput
	if err := e.Bind(&input); err != nil {
		logger.Error("error binding", "err", err)
		return fmt.Errorf("error binding: %w", err)
	}

	if input.Rkey == nil {
		input.Rkey = to.StringPtr(s.repoman.clock.Next().String())
	}

	b, err := json.Marshal(input.Record)
	if err != nil {
		logger.Error("failed to marshal input record", "err", err)
		return fmt.Errorf("failed to marshal input record: %w", err)
	}

	record := models.PrivateRecord{
		Did:       repo.Repo.Did,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Nsid:      input.Collection,
		Rkey:      *input.Rkey,
		Value:     b,
	}

	if err := s.db.Create(ctx, &record, nil).Error; err != nil {
		logger.Error("failed to create record in db", "err", err)
		return fmt.Errorf("failed to create record in db")
	}

	return e.NoContent(200)
}
