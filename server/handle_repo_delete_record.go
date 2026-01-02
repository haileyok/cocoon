package server

import (
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoDeleteRecordInput struct {
	Repo       string  `json:"repo" validate:"required,atproto-did"`
	Collection string  `json:"collection" validate:"required,atproto-nsid"`
	Rkey       string  `json:"rkey" validate:"required,atproto-rkey"`
	SwapRecord *string `json:"swapRecord"`
	SwapCommit *string `json:"swapCommit"`
}

func (s *Server) handleDeleteRecord(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleDeleteRecord")

	repo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoRepoDeleteRecordInput
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		logger.Error("error validating", "error", err)
		return helpers.InputError(e, nil)
	}

	if repo.Repo.Did != req.Repo {
		logger.Warn("mismatched repo/auth")
		return helpers.InputError(e, nil)
	}

	results, err := s.repoman.applyWrites(ctx, repo.Repo, []Op{
		{
			Type:       OpTypeDelete,
			Collection: req.Collection,
			Rkey:       &req.Rkey,
			SwapRecord: req.SwapRecord,
		},
	}, req.SwapCommit)
	if err != nil {
		logger.Error("error applying writes", "error", err)
		return helpers.ServerError(e, nil)
	}

	results[0].Type = nil
	results[0].Uri = nil
	results[0].Cid = nil
	results[0].ValidationStatus = nil

	return e.JSON(200, results[0])
}
