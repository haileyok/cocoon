package server

import (
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoApplyWritesInput struct {
	Repo       string                          `json:"repo" validate:"required,atproto-did"`
	Validate   *bool                           `json:"bool,omitempty"`
	Writes     []ComAtprotoRepoApplyWritesItem `json:"writes"`
	SwapCommit *string                         `json:"swapCommit"`
}

type ComAtprotoRepoApplyWritesItem struct {
	Type       string          `json:"$type"`
	Collection string          `json:"collection"`
	Rkey       string          `json:"rkey"`
	Value      *MarshalableMap `json:"value,omitempty"`
}

type ComAtprotoRepoApplyWritesOutput struct {
	Commit  RepoCommit         `json:"commit"`
	Results []ApplyWriteResult `json:"results"`
}

func (s *Server) handleApplyWrites(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleRepoApplyWrites")

	var req ComAtprotoRepoApplyWritesInput
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		logger.Error("error validating", "error", err)
		return helpers.InputError(e, nil)
	}

	repo := e.Get("repo").(*models.RepoActor)

	if repo.Repo.Did != req.Repo {
		logger.Warn("mismatched repo/auth")
		return helpers.InputError(e, nil)
	}

	ops := make([]Op, 0, len(req.Writes))
	for _, item := range req.Writes {
		ops = append(ops, Op{
			Type:       OpType(item.Type),
			Collection: item.Collection,
			Rkey:       &item.Rkey,
			Record:     item.Value,
		})
	}

	results, err := s.repoman.applyWrites(ctx, repo.Repo, ops, req.SwapCommit)
	if err != nil {
		logger.Error("error applying writes", "error", err)
		return helpers.ServerError(e, nil)
	}

	commit := *results[0].Commit

	for i := range results {
		results[i].Commit = nil
	}

	return e.JSON(200, ComAtprotoRepoApplyWritesOutput{
		Commit:  commit,
		Results: results,
	})
}
