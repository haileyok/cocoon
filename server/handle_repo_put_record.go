package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoPutRecordInput struct {
	Repo       string          `json:"repo" validate:"required,atproto-did"`
	Collection string          `json:"collection" validate:"required,atproto-nsid"`
	Rkey       string          `json:"rkey" validate:"required,atproto-rkey"`
	Validate   *bool           `json:"bool,omitempty"`
	Record     MarshalableMap  `json:"record" validate:"required"`
	SwapRecord json.RawMessage `json:"swapRecord,omitempty"`
	SwapCommit json.RawMessage `json:"swapCommit,omitempty"`
}

func (s *Server) handlePutRecord(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handlePutRecord")

	repo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoRepoPutRecordInput
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

	swapCommit, err := parseRepoSwap(req.SwapCommit, false)
	if err != nil {
		return helpers.InputError(e, nil)
	}
	swapRecord, err := parseRepoSwap(req.SwapRecord, true)
	if err != nil {
		return helpers.InputError(e, nil)
	}

	optype := OpTypeCreate
	if swapRecord != nil && swapRecord.Defined() {
		optype = OpTypeUpdate
	}

	action := actionForOpType(optype)
	if !s.hasRepoScope(e, req.Collection, "create") && !s.hasRepoScope(e, req.Collection, "update") {
		return helpers.InsufficientScopeError(e, fmt.Sprintf("repo:%s?action=%s", req.Collection, action))
	}

	results, err := s.repoman.applyWrites(ctx, repo.Repo, []Op{
		{
			Type:       optype,
			Collection: req.Collection,
			Rkey:       &req.Rkey,
			Validate:   req.Validate,
			Record:     &req.Record,
			SwapRecord: swapRecord,
		},
	}, swapCommit, s.repoWriteAuthorization(e))
	if err != nil {
		var scopeErr repoScopeError
		if errors.As(err, &scopeErr) {
			return helpers.InsufficientScopeError(e, scopeErr.Error())
		}
		var downErr errAccountTakenDown
		if errors.As(err, &downErr) {
			return helpers.InputError(e, to.StringPtr("AccountTakedown"))
		}
		if errors.Is(err, errInvalidSwap) {
			return e.JSON(400, map[string]string{"error": "InvalidSwap"})
		}
		logger.Error("error applying writes", "error", err)
		return helpers.ServerError(e, nil)
	}

	results[0].Type = nil

	return e.JSON(200, results[0])
}
