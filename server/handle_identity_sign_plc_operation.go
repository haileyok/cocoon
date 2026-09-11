package server

import (
	"context"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSignPlcOperationRequest struct {
	Token               string                                `json:"token"`
	VerificationMethods *map[string]string                    `json:"verificationMethods"`
	RotationKeys        *[]string                             `json:"rotationKeys"`
	AlsoKnownAs         *[]string                             `json:"alsoKnownAs"`
	Services            *map[string]identity.OperationService `json:"services"`
}

type ComAtprotoSignPlcOperationResponse struct {
	Operation plc.Operation `json:"operation"`
}

func (s *Server) handleSignPlcOperation(e echo.Context) error {
	logger := s.logger.With("name", "handleSignPlcOperation")

	repo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoSignPlcOperationRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if !strings.HasPrefix(repo.Repo.Did, "did:plc:") {
		return helpers.InputError(e, nil)
	}

	if repo.PlcOperationCode == nil || repo.PlcOperationCodeExpiresAt == nil {
		return helpers.InputError(e, to.StringPtr("InvalidToken"))
	}

	if *repo.PlcOperationCode != req.Token {
		return helpers.InvalidTokenError(e)
	}

	if time.Now().UTC().After(*repo.PlcOperationCodeExpiresAt) {
		return helpers.ExpiredTokenError(e)
	}

	// Atomically claim (consume) the token BEFORE building the operation.
	// The check above runs against this request's repo snapshot; a concurrent
	// request with the same token would pass the same check. A conditional
	// UPDATE that only matches the still-unconsumed, unexpired token ensures
	// exactly one request wins (fail-closed: a signing failure burns the
	// token, but the user can simply request a new one).
	claimed := s.db.Client().Exec(
		"UPDATE repos SET plc_operation_code = NULL, plc_operation_code_expires_at = NULL WHERE did = ? AND plc_operation_code = ? AND plc_operation_code_expires_at > ?",
		repo.Repo.Did, req.Token, time.Now().UTC(),
	)
	if claimed.Error != nil {
		logger.Error("error claiming plc operation token", "error", claimed.Error)
		return helpers.ServerError(e, nil)
	}
	if claimed.RowsAffected != 1 {
		return helpers.InvalidTokenError(e)
	}

	ctx := context.WithValue(e.Request().Context(), "skip-cache", true)
	lastOp, lastCid, err := s.plcClient.GetLastOp(ctx, repo.Repo.Did)
	if err != nil {
		logger.Error("error fetching last plc operation", "error", err)
		return helpers.ServerError(e, nil)
	}

	// Reference parity: refuse to build on a tombstoned DID.
	if lastOp.Type == "plc_tombstone" {
		return helpers.InputError(e, to.StringPtr("Did is tombstoned"))
	}

	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: lastOp.VerificationMethods,
		RotationKeys:        lastOp.RotationKeys,
		AlsoKnownAs:         lastOp.AlsoKnownAs,
		Services:            lastOp.Services,
		Prev:                &lastCid,
	}
	if req.VerificationMethods != nil {
		op.VerificationMethods = *req.VerificationMethods
	}
	if req.RotationKeys != nil {
		op.RotationKeys = *req.RotationKeys
	}
	if req.AlsoKnownAs != nil {
		op.AlsoKnownAs = *req.AlsoKnownAs
	}
	if req.Services != nil {
		op.Services = *req.Services
	}

	k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		logger.Error("error parsing signing key", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.plcClient.SignOp(k, &op); err != nil {
		logger.Error("error signing plc operation", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, ComAtprotoSignPlcOperationResponse{
		Operation: op,
	})
}
