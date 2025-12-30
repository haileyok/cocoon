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
	repo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoSignPlcOperationRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
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

	ctx := context.WithValue(e.Request().Context(), "skip-cache", true)
	log, err := identity.FetchDidAuditLog(ctx, nil, repo.Repo.Did)
	if err != nil {
		s.logger.Error("error fetching doc", "error", err)
		return helpers.ServerError(e, nil)
	}

	latest := log[len(log)-1]

	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: latest.Operation.VerificationMethods,
		RotationKeys:        latest.Operation.RotationKeys,
		AlsoKnownAs:         latest.Operation.AlsoKnownAs,
		Services:            latest.Operation.Services,
		Prev:                &latest.Cid,
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
		s.logger.Error("error parsing signing key", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.plcClient.SignOp(k, &op); err != nil {
		s.logger.Error("error signing plc operation", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec(ctx, "UPDATE repos SET plc_operation_code = NULL, plc_operation_code_expires_at = NULL WHERE did = ?", nil, repo.Repo.Did).Error; err != nil {
		s.logger.Error("error updating repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, ComAtprotoSignPlcOperationResponse{
		Operation: op,
	})
}
