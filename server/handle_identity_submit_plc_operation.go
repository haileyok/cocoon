package server

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSubmitPlcOperationRequest struct {
	Operation plc.Operation `json:"operation"`
}

func (s *Server) handleSubmitPlcOperation(e echo.Context) error {
	repo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoSubmitPlcOperationRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}
	if !strings.HasPrefix(repo.Repo.Did, "did:plc:") {
		return helpers.InputError(e, nil)
	}

	op := req.Operation;

	k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		s.logger.Error("error parsing key", "error", err)
		return helpers.ServerError(e, nil)
	}
	required, err := s.plcClient.CreateDidCredentials(k, "", repo.Actor.Handle)
	if err != nil {
		s.logger.Error("error crating did credentials", "error", err)
		return helpers.ServerError(e, nil)
	}

	for _, expectedKey := range required.RotationKeys {
		if !slices.Contains(op.RotationKeys, expectedKey) {
			return helpers.InputError(e, nil)
		}
	}
	if op.Services["atproto_pds"].Type != "AtprotoPersonalDataServer" {
		return helpers.InputError(e, nil)
	}
	if op.Services["atproto_pds"].Endpoint != required.Services["atproto_pds"].Endpoint {
		return helpers.InputError(e, nil)
	}
	if op.VerificationMethods["atproto"] != required.VerificationMethods["atproto"] {
		return helpers.InputError(e, nil)
	}
	if op.AlsoKnownAs[0] != required.AlsoKnownAs[0] {
		return helpers.InputError(e, nil)
	}

	if err := s.plcClient.SendOperation(e.Request().Context(), repo.Repo.Did, &op); err != nil {
		return err
	}

	if err := s.passport.BustDoc(context.TODO(), repo.Repo.Did); err != nil {
		s.logger.Warn("error busting did doc", "error", err)
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:    repo.Repo.Did,
			Seq:    time.Now().UnixMicro(), // TODO: no
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	return nil
}
