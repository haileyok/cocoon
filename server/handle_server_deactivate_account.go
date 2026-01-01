package server

import (
	"context"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerDeactivateAccountRequest struct {
	// NOTE: this implementation will not pay attention to this value
	DeleteAfter time.Time `json:"deleteAfter"`
}

func (s *Server) handleServerDeactivateAccount(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerDeactivateAccount")

	var req ComAtprotoServerDeactivateAccountRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	urepo := e.Get("repo").(*models.RepoActor)

	if err := s.db.Exec(ctx, "UPDATE repos SET deactivated = ? WHERE did = ?", nil, true, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating account status to deactivated", "error", err)
		return helpers.ServerError(e, nil)
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: false,
			Did:    urepo.Repo.Did,
			Status: to.StringPtr("deactivated"),
			Seq:    time.Now().UnixMicro(), // TODO: bad puppy
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	return e.NoContent(200)
}
