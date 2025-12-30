package server

import (
	"context"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerActivateAccountRequest struct {
	// NOTE: this implementation will not pay attention to this value
	DeleteAfter time.Time `json:"deleteAfter"`
}

func (s *Server) handleServerActivateAccount(e echo.Context) error {
	ctx := e.Request().Context()

	var req ComAtprotoServerDeactivateAccountRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	urepo := e.Get("repo").(*models.RepoActor)

	if err := s.db.Exec(ctx, "UPDATE repos SET deactivated = ? WHERE did = ?", nil, false, urepo.Repo.Did).Error; err != nil {
		s.logger.Error("error updating account status to deactivated", "error", err)
		return helpers.ServerError(e, nil)
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: true,
			Did:    urepo.Repo.Did,
			Status: nil,
			Seq:    time.Now().UnixMicro(), // TODO: bad puppy
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	return e.NoContent(200)
}
