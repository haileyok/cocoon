package server

import (
	"context"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerActivateAccountRequest struct {
	// NOTE: this implementation will not pay attention to this value
	DeleteAfter time.Time `json:"deleteAfter"`
}

func (s *Server) handleServerActivateAccount(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerActivateAccount")

	var req ComAtprotoServerDeactivateAccountRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	urepo := e.Get("repo").(*models.RepoActor)

	if err := s.db.Exec(ctx, "UPDATE repos SET deactivated = ? WHERE did = ?", nil, false, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating account status to deactivated", "error", err)
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

	// Announce the repo's current head so relays learn the active account's
	// authoritative state (Sync v1.1 #sync event).
	if len(urepo.Repo.Root) > 0 {
		root, err := cid.Cast(urepo.Repo.Root)
		if err != nil {
			logger.Error("error casting repo root for sync event", "error", err)
		} else if err := s.emitRepoSync(context.TODO(), urepo.Repo.Did, urepo.Repo.Rev, root); err != nil {
			logger.Error("error emitting repo sync event", "error", err)
		}
	}

	return e.NoContent(200)
}
