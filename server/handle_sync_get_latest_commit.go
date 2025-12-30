package server

import (
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSyncGetLatestCommitResponse struct {
	Cid string `json:"string"`
	Rev string `json:"rev"`
}

func (s *Server) handleSyncGetLatestCommit(e echo.Context) error {
	ctx := e.Request().Context()

	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		return err
	}

	c, err := cid.Cast(urepo.Root)
	if err != nil {
		return err
	}

	return e.JSON(200, ComAtprotoSyncGetLatestCommitResponse{
		Cid: c.String(),
		Rev: urepo.Rev,
	})
}
