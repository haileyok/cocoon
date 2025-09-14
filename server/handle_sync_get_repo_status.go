package server

import (
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSyncGetRepoStatusResponse struct {
	Did    string  `json:"did"`
	Active bool    `json:"active"`
	Status *string `json:"status,omitempty"`
	Rev    *string `json:"rev,omitempty"`
}

// TODO: make this actually do the right thing
func (s *Server) handleSyncGetRepoStatus(e echo.Context) error {
	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(did)
	if err != nil {
		return err
	}

	return e.JSON(200, ComAtprotoSyncGetRepoStatusResponse{
		Did:    urepo.Repo.Did,
		Active: urepo.Active(),
		Status: urepo.Status(),
		Rev:    &urepo.Rev,
	})
}
