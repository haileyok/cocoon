package server

import (
	"github.com/haileyok/cocoon/internal/space"
	"github.com/labstack/echo/v4"
)

// Pieces of Spaces that later slices fill in.

// notifySpaceWrite tells the space authority about a new repo state.
func (s *Server) notifySpaceWrite(ref space.Ref, did string, commit *spaceCommit) {}

// verifySpaceCredentialRequest verifies a request presenting a space
// credential.
func (s *Server) verifySpaceCredentialRequest(e echo.Context) (*spaceCredentialAuth, error) {
	return nil, errAuthRequired("", "space credentials are not supported yet")
}

func (s *Server) isTakenDown(did string) (bool, error) { return false, nil }

func (s *Server) assertNotTakenDown(did string) error { return nil }

// stopSpaceWorkers stops background space work.
func (s *Server) stopSpaceWorkers() {}
