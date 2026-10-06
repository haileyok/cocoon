package server

import (
	"github.com/haileyok/cocoon/internal/space"
)

// Pieces of Spaces that later slices fill in.

// notifySpaceWrite tells the space authority about a new repo state.
func (s *Server) notifySpaceWrite(ref space.Ref, did string, commit *spaceCommit) {}

// stopSpaceWorkers stops background space work.
func (s *Server) stopSpaceWorkers() { s.spaceJobs.Wait() }
