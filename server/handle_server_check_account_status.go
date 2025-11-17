package server

import (
	"errors"
	"sync"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerCheckAccountStatusResponse struct {
	Activated          bool   `json:"activated"`
	ValidDid           bool   `json:"validDid"`
	RepoCommit         string `json:"repoCommit"`
	RepoRev            string `json:"repoRev"`
	RepoBlocks         int64  `json:"repoBlocks"`
	IndexedRecords     int64  `json:"indexedRecords"`
	PrivateStateValues int64  `json:"privateStateValues"`
	ExpectedBlobs      int64  `json:"expectedBlobs"`
	ImportedBlobs      int64  `json:"importedBlobs"`
}

func (s *Server) handleServerCheckAccountStatus(e echo.Context) error {
	urepo := e.Get("repo").(*models.RepoActor)

	_, didErr := syntax.ParseDID(urepo.Repo.Did)
	if didErr != nil {
		s.logger.Error("error validating did", "err", didErr)
	}

	resp := ComAtprotoServerCheckAccountStatusResponse{
		Activated:     true, // TODO: should allow for deactivation etc.
		ValidDid:      didErr == nil,
		RepoRev:       urepo.Rev,
		ImportedBlobs: 0, // TODO: ???
	}

	rootcid, err := cid.Cast(urepo.Root)
	if err != nil {
		s.logger.Error("error casting cid", "error", err)
		return helpers.ServerError(e, nil)
	}

	resp.RepoCommit = rootcid.String()

	type CountResp struct {
		Ct int64
	}

	var blockCtResp CountResp
	var recCtResp CountResp
	var blobCtResp CountResp

	var wg sync.WaitGroup
	var procErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.db.Raw("SELECT COUNT(*) AS ct FROM blocks WHERE did = ?", nil, urepo.Repo.Did).Scan(&blockCtResp).Error; err != nil {
			s.logger.Error("error getting block count", "error", err)
			procErr = errors.Join(procErr, err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.db.Raw("SELECT COUNT(*) AS ct FROM records WHERE did = ?", nil, urepo.Repo.Did).Scan(&recCtResp).Error; err != nil {
			s.logger.Error("error getting record count", "error", err)
			procErr = errors.Join(procErr, err)
		}
	}()

	wg.Add(1)
	go func() {
		if err := s.db.Raw("SELECT COUNT(*) AS ct FROM blobs WHERE did = ?", nil, urepo.Repo.Did).Scan(&blobCtResp).Error; err != nil {
			s.logger.Error("error getting expected blobs count", "error", err)
			procErr = errors.Join(procErr, err)
		}
	}()

	wg.Wait()
	if procErr != nil {
		return helpers.ServerError(e, nil)
	}

	resp.RepoBlocks = blockCtResp.Ct
	resp.IndexedRecords = recCtResp.Ct
	resp.ExpectedBlobs = blobCtResp.Ct

	return e.JSON(200, resp)
}
