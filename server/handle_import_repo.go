package server

import (
	"bytes"
	"context"
	"io"
	"slices"

	"github.com/bluesky-social/indigo/repo"
	"github.com/haileyok/cocoon/blockstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipld/go-car"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleRepoImportRepo(e echo.Context) error {
	urepo := e.Get("repo").(*models.RepoActor)

	b, err := io.ReadAll(e.Request().Body)
	if err != nil {
		s.logger.Error("could not read bytes in import request", "error", err)
		return helpers.ServerError(e, nil)
	}

	bs := blockstore.New(urepo.Repo.Did, s.db)

	cs, err := car.NewCarReader(bytes.NewReader(b))
	if err != nil {
		s.logger.Error("could not read car in import request", "error", err)
		return helpers.ServerError(e, nil)
	}

	orderedBlocks := []blocks.Block{}
	currBlock, err := cs.Next()
	if err != nil {
		s.logger.Error("could not get first block from car", "error", err)
		return helpers.ServerError(e, nil)
	}
	currBlockCt := 1

	for currBlock != nil {
		s.logger.Info("someone is importing their repo", "block", currBlockCt)
		orderedBlocks = append(orderedBlocks, currBlock)
		next, _ := cs.Next()
		currBlock = next
		currBlockCt++
	}

	slices.Reverse(orderedBlocks)

	if err := bs.PutMany(context.TODO(), orderedBlocks); err != nil {
		s.logger.Error("could not insert blocks", "error", err)
		return helpers.ServerError(e, nil)
	}

	r, err := repo.OpenRepo(context.TODO(), bs, cs.Header.Roots[0])
	if err != nil {
		s.logger.Error("could not open repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	root, rev, err := r.Commit(context.TODO(), urepo.SignFor)
	if err != nil {
		s.logger.Error("error committing", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := bs.UpdateRepo(context.TODO(), root, rev); err != nil {
		s.logger.Error("error updating repo after commit", "error", err)
		return helpers.ServerError(e, nil)
	}

	return nil
}
