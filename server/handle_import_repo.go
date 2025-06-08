package server

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/repo"
	"github.com/haileyok/cocoon/blockstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
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

	tx := s.db.BeginDangerously()

	clock := syntax.NewTIDClock(0)

	if err := r.ForEach(context.TODO(), "", func(key string, cid cid.Cid) error {
		pts := strings.Split(key, "/")
		nsid := pts[0]
		rkey := pts[1]
		cidStr := cid.String()
		b, err := bs.Get(context.TODO(), cid)
		if err != nil {
			s.logger.Error("record bytes don't exist in blockstore", "error", err)
			return helpers.ServerError(e, nil)
		}

		rec := models.Record{
			Did:       urepo.Repo.Did,
			CreatedAt: clock.Next().String(),
			Nsid:      nsid,
			Rkey:      rkey,
			Cid:       cidStr,
			Value:     b.RawData(),
		}

		if err := tx.Create(rec).Error; err != nil {
			return err
		}

		return nil
	}); err != nil {
		tx.Rollback()
		s.logger.Error("record bytes don't exist in blockstore", "error", err)
		return helpers.ServerError(e, nil)
	}

	tx.Commit()

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
