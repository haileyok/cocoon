package server

import (
	"bytes"
	"context"
	"io"

	"github.com/haileyok/cocoon/blockstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipld/go-car"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleRepoImportRepo(e echo.Context) error {
	repo := e.Get("repo").(*models.RepoActor)

	b, err := io.ReadAll(e.Request().Body)
	if err != nil {
		s.logger.Error("could not read bytes in import request", "error", err)
		return helpers.ServerError(e, nil)
	}

	bs := blockstore.New(repo.Repo.Did, s.db)

	cs, err := car.NewCarReader(bytes.NewReader(b))
	if err != nil {
		s.logger.Error("could not read car in import request", "error", err)
		return helpers.ServerError(e, nil)
	}

	currBlock, err := cs.Next()
	if err != nil {
		s.logger.Error("could not get first block from car", "error", err)
		return helpers.ServerError(e, nil)
	}

	for len(currBlock.RawData()) != 0 {
		bs.Put(context.TODO(), currBlock)

		next, err := cs.Next()
		if err != nil {
			s.logger.Error("could not get nexte block from car", "error", err)
			return helpers.ServerError(e, nil)
		}

		currBlock = next
	}

	return nil
}
