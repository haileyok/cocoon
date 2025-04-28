package server

import (
	"bytes"
	"context"
	"strings"

	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/blockstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleImportRepo(e echo.Context) error {
	var b []byte

	if err := e.Bind(&b); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	root, in, err := repo.LoadRepoFromCAR(e.Request().Context(), bytes.NewReader(b))
	if err != nil {
		s.logger.Error("error reading car file being imported", "error", err)
		return helpers.ServerError(e, nil)
	}

	bs := blockstore.New(in.DID.String(), s.db)

	in.MST.Walk(func(k []byte, c cid.Cid) error {
		block, err := in.RecordStore.Get(context.TODO(), c)
		if err != nil {
			return err
		}

		if err := bs.Put(context.TODO(), block); err != nil {
			return err
		}

		pts := strings.Split(string(k), "/")
		if len(pts) != 2 {
			s.logger.Warn("invalid key?")
			return nil
		}

		nsid, _ := syntax.ParseNSID(pts[0])
		rkey, _ := syntax.ParseRecordKey(pts[1])

		recb, rc, err := in.GetRecordBytes(context.TODO(), nsid, rkey)
		if err != nil {
			return err
		}

		return nil
	})

	return nil
}
