package server

import (
	"bytes"

	"github.com/bluesky-social/indigo/carstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSyncGetBlocksRequest struct {
	Did  string   `query:"did"`
	Cids []string `query:"cids"`
}

func (s *Server) handleGetBlocks(e echo.Context) error {
	ctx := e.Request().Context()

	var req ComAtprotoSyncGetBlocksRequest
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, nil)
	}

	var cids []cid.Cid

	for _, cs := range req.Cids {
		c, err := cid.Cast([]byte(cs))
		if err != nil {
			return err
		}

		cids = append(cids, c)
	}

	urepo, err := s.getRepoActorByDid(ctx, req.Did)
	if err != nil {
		return helpers.ServerError(e, nil)
	}

	buf := new(bytes.Buffer)
	rc, err := cid.Cast(urepo.Root)
	if err != nil {
		return err
	}

	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{rc},
		Version: 1,
	})

	if _, err := carstore.LdWrite(buf, hb); err != nil {
		s.logger.Error("error writing to car", "error", err)
		return helpers.ServerError(e, nil)
	}

	bs := s.getBlockstore(urepo.Repo.Did)

	for _, c := range cids {
		b, err := bs.Get(ctx, c)
		if err != nil {
			return err
		}

		if _, err := carstore.LdWrite(buf, b.Cid().Bytes(), b.RawData()); err != nil {
			return err
		}
	}

	return e.Stream(200, "application/vnd.ipld.car", bytes.NewReader(buf.Bytes()))
}
