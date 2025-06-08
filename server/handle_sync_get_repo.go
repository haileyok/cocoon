package server

import (
	"bytes"

	"github.com/bluesky-social/indigo/carstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleSyncGetRepo(e echo.Context) error {
	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(did)
	if err != nil {
		return err
	}

	rc, err := cid.Cast(urepo.Root)
	if err != nil {
		return err
	}

	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{rc},
		Version: 1,
	})

	buf := new(bytes.Buffer)

	if _, err := carstore.LdWrite(buf, hb); err != nil {
		s.logger.Error("error writing to car", "error", err)
		return helpers.ServerError(e, nil)
	}

	var blocks []models.Block
	if err := s.db.Raw("SELECT * FROM blocks WHERE did = ? ORDER BY rev ASC", nil, urepo.Repo.Did).Scan(&blocks).Error; err != nil {
		return err
	}

	for _, block := range blocks {
		if _, err := carstore.LdWrite(buf, block.Cid, block.Value); err != nil {
			return err
		}
	}

	return e.Stream(200, "application/vnd.ipld.car", bytes.NewReader(buf.Bytes()))
}
