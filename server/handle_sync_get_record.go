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

func (s *Server) handleSyncGetRecord(e echo.Context) error {
	did := e.QueryParam("did")
	collection := e.QueryParam("collection")
	rkey := e.QueryParam("rkey")

	var urepo models.Repo
	if err := s.db.Raw("SELECT * FROM repos WHERE did = ?", nil, did).Scan(&urepo).Error; err != nil {
		s.logger.Error("error getting repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	root, blocks, err := s.repoman.getRecordProof(urepo, collection, rkey)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)

	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{root},
		Version: 1,
	})

	if _, err := carstore.LdWrite(buf, hb); err != nil {
		s.logger.Error("error writing to car", "error", err)
		return helpers.ServerError(e, nil)
	}

	for _, blk := range blocks {
		if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
			s.logger.Error("error writing to car", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	return e.Stream(200, "application/vnd.ipld.car", bytes.NewReader(buf.Bytes()))
}
