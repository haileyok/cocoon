package server

import (
	"bytes"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleSyncGetBlob(e echo.Context) error {
	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	cstr := e.QueryParam("cid")
	if cstr == "" {
		return helpers.InputError(e, nil)
	}

	c, err := cid.Parse(cstr)
	if err != nil {
		return helpers.InputError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(did)
	if err != nil {
		s.logger.Error("could not find user for requested blob", "error", err)
		return helpers.InputError(e, nil)
	}

	status := urepo.Status()
	if status != nil {
		if *status == "deactivated" {
			return helpers.InputError(e, to.StringPtr("RepoDeactivated"))
		}
	}

	var blob models.Blob
	if err := s.db.Raw("SELECT * FROM blobs WHERE did = ? AND cid = ?", nil, did, c.Bytes()).Scan(&blob).Error; err != nil {
		s.logger.Error("error looking up blob", "error", err)
		return helpers.ServerError(e, nil)
	}

	buf := new(bytes.Buffer)

	var parts []models.BlobPart
	if err := s.db.Raw("SELECT * FROM blob_parts WHERE blob_id = ? ORDER BY idx", nil, blob.ID).Scan(&parts).Error; err != nil {
		s.logger.Error("error getting blob parts", "error", err)
		return helpers.ServerError(e, nil)
	}

	// TODO: we can just stream this, don't need to make a buffer
	for _, p := range parts {
		buf.Write(p.Data)
	}

	e.Response().Header().Set(echo.HeaderContentDisposition, "attachment; filename="+c.String())

	return e.Stream(200, "application/octet-stream", buf)
}
