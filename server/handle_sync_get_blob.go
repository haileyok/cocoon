package server

import (
	"bytes"
	"fmt"
	"io"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleSyncGetBlob(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleSyncGetBlob")

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

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find user for requested blob", "error", err)
		return helpers.InputError(e, nil)
	}

	status := urepo.Status()
	if status != nil {
		if *status == "deactivated" {
			return helpers.InputError(e, to.StringPtr("RepoDeactivated"))
		}
	}

	// A blob only space records reference is permissioned data.
	if spaceOnly, err := s.isSpaceOnlyBlob(ctx, did, c); err != nil {
		logger.Error("error checking blob references", "error", err)
		return helpers.ServerError(e, nil)
	} else if spaceOnly {
		return e.JSON(400, map[string]string{"error": "BlobNotFound", "message": "Blob not found"})
	}

	var blob models.Blob
	if err := s.db.Raw(ctx, "SELECT * FROM blobs WHERE did = ? AND cid = ?", nil, did, c.Bytes()).Scan(&blob).Error; err != nil {
		logger.Error("error looking up blob", "error", err)
		return helpers.ServerError(e, nil)
	}

	buf := new(bytes.Buffer)

	if blob.Storage == "sqlite" {
		var parts []models.BlobPart
		if err := s.db.Raw(ctx, "SELECT * FROM blob_parts WHERE blob_id = ? ORDER BY idx", nil, blob.ID).Scan(&parts).Error; err != nil {
			logger.Error("error getting blob parts", "error", err)
			return helpers.ServerError(e, nil)
		}

		// TODO: we can just stream this, don't need to make a buffer
		for _, p := range parts {
			buf.Write(p.Data)
		}
	} else if blob.Storage == "s3" {
		if !(s.s3Config != nil && s.s3Config.BlobstoreEnabled) {
			logger.Error("s3 storage disabled")
			return helpers.ServerError(e, nil)
		}

		blobKey := fmt.Sprintf("blobs/%s/%s", urepo.Repo.Did, c.String())

		if s.s3Config.CDNUrl != "" {
			redirectUrl := fmt.Sprintf("%s/%s", s.s3Config.CDNUrl, blobKey)
			return e.Redirect(302, redirectUrl)
		}

		body, err := s.getS3Blob(ctx, urepo.Repo.Did, c)
		if err != nil {
			logger.Error("error getting blob from s3", "error", err)
			return helpers.ServerError(e, nil)
		}
		defer body.Close()

		if _, err := io.Copy(buf, body); err != nil {
			logger.Error("error reading blob", "error", err)
			return helpers.ServerError(e, nil)
		}
	} else {
		logger.Error("unknown storage", "storage", blob.Storage)
		return helpers.ServerError(e, nil)
	}

	e.Response().Header().Set(echo.HeaderContentDisposition, "attachment; filename="+c.String())

	return e.Stream(200, "application/octet-stream", buf)
}
