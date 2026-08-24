package server

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
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

	// Uploading a blob does not make it public. Only a reference from the
	// account's public repository increments Blob.RefCount; SpaceBlobRef is tracked
	// separately and must never authorize this unauthenticated sync endpoint.
	ready, err := s.selectReadyBlob(ctx, did, c.Bytes(), true)
	if err != nil {
		logger.Error("error looking up blob", "error", err)
		return helpers.ServerError(e, nil)
	}
	if ready == nil {
		return helpers.InputError(e, to.StringPtr("BlobNotFound"))
	}

	if ready.Blob.Storage == "s3" {
		if !(s.s3Config != nil && s.s3Config.BlobstoreEnabled) {
			logger.Error("s3 storage disabled")
			return helpers.ServerError(e, nil)
		}
		_, blobKey, err := blobS3Target(ready.Blob, s.s3Config)
		if err != nil {
			logger.Error("invalid S3 blob target")
			return helpers.ServerError(e, nil)
		}
		if s.s3Config.CDNUrl != "" {
			redirectUrl := fmt.Sprintf("%s/%s", s.s3Config.CDNUrl, blobKey)
			return e.Redirect(302, redirectUrl)
		}
	}

	data, err := s.readReadyBlob(ctx, ready)
	if err != nil {
		logger.Error("error reading blob", "error", err)
		return helpers.ServerError(e, nil)
	}
	buf := bytes.NewBuffer(data)

	mimeType := ready.Blob.MimeType
	if mimeType == "" {
		mimeType = http.DetectContentType(data)
	}
	e.Response().Header().Set(echo.HeaderContentDisposition, "attachment; filename="+c.String())
	e.Response().Header().Set(echo.HeaderContentLength, strconv.Itoa(len(data)))

	return e.Stream(200, mimeType, buf)
}
