package server

import (
	"bytes"
	"fmt"
	"io"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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

	if blob.Storage == "sqlite" {
		var parts []models.BlobPart
		if err := s.db.Raw("SELECT * FROM blob_parts WHERE blob_id = ? ORDER BY idx", nil, blob.ID).Scan(&parts).Error; err != nil {
			s.logger.Error("error getting blob parts", "error", err)
			return helpers.ServerError(e, nil)
		}

		// TODO: we can just stream this, don't need to make a buffer
		for _, p := range parts {
			buf.Write(p.Data)
		}
	} else if blob.Storage == "s3" && s.s3Config != nil && s.s3Config.BlobstoreEnabled {
		config := &aws.Config{
			Region:      aws.String(s.s3Config.Region),
			Credentials: credentials.NewStaticCredentials(s.s3Config.AccessKey, s.s3Config.SecretKey, ""),
		}

		if s.s3Config.Endpoint != "" {
			config.Endpoint = aws.String(s.s3Config.Endpoint)
			config.S3ForcePathStyle = aws.Bool(true)
		}

		sess, err := session.NewSession(config)
		if err != nil {
			s.logger.Error("error creating aws session", "error", err)
			return helpers.ServerError(e, nil)
		}

		svc := s3.New(sess)
		if result, err := svc.GetObject(&s3.GetObjectInput{
			Bucket: aws.String(s.s3Config.Bucket),
			Key:    aws.String(fmt.Sprintf("blobs/%s/%s", urepo.Repo.Did, c.String())),
		}); err != nil {
			s.logger.Error("error getting blob from s3", "error", err)
			return helpers.ServerError(e, nil)
		} else {
			read := 0
			part := 0
			partBuf := make([]byte, 0x10000)

			for {
				n, err := io.ReadFull(result.Body, partBuf)
				if err == io.ErrUnexpectedEOF || err == io.EOF {
					if n == 0 {
						break
					}
				} else if err != nil && err != io.ErrUnexpectedEOF {
					s.logger.Error("error reading blob", "error", err)
					return helpers.ServerError(e, nil)
				}

				data := partBuf[:n]
				read += n
				buf.Write(data)
				part++
			}
		}
	} else {
		s.logger.Error("unknown storage", "storage", blob.Storage)
		return helpers.ServerError(e, nil)
	}

	e.Response().Header().Set(echo.HeaderContentDisposition, "attachment; filename="+c.String())

	return e.Stream(200, "application/octet-stream", buf)
}
