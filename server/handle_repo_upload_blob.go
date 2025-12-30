package server

import (
	"bytes"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"github.com/multiformats/go-multihash"
)

const (
	blockSize = 0x10000
)

type ComAtprotoRepoUploadBlobResponse struct {
	Blob struct {
		Type string `json:"$type"`
		Ref  struct {
			Link string `json:"$link"`
		} `json:"ref"`
		MimeType string `json:"mimeType"`
		Size     int    `json:"size"`
	} `json:"blob"`
}

func (s *Server) handleRepoUploadBlob(e echo.Context) error {
	ctx := e.Request().Context()

	urepo := e.Get("repo").(*models.RepoActor)

	mime := e.Request().Header.Get("content-type")
	if mime == "" {
		mime = "application/octet-stream"
	}

	storage := "sqlite"
	s3Upload := s.s3Config != nil && s.s3Config.BlobstoreEnabled
	if s3Upload {
		storage = "s3"
	}
	blob := models.Blob{
		Did:       urepo.Repo.Did,
		RefCount:  0,
		CreatedAt: s.repoman.clock.Next().String(),
		Storage:   storage,
	}

	if err := s.db.Create(ctx, &blob, nil).Error; err != nil {
		s.logger.Error("error creating new blob in db", "error", err)
		return helpers.ServerError(e, nil)
	}

	read := 0
	part := 0

	buf := make([]byte, 0x10000)
	fulldata := new(bytes.Buffer)

	for {
		n, err := io.ReadFull(e.Request().Body, buf)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			if n == 0 {
				break
			}
		} else if err != nil && err != io.ErrUnexpectedEOF {
			s.logger.Error("error reading blob", "error", err)
			return helpers.ServerError(e, nil)
		}

		data := buf[:n]
		read += n
		fulldata.Write(data)

		if !s3Upload {
			blobPart := models.BlobPart{
				BlobID: blob.ID,
				Idx:    part,
				Data:   data,
			}

			if err := s.db.Create(ctx, &blobPart, nil).Error; err != nil {
				s.logger.Error("error adding blob part to db", "error", err)
				return helpers.ServerError(e, nil)
			}
		}
		part++

		if n < blockSize {
			break
		}
	}

	c, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(fulldata.Bytes())
	if err != nil {
		s.logger.Error("error creating cid prefix", "error", err)
		return helpers.ServerError(e, nil)
	}

	if s3Upload {
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

		if _, err := svc.PutObject(&s3.PutObjectInput{
			Bucket: aws.String(s.s3Config.Bucket),
			Key:    aws.String(fmt.Sprintf("blobs/%s/%s", urepo.Repo.Did, c.String())),
			Body:   bytes.NewReader(fulldata.Bytes()),
		}); err != nil {
			s.logger.Error("error uploading blob to s3", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	if err := s.db.Exec(ctx, "UPDATE blobs SET cid = ? WHERE id = ?", nil, c.Bytes(), blob.ID).Error; err != nil {
		// there should probably be somme handling here if this fails...
		s.logger.Error("error updating blob", "error", err)
		return helpers.ServerError(e, nil)
	}

	resp := ComAtprotoRepoUploadBlobResponse{}
	resp.Blob.Type = "blob"
	resp.Blob.Ref.Link = c.String()
	resp.Blob.MimeType = mime
	resp.Blob.Size = read

	return e.JSON(200, resp)
}
