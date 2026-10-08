package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

// Space blobs, following the reference PDS's space/getBlob.ts and
// listBlobs.ts at bluesky-social/atproto 5b95b2f2. A blob is uploaded with
// com.atproto.repo.uploadBlob and belongs to a space once a record there
// references it.

// readBlobBytes reads an account's blob from its storage.
func (s *Server) readBlobBytes(ctx context.Context, did string, c cid.Cid) ([]byte, bool, error) {
	var blobs []models.Blob
	if err := s.db.Raw(ctx, "SELECT * FROM blobs WHERE did = ? AND cid = ?", nil, did, c.Bytes()).Scan(&blobs).Error; err != nil {
		return nil, false, err
	}
	if len(blobs) == 0 {
		return nil, false, nil
	}
	blob := blobs[0]
	switch blob.Storage {
	case "s3":
		if s.s3Config == nil || !s.s3Config.BlobstoreEnabled {
			return nil, false, fmt.Errorf("s3 storage disabled")
		}
		cfg := &aws.Config{Region: aws.String(s.s3Config.Region), Credentials: credentials.NewStaticCredentials(s.s3Config.AccessKey, s.s3Config.SecretKey, "")}
		if s.s3Config.Endpoint != "" {
			cfg.Endpoint = aws.String(s.s3Config.Endpoint)
			cfg.S3ForcePathStyle = aws.Bool(true)
		}
		sess, err := session.NewSession(cfg)
		if err != nil {
			return nil, false, err
		}
		out, err := s3.New(sess).GetObjectWithContext(ctx, &s3.GetObjectInput{Bucket: aws.String(s.s3Config.Bucket), Key: aws.String(fmt.Sprintf("blobs/%s/%s", did, c.String()))})
		if err != nil {
			return nil, false, err
		}
		defer out.Body.Close()
		b, err := io.ReadAll(out.Body)
		return b, err == nil, err
	default:
		var parts []models.BlobPart
		if err := s.db.Raw(ctx, "SELECT * FROM blob_parts WHERE blob_id = ? ORDER BY idx", nil, blob.ID).Scan(&parts).Error; err != nil {
			return nil, false, err
		}
		var buf bytes.Buffer
		for _, p := range parts {
			buf.Write(p.Data)
		}
		return buf.Bytes(), true, nil
	}
}

// assertBlobsUploaded checks every blob a write references was uploaded.
func (st *spaceStore) assertBlobsUploaded(writes []spaceWrite) error {
	for _, w := range writes {
		for _, b := range w.Blobs {
			var n int64
			if err := st.db.Model(&models.Blob{}).Where("did = ? AND cid = ?", st.did, b.Bytes()).Count(&n).Error; err != nil {
				return err
			}
			if n == 0 {
				return errInvalid("BlobNotFound", "Could not find blob: %s", b)
			}
		}
	}
	return nil
}

// recordBlobs returns the blobs a space record references.
func (st *spaceStore) recordBlobs(recordURI string) ([]string, error) {
	var cids []string
	return cids, st.db.Model(&models.SpaceRecordBlob{}).Where("record_uri = ?", recordURI).Pluck("blob_cid", &cids).Error
}

// gcBlobs deletes blobs no record, public or space, references any more.
func (st *spaceStore) gcBlobs(cids []string) error {
	for _, cs := range cids {
		c, err := cid.Decode(cs)
		if err != nil {
			continue
		}
		var inSpaces int64
		if err := st.db.Model(&models.SpaceRecordBlob{}).Where("did = ? AND blob_cid = ?", st.did, cs).Count(&inSpaces).Error; err != nil {
			return err
		}
		if inSpaces > 0 {
			continue
		}
		if err := st.db.Exec("DELETE FROM blob_parts WHERE blob_id IN (SELECT id FROM blobs WHERE did = ? AND cid = ? AND ref_count <= 0)", st.did, c.Bytes()).Error; err != nil {
			return err
		}
		if err := st.db.Exec("DELETE FROM blobs WHERE did = ? AND cid = ? AND ref_count <= 0", st.did, c.Bytes()).Error; err != nil {
			return err
		}
	}
	return nil
}

func (st *spaceStore) listBlobs(uri string, limit int, since, cursor string) ([]string, error) {
	q := st.db.Table("space_record_blobs AS b").
		Joins("JOIN space_records r ON r.uri = b.record_uri").
		Where("r.did = ? AND r.space = ?", st.did, uri).
		Group("b.blob_cid").Order("b.blob_cid asc").Limit(limit)
	if since != "" {
		q = q.Where("r.repo_rev > ?", since)
	}
	if cursor != "" {
		q = q.Where("b.blob_cid > ?", cursor)
	}
	var cids []string
	return cids, q.Pluck("b.blob_cid", &cids).Error
}

func (st *spaceStore) isBlobInSpace(uri, blobCid string) (bool, error) {
	var n int64
	err := st.db.Table("space_record_blobs AS b").
		Joins("JOIN space_records r ON r.uri = b.record_uri").
		Where("r.did = ? AND r.space = ? AND b.blob_cid = ?", st.did, uri, blobCid).Count(&n).Error
	return n > 0, err
}

// isSpaceOnlyBlob reports whether only space records reference a blob, which
// public sync must not serve.
func (s *Server) isSpaceOnlyBlob(ctx context.Context, did string, c cid.Cid) (bool, error) {
	var rows []struct{ RefCount int }
	if err := s.db.Raw(ctx, "SELECT ref_count FROM blobs WHERE did = ? AND cid = ?", nil, did, c.Bytes()).Scan(&rows).Error; err != nil {
		return false, err
	}
	if len(rows) == 0 || rows[0].RefCount > 0 {
		return false, nil
	}
	var n int64
	if err := s.db.Client().WithContext(ctx).Model(&models.SpaceRecordBlob{}).Where("did = ? AND blob_cid = ?", did, c.String()).Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Server) handleSpaceGetBlob(e echo.Context) error {
	p, err := s.spaceReadAuth(e)
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	c, err := cid.Decode(e.QueryParam("cid"))
	if err != nil {
		return writeSpaceResult(e, nil, errInvalid("", "cid must be a valid cid"))
	}
	// Do not reveal whether an unreferenced blob exists.
	in, err := s.spaceStore(nil, p.repo).isBlobInSpace(p.ref.String(), c.String())
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	if !in {
		return writeSpaceResult(e, nil, errInvalid("BlobNotFound", "Blob not found"))
	}
	data, found, err := s.readBlobBytes(e.Request().Context(), p.repo, c)
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	if !found {
		return writeSpaceResult(e, nil, errInvalid("BlobNotFound", "Blob not found"))
	}
	h := e.Response().Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", c.String()))
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	return e.Blob(http.StatusOK, "application/octet-stream", data)
}

func (s *Server) handleSpaceListBlobs(e echo.Context) error {
	body, err := func() (any, error) {
		p, err := s.spaceReadAuth(e)
		if err != nil {
			return nil, err
		}
		q := e.QueryParams()
		since, err := parseTIDParam("since", q.Get("since"))
		if err != nil {
			return nil, err
		}
		limit, err := parseLimitParam(q.Get("limit"), 500, 1, 1000)
		if err != nil {
			return nil, err
		}
		cids, err := s.spaceStore(nil, p.repo).listBlobs(p.ref.String(), limit, since, q.Get("cursor"))
		if err != nil {
			return nil, err
		}
		if cids == nil {
			cids = []string{}
		}
		res := map[string]any{"cids": cids}
		if len(cids) >= limit {
			res["cursor"] = cids[len(cids)-1]
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}
