package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"github.com/multiformats/go-multihash"
	"gorm.io/gorm"
)

const (
	blockSize         = 0x10000
	maxBlobUploadSize = 100 << 20
)

const blobCleanupTimeout = 5 * time.Second

type blobUploadLock struct {
	mu   sync.Mutex
	refs int
}

type blobUploadLockSet struct {
	mu    sync.Mutex
	locks map[string]*blobUploadLock
}

// lock serializes publication of equal canonical DID/CID uploads while
// allowing unrelated blobs to upload concurrently. The lock is reference
// counted so idle keys do not accumulate for the lifetime of the process.
func (s *blobUploadLockSet) lock(key string) func() {
	s.mu.Lock()
	if s.locks == nil {
		s.locks = make(map[string]*blobUploadLock)
	}
	entry := s.locks[key]
	if entry == nil {
		entry = &blobUploadLock{}
		s.locks[key] = entry
	}
	entry.refs++
	s.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		s.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.locks, key)
		}
		s.mu.Unlock()
	}
}

func blobUploadKey(did string, c cid.Cid) string {
	return did + "\\x00" + c.String()
}

func detachedBlobCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), blobCleanupTimeout)
}

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
	logger := s.logger.With("name", "handleRepoUploadBlob")

	urepo := e.Get("repo").(*models.RepoActor)

	mime := e.Request().Header.Get("content-type")
	if mime == "" {
		mime = "application/octet-stream"
	}
	if principal, ok := PrincipalFromContext(e).(*OAuthPrincipal); ok && !oauthAllowsBlobScope(principal, mime) {
		return helpers.InsufficientScopeError(e, "blob:"+mime)
	}

	storage := "sqlite"
	s3Upload := s.s3Config != nil && s.s3Config.BlobstoreEnabled
	if s3Upload {
		storage = "s3"
		if s.s3Config.Bucket == "" || s.s3Config.Region == "" {
			logger.Error("S3 blob storage is missing required configuration")
			return helpers.ServerError(e, nil)
		}
	}

	// Read and hash the request before creating the metadata row. This keeps
	// malformed/failed requests from leaving a CID-less blob behind and lets a
	// new S3 row be inserted complete (CID and immutable target) before upload.
	read := 0
	buf := make([]byte, blockSize)
	fulldata := new(bytes.Buffer)
	limitedBody := io.LimitReader(e.Request().Body, maxBlobUploadSize+1)
	for {
		n, err := io.ReadFull(limitedBody, buf)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			if n == 0 {
				break
			}
		} else if err != nil {
			logger.Error("error reading blob", "error", err)
			return helpers.ServerError(e, nil)
		}
		read += n
		_, _ = fulldata.Write(buf[:n])
		if n < blockSize {
			break
		}
	}
	if read > maxBlobUploadSize {
		return helpers.InputError(e, nil)
	}

	c, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(fulldata.Bytes())
	if err != nil {
		logger.Error("error creating cid prefix", "error", err)
		return helpers.ServerError(e, nil)
	}

	unlock := s.blobUploadLocks.lock(blobUploadKey(urepo.Repo.Did, c))
	defer unlock()

	if existing, err := s.findReadyBlob(ctx, urepo.Repo.Did, c.Bytes()); err != nil {
		logger.Error("error checking for existing blob", "error", err)
		return helpers.ServerError(e, nil)
	} else if existing != nil {
		responseMime, responseSize := mime, read
		if existing.MimeType != "" || existing.Size != 0 {
			responseMime = existing.MimeType
			responseSize = int(existing.Size)
		}
		return e.JSON(200, repoUploadBlobResponse(c, responseMime, responseSize))
	}

	var svc s3BlobClient
	if s3Upload {
		svc, err = s.s3Service()
		if err != nil {
			logger.Error("error creating S3 client")
			return helpers.ServerError(e, nil)
		}
	}

	blob := models.Blob{
		Did:       urepo.Repo.Did,
		Cid:       c.Bytes(),
		MimeType:  mime,
		Size:      int64(read),
		RefCount:  0,
		CreatedAt: s.repoman.clock.Next().String(),
		Storage:   storage,
	}
	var objectKey string
	if s3Upload {
		objectKey, err = newS3BlobObjectKey(blob.Did, blob.Cid)
		if err != nil {
			logger.Error("error creating S3 blob identity")
			return helpers.ServerError(e, nil)
		}
		blob.Bucket = s.s3Config.Bucket
		blob.ObjectKey = objectKey
	}
	if s3Upload {
		// Publish the object before its metadata. A Blob row is a durable
		// capability: public and permissioned record writers may reference it as
		// soon as it exists, so it must never become visible before PutObject has
		// completed successfully.
		if _, err := svc.PutObject(&s3.PutObjectInput{
			Bucket: aws.String(blob.Bucket),
			Key:    aws.String(objectKey),
			Body:   bytes.NewReader(fulldata.Bytes()),
		}); err != nil {
			// Providers may have persisted an object before returning an error.
			// There is no metadata row to enqueue yet, so persist the exact
			// generation before attempting direct cleanup. The outbox remains the
			// durable retry path when DeleteObject also fails.
			cleanupCtx, cleanupCancel := detachedBlobCleanupContext(ctx)
			defer cleanupCancel()
			if enqueueErr := enqueueBlobDeletion(cleanupCtx, s.db, blob, s.s3Config, time.Now().UTC()); enqueueErr != nil {
				logger.Error("error enqueueing failed S3 upload cleanup", "error", enqueueErr)
			}
			_, _ = svc.DeleteObject(&s3.DeleteObjectInput{Bucket: aws.String(blob.Bucket), Key: aws.String(objectKey)})
			logger.Error("error uploading blob to S3", "error", err)
			return helpers.ServerError(e, nil)
		}

		if err := s.db.Create(ctx, &blob, nil).Error; err != nil {
			// The object is durable but its publication failed. Enqueue the exact
			// generation before attempting deletion so a transient DeleteObject
			// failure cannot strand the object. Keep the direct delete as a fast,
			// best-effort cleanup path.
			cleanupCtx, cleanupCancel := detachedBlobCleanupContext(ctx)
			defer cleanupCancel()
			if enqueueErr := enqueueBlobDeletion(cleanupCtx, s.db, blob, s.s3Config, time.Now().UTC()); enqueueErr != nil {
				logger.Error("error enqueueing failed S3 blob cleanup", "error", enqueueErr)
			}
			_, _ = svc.DeleteObject(&s3.DeleteObjectInput{Bucket: aws.String(blob.Bucket), Key: aws.String(objectKey)})
			if blob.ID != 0 {
				if deleteErr := s.db.Delete(cleanupCtx, &models.Blob{ID: blob.ID}, nil).Error; deleteErr != nil {
					logger.Error("error cleaning up failed S3 blob metadata", "error", deleteErr)
				}
				_ = s.db.Exec(cleanupCtx, "DELETE FROM blob_parts WHERE blob_id = ?", nil, blob.ID)
			}
			logger.Error("error publishing new blob metadata", "error", err)
			return helpers.ServerError(e, nil)
		}
	} else {
		// A Blob row is a durable capability: publish it together with every
		// BlobPart in one transaction so readers can never observe partial
		// content. Any part failure rolls back the row and all earlier parts.
		if err := publishSQLiteBlob(ctx, s.db, &blob, fulldata.Bytes(), nil); err != nil {
			logger.Error("error publishing blob and parts to db", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	return e.JSON(200, repoUploadBlobResponse(c, mime, read))
}

// publishSQLiteBlob keeps metadata publication and all content parts in one
// commit. afterBlobCreate is intentionally private and nil in production; the
// deterministic test uses it to pause between the metadata insert and parts,
// proving readers cannot observe an uncommitted capability.
func publishSQLiteBlob(ctx context.Context, database *db.DB, blob *models.Blob, content []byte, afterBlobCreate func()) error {
	return database.Transaction(ctx, func(tx *db.DB) error {
		if err := tx.Create(ctx, blob, nil).Error; err != nil {
			return err
		}
		if afterBlobCreate != nil {
			afterBlobCreate()
		}
		for offset, part := 0, 0; offset < len(content) || (offset == 0 && len(content) == 0); part++ {
			end := offset + blockSize
			if end > len(content) {
				end = len(content)
			}
			data := append([]byte(nil), content[offset:end]...)
			blobPart := models.BlobPart{BlobID: blob.ID, Idx: part, Data: data}
			if err := tx.Create(ctx, &blobPart, nil).Error; err != nil {
				return err
			}
			offset = end
			if end == len(content) {
				break
			}
		}
		return nil
	})
}

func repoUploadBlobResponse(c cid.Cid, mime string, size int) ComAtprotoRepoUploadBlobResponse {
	resp := ComAtprotoRepoUploadBlobResponse{}
	resp.Blob.Type = "blob"
	resp.Blob.Ref.Link = c.String()
	resp.Blob.MimeType = mime
	resp.Blob.Size = size
	return resp
}

type readyBlob struct {
	Blob    models.Blob
	Content []byte // populated for verified SQLite generations
}

// selectReadyBlob returns the newest cryptographically ready generation for a
// DID/CID. SQLite rows are loaded and hashed before they are considered ready;
// S3 rows are ready once their immutable target is persisted after PutObject.
// Invalid legacy SQLite rows are skipped and best-effort cleaned only when no
// public or permissioned references protect them.
func (s *Server) selectReadyBlob(ctx context.Context, did string, rawCID []byte, publicOnly bool) (*readyBlob, error) {
	var blobs []models.Blob
	query := s.db.Client().WithContext(ctx).Where("did = ? AND cid = ?", did, rawCID)
	if publicOnly {
		query = query.Where("ref_count > 0")
	}
	if err := query.Order("id DESC").Find(&blobs).Error; err != nil {
		return nil, err
	}
	for i := range blobs {
		blob := blobs[i]
		switch blob.Storage {
		case "s3":
			if _, _, err := blobS3Target(blob, s.s3Config); err != nil {
				continue
			}
			return &readyBlob{Blob: blob}, nil
		case "", "sqlite":
			content, valid, err := s.loadVerifiedSQLiteBlob(ctx, blob)
			if err != nil {
				return nil, err
			}
			if valid {
				return &readyBlob{Blob: blob, Content: content}, nil
			}
			if err := s.cleanupInvalidSQLiteBlob(ctx, blob); err != nil && ctx.Err() == nil && s.logger != nil {
				s.logger.Warn("error cleaning invalid legacy blob generation", "error", err)
			}
		}
	}
	return nil, nil
}

func (s *Server) loadVerifiedSQLiteBlob(ctx context.Context, blob models.Blob) ([]byte, bool, error) {
	var parts []models.BlobPart
	if err := s.db.Client().WithContext(ctx).
		Where("blob_id = ?", blob.ID).
		Order("idx ASC").Find(&parts).Error; err != nil {
		return nil, false, err
	}
	if len(parts) == 0 {
		return nil, false, nil
	}
	var data bytes.Buffer
	for expectedIdx, part := range parts {
		if part.Idx != expectedIdx {
			return nil, false, nil
		}
		_, _ = data.Write(part.Data)
	}
	expected, err := cid.Cast(blob.Cid)
	if err != nil {
		return nil, false, nil
	}
	actual, err := expected.Prefix().Sum(data.Bytes())
	if err != nil {
		return nil, false, nil
	}
	if !actual.Equals(expected) {
		return nil, false, nil
	}
	return data.Bytes(), true, nil
}

func (s *Server) cleanupInvalidSQLiteBlob(ctx context.Context, blob models.Blob) error {
	if blob.RefCount > 0 {
		return nil
	}
	var permissionedRefs int64
	if err := s.db.Client().WithContext(ctx).Model(&models.SpaceBlobRef{}).
		Where("author = ? AND cid = ?", blob.Did, cidString(blob.Cid)).Count(&permissionedRefs).Error; err != nil {
		return err
	}
	if permissionedRefs > 0 {
		return nil
	}
	return s.db.Transaction(ctx, func(tx *db.DB) error {
		var current models.Blob
		result := tx.Client().WithContext(ctx).Where("id = ?", blob.ID).First(&current)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil
		}
		if result.Error != nil {
			return result.Error
		}
		if current.RefCount > 0 {
			return nil
		}
		var refs int64
		if err := tx.Client().WithContext(ctx).Model(&models.SpaceBlobRef{}).
			Where("author = ? AND cid = ?", current.Did, cidString(current.Cid)).Count(&refs).Error; err != nil {
			return err
		}
		if refs > 0 {
			return nil
		}
		if err := tx.Exec(ctx, "DELETE FROM blob_parts WHERE blob_id = ?", nil, current.ID).Error; err != nil {
			return err
		}
		return tx.Exec(ctx, "DELETE FROM blobs WHERE id = ? AND ref_count = 0", nil, current.ID).Error
	})
}

func (s *Server) findReadyBlob(ctx context.Context, did string, rawCID []byte) (*models.Blob, error) {
	ready, err := s.selectReadyBlob(ctx, did, rawCID, false)
	if err != nil || ready == nil {
		return nil, err
	}
	return &ready.Blob, nil
}

func (s *Server) readReadyBlob(ctx context.Context, ready *readyBlob) ([]byte, error) {
	if ready == nil {
		return nil, gorm.ErrRecordNotFound
	}
	if ready.Blob.Storage == "" || ready.Blob.Storage == "sqlite" {
		return ready.Content, nil
	}
	if ready.Blob.Storage != "s3" {
		return nil, fmt.Errorf("unknown blob storage %q", ready.Blob.Storage)
	}
	if s.s3Config == nil || !s.s3Config.BlobstoreEnabled {
		return nil, fmt.Errorf("S3 blob storage is disabled")
	}
	bucket, objectKey, err := blobS3Target(ready.Blob, s.s3Config)
	if err != nil {
		return nil, err
	}
	svc, err := s.s3Service()
	if err != nil {
		return nil, err
	}
	result, err := svc.GetObject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(objectKey)})
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()
	var data bytes.Buffer
	if _, err := io.Copy(&data, result.Body); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
