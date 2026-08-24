package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

const (
	BlobDeletionPending = "pending"
	BlobDeletionRetry   = "retry"
	BlobDeletionDeleted = "deleted"
	BlobDeletionFailed  = "failed"
)

const (
	blobDeletionFailureMessage = "S3 blob deletion failed"
	// BlobDeletionRetention is the documented minimum time successful deletion
	// rows remain available for audit/replay inspection.
	BlobDeletionRetention = 7 * 24 * time.Hour
)

// BlobDeletionS3Client is the small part of the AWS client needed by the
// durable deletion worker. Keeping this interface narrow makes tests safe and
// prevents the worker from depending on provider-specific client state.
type BlobDeletionS3Client interface {
	DeleteObject(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
}

type BlobDeletionWorkerOptions struct {
	BaseDelay time.Duration
	MaxDelay  time.Duration
	// MaxAttempts is retained for configuration compatibility. Deletion rows
	// never become terminally failed; it no longer limits retry eligibility.
	MaxAttempts      int
	BatchSize        int
	DeletedRetention time.Duration
}

func (o BlobDeletionWorkerOptions) defaults() BlobDeletionWorkerOptions {
	if o.BaseDelay <= 0 {
		o.BaseDelay = time.Minute
	}
	if o.MaxDelay <= 0 {
		o.MaxDelay = time.Hour
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 8
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.DeletedRetention <= 0 {
		o.DeletedRetention = BlobDeletionRetention
	}
	return o
}

// BlobDeletionWorker processes only rows visible through the root database
// connection. Consequently rows written by an account-delete transaction are
// not eligible until that transaction commits.
type BlobDeletionWorker struct {
	db            *db.DB
	client        BlobDeletionS3Client
	clientFactory func() (BlobDeletionS3Client, error)
	clock         func() time.Time
	options       BlobDeletionWorkerOptions
	clientMu      sync.Mutex
}

func NewBlobDeletionWorker(s *Server) *BlobDeletionWorker {
	w := &BlobDeletionWorker{options: (BlobDeletionWorkerOptions{}).defaults(), clock: time.Now}
	if s != nil {
		w.db = s.db
		w.clientFactory = func() (BlobDeletionS3Client, error) {
			return s.blobDeletionService()
		}
	}
	return w
}

func NewBlobDeletionWorkerForDB(database *db.DB, client BlobDeletionS3Client, clock func() time.Time) *BlobDeletionWorker {
	if clock == nil {
		clock = time.Now
	}
	return &BlobDeletionWorker{db: database, client: client, clock: clock, options: (BlobDeletionWorkerOptions{}).defaults()}
}

func (w *BlobDeletionWorker) SetS3Client(client BlobDeletionS3Client) {
	if w == nil {
		return
	}
	w.clientMu.Lock()
	w.client = client
	w.clientMu.Unlock()
}

func (w *BlobDeletionWorker) SetClock(clock func() time.Time) {
	if w == nil {
		return
	}
	if clock == nil {
		clock = time.Now
	}
	w.clock = clock
}

func (w *BlobDeletionWorker) SetOptions(options BlobDeletionWorkerOptions) {
	if w == nil {
		return
	}
	w.options = options.defaults()
}

func (w *BlobDeletionWorker) now() time.Time {
	if w == nil || w.clock == nil {
		return time.Now().UTC()
	}
	return w.clock().UTC()
}

func (w *BlobDeletionWorker) getClient() (BlobDeletionS3Client, error) {
	if w == nil {
		return nil, errors.New("blob deletion worker is nil")
	}
	w.clientMu.Lock()
	defer w.clientMu.Unlock()
	if w.client != nil {
		return w.client, nil
	}
	if w.clientFactory == nil {
		return nil, errors.New("blob deletion worker has no S3 client")
	}
	client, err := w.clientFactory()
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("blob deletion worker received nil S3 client")
	}
	w.client = client
	return client, nil
}

// RunOnce processes at most limit eligible rows. Network I/O happens before
// the terminal DB update, never inside an account transaction. DeleteObject
// is idempotent; a provider's not-found response is therefore success.
func (w *BlobDeletionWorker) RunOnce(ctx context.Context, limit int) (int, error) {
	if w == nil || w.db == nil {
		return 0, errors.New("blob deletion worker has no database")
	}
	if limit <= 0 || limit > w.options.BatchSize {
		limit = w.options.BatchSize
	}
	now := w.now()
	var rows []models.BlobDeletion
	if err := w.db.Client().WithContext(ctx).
		Where("status IN ?", []string{BlobDeletionPending, BlobDeletionRetry, BlobDeletionFailed}).
		Where("next_attempt_at IS NULL OR next_attempt_at <= ?", now).
		Order("id ASC").Limit(limit).Find(&rows).Error; err != nil {
		return 0, err
	}
	if _, err := w.pruneDeleted(ctx, now); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	client, clientErr := w.getClient()
	if clientErr != nil {
		// S3 configuration/factory failure is a worker-level outage, not a
		// deletion attempt. Leave all selected rows untouched for the next run.
		return 0, clientErr
	}
	processed := 0
	for _, row := range rows {
		var err error
		if row.Bucket == "" || row.ObjectKey == "" {
			err = errors.New("invalid S3 deletion target")
		} else {
			_, err = client.DeleteObject(&s3.DeleteObjectInput{
				Bucket: aws.String(row.Bucket),
				Key:    aws.String(row.ObjectKey),
			})
			if isS3ObjectGone(err) {
				err = nil
			}
		}
		if err != nil {
			if updateErr := w.fail(ctx, row.ID, now); updateErr != nil {
				return processed, updateErr
			}
			processed++
			continue
		}
		when := now
		if updateErr := w.db.Client().WithContext(ctx).
			Model(&models.BlobDeletion{}).
			Where("id = ? AND status IN ?", row.ID, []string{BlobDeletionPending, BlobDeletionRetry, BlobDeletionFailed}).
			Updates(map[string]any{
				"status":          BlobDeletionDeleted,
				"deleted_at":      &when,
				"next_attempt_at": nil,
				"last_error":      "",
				"updated_at":      now,
			}).Error; updateErr != nil {
			return processed, updateErr
		}
		processed++
	}
	return processed, nil
}

func (w *BlobDeletionWorker) ProcessOnce(ctx context.Context, limit int) (int, error) {
	return w.RunOnce(ctx, limit)
}

func (s *Server) runBlobDeletionWorker(ctx context.Context) {
	if s == nil || s.db == nil {
		return
	}
	worker := NewBlobDeletionWorker(s)
	run := func() {
		if _, err := worker.RunOnce(ctx, 0); err != nil && ctx.Err() == nil && s.logger != nil {
			// Do not include provider errors, object keys, or URLs in logs.
			s.logger.Error("error processing S3 blob deletion outbox")
		}
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (w *BlobDeletionWorker) fail(ctx context.Context, id uint, now time.Time) error {
	return w.db.Transaction(ctx, func(tx *db.DB) error {
		var row models.BlobDeletion
		if err := tx.Client().WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if row.Status == BlobDeletionDeleted {
			return nil
		}
		attempt := row.AttemptCount + 1
		// Deletion compliance is eventual even during a prolonged outage. Keep
		// the row retryable forever, with exponential delay capped at MaxDelay.
		delay := w.options.BaseDelay
		for i := 1; i < attempt && delay < w.options.MaxDelay; i++ {
			if delay > w.options.MaxDelay/2 {
				delay = w.options.MaxDelay
			} else {
				delay *= 2
			}
		}
		if delay > w.options.MaxDelay {
			delay = w.options.MaxDelay
		}
		candidate := now.Add(delay)
		next := &candidate
		status := BlobDeletionRetry
		return tx.Client().WithContext(ctx).Model(&models.BlobDeletion{}).Where("id = ?", id).Updates(map[string]any{
			"status":          status,
			"attempt_count":   attempt,
			"next_attempt_at": next,
			"last_error":      blobDeletionFailureMessage,
			"updated_at":      now,
		}).Error
	})
}

// PruneDeleted removes only successful deletion rows older than the configured
// retention interval. Pending/retry/failed rows are never pruned.
func (w *BlobDeletionWorker) PruneDeleted(ctx context.Context) (int64, error) {
	if w == nil || w.db == nil {
		return 0, errors.New("blob deletion worker has no database")
	}
	return w.pruneDeleted(ctx, w.now())
}

func (w *BlobDeletionWorker) pruneDeleted(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-w.options.DeletedRetention)
	var ids []uint
	if err := w.db.Client().WithContext(ctx).
		Model(&models.BlobDeletion{}).
		Where("status = ? AND deleted_at IS NOT NULL AND deleted_at <= ?", BlobDeletionDeleted, cutoff).
		Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result := w.db.Client().WithContext(ctx).
		Where("id IN ? AND status = ? AND deleted_at IS NOT NULL AND deleted_at <= ?", ids, BlobDeletionDeleted, cutoff).
		Delete(&models.BlobDeletion{})
	return result.RowsAffected, result.Error
}

func isS3ObjectGone(err error) bool {
	if err == nil {
		return true
	}
	var requestFailure awserr.RequestFailure
	if errors.As(err, &requestFailure) && requestFailure.StatusCode() == http.StatusNotFound {
		return true
	}
	var awsError awserr.Error
	if errors.As(err, &awsError) {
		switch awsError.Code() {
		case "NoSuchKey", "NotFound", "NoSuchObject":
			return true
		}
	}
	return false
}
