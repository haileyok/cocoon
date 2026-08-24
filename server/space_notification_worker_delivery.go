package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SpaceNotificationSender is the only network-facing dependency of the
// durable worker. Send must make the supplied delivery idempotent using its
// IdempotencyKey; a process crash after Send and before the DB update is safe.
// Descriptive aliases retain the existing resolver names while making the
// injection contract discoverable to lifecycle owners.
type SpaceNotificationTargetResolver = SpaceNotificationResolver
type SpaceNotificationTargetResolverFunc = SpaceNotificationResolverFunc

const (
	spaceReplayCleanupBatchSize   = 1000
	spaceDeliveryCleanupBatchSize = 1000

	SpaceNotifyDeliveryPending   = "pending"
	SpaceNotifyDeliveryRetry     = "retry"
	SpaceNotifyDeliveryDelivered = "delivered"
	SpaceNotifyDeliveryExpired   = "expired"
	SpaceNotifyDeliveryFailed    = "failed"
)

type SpaceNotificationSender interface {
	Send(context.Context, string, models.SpaceNotifyDelivery) error
}

type SpaceNotificationSenderFunc func(context.Context, string, models.SpaceNotifyDelivery) error

func (f SpaceNotificationSenderFunc) Send(ctx context.Context, target string, d models.SpaceNotifyDelivery) error {
	if f == nil {
		return errors.New("nil notification sender")
	}
	return f(ctx, target, d)
}

type SpaceNotificationWorkerOptions struct {
	BaseDelay         time.Duration
	MaxDelay          time.Duration
	MaxAttempts       int
	BatchSize         int
	DeliveryRetention time.Duration
}

func (o SpaceNotificationWorkerOptions) defaults() SpaceNotificationWorkerOptions {
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
	if o.DeliveryRetention <= 0 {
		o.DeliveryRetention = SpaceNotifyDeliveryTTL
	}
	return o
}

// SpaceNotificationWorker is intentionally pull-based. It starts no goroutine;
// the lifecycle owner calls RunOnce after commit and on its desired schedule.
type SpaceNotificationWorker struct {
	db       *db.DB
	sender   SpaceNotificationSender
	resolver SpaceNotificationResolver
	clock    func() time.Time
	options  SpaceNotificationWorkerOptions
}

func NewSpaceNotificationWorker(s *Server, sender SpaceNotificationSender, resolver ...SpaceNotificationResolver) *SpaceNotificationWorker {
	var database *db.DB
	if s != nil {
		database = s.db
	}
	var r SpaceNotificationResolver
	if len(resolver) > 0 {
		r = resolver[0]
	} else {
		r = spaceNotificationResolver(s)
	}
	return &SpaceNotificationWorker{db: database, sender: sender, resolver: r, clock: spaceNotificationClock(s), options: (SpaceNotificationWorkerOptions{}).defaults()}
}

func NewSpaceNotificationWorkerWithOptions(s *Server, sender SpaceNotificationSender, options SpaceNotificationWorkerOptions, resolver ...SpaceNotificationResolver) *SpaceNotificationWorker {
	w := NewSpaceNotificationWorker(s, sender, resolver...)
	w.options = options.defaults()
	return w
}

func NewSpaceNotificationWorkerForDB(database *db.DB, sender SpaceNotificationSender, clock func() time.Time, resolver SpaceNotificationResolver) *SpaceNotificationWorker {
	if clock == nil {
		clock = time.Now
	}
	return &SpaceNotificationWorker{db: database, sender: sender, clock: clock, resolver: resolver, options: (SpaceNotificationWorkerOptions{}).defaults()}
}

func (s *Server) SetSpaceNotificationSender(sender SpaceNotificationSender) {
	if s != nil {
		s.spaceNotifySender = sender
	}
}

func (s *Server) runSpaceNotificationWorker(ctx context.Context) {
	if s == nil || s.config == nil || !s.config.SpacesEnabled || s.spaceNotifySender == nil {
		return
	}
	worker := NewSpaceNotificationWorker(s, s.spaceNotifySender)
	run := func() {
		if _, err := worker.RunOnce(ctx, 0); err != nil && ctx.Err() == nil && s.logger != nil {
			s.logger.Error("error processing Spaces notification outbox", "err", err)
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

func (w *SpaceNotificationWorker) SetSender(sender SpaceNotificationSender) { w.sender = sender }
func (w *SpaceNotificationWorker) SetResolver(resolver SpaceNotificationResolver) {
	w.resolver = resolver
}
func (w *SpaceNotificationWorker) SetClock(clock func() time.Time) {
	if clock == nil {
		clock = time.Now
	}
	w.clock = clock
}
func (w *SpaceNotificationWorker) SetOptions(options SpaceNotificationWorkerOptions) {
	w.options = options.defaults()
}
func (w *SpaceNotificationWorker) now() time.Time {
	if w.clock == nil {
		return time.Now().UTC()
	}
	return w.clock().UTC()
}

// RunOnce selects durable pending/retry rows in ID order. It deliberately does
// not use a process-local claim: duplicate workers and crash redelivery are
// handled by the sender's deterministic idempotency key.
func (w *SpaceNotificationWorker) RunOnce(ctx context.Context, limit int) (int, error) {
	if w == nil || w.db == nil {
		return 0, errors.New("notification worker has no database")
	}
	if limit <= 0 || limit > w.options.BatchSize {
		limit = w.options.BatchSize
	}
	now := w.now()
	if err := w.expire(ctx, now); err != nil {
		return 0, err
	}
	var rows []models.SpaceNotifyDelivery
	q := w.db.Client().WithContext(ctx).Where("status IN ?", []string{"pending", "retry"}).Where("expires_at > ?", now).Where("(next_attempt_at IS NULL OR next_attempt_at <= ?)", now).Order("id ASC").Limit(limit)
	if err := q.Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("load notification outbox: %w", err)
	}
	for _, row := range rows {
		target, err := w.resolve(ctx, row.Service)
		if err == nil && w.sender == nil {
			err = errors.New("notification worker has no sender")
		}
		if err == nil {
			err = w.sender.Send(ctx, target, row)
		}
		if err != nil {
			if e := w.fail(ctx, row.IdempotencyKey, err, now); e != nil {
				return len(rows), e
			}
			continue
		}
		when := now
		if err := w.db.Client().WithContext(ctx).Model(&models.SpaceNotifyDelivery{}).Where("idempotency_key = ? AND status IN ?", row.IdempotencyKey, []string{"pending", "retry", "processing"}).Updates(map[string]any{"status": "delivered", "delivered_at": &when, "next_attempt_at": nil, "last_error": "", "updated_at": now}).Error; err != nil {
			return len(rows), err
		}
	}
	return len(rows), nil
}

func (w *SpaceNotificationWorker) ProcessOnce(ctx context.Context, limit int) (int, error) {
	return w.RunOnce(ctx, limit)
}

func (w *SpaceNotificationWorker) resolve(ctx context.Context, service string) (string, error) {
	if w.resolver == nil {
		if strings.TrimSpace(service) == "" {
			return "", errors.New("empty notification service")
		}
		return service, nil
	}
	target, err := w.resolver.Resolve(ctx, service)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(target) == "" {
		return "", errors.New("empty notification target")
	}
	return target, nil
}

func (w *SpaceNotificationWorker) expire(ctx context.Context, now time.Time) error {
	var firstErr error
	recordErr := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	if err := w.db.Client().WithContext(ctx).Model(&models.SpaceNotifyDelivery{}).Where("status IN ? AND expires_at <= ?", []string{SpaceNotifyDeliveryPending, SpaceNotifyDeliveryRetry, "processing"}, now).Updates(map[string]any{"status": SpaceNotifyDeliveryExpired, "last_error": "delivery expired", "updated_at": now}).Error; err != nil {
		recordErr(err)
	}
	if _, err := w.pruneTerminalDeliveries(ctx, now); err != nil {
		recordErr(err)
	}
	// Registration expiry and replay-token cleanup are independent of delivery
	// cleanup. Run both even when an earlier cleanup fails so stale credentials
	// are not retained unnecessarily.
	if err := w.db.Client().WithContext(ctx).Where("expires_at <= ?", now).Delete(&models.SpaceNotifyRegistration{}).Error; err != nil {
		recordErr(err)
	}
	if _, err := space.NewGORMReplayStore(w.db.Client()).DeleteExpired(ctx, now, spaceReplayCleanupBatchSize); err != nil {
		recordErr(err)
	}
	return firstErr
}

// pruneTerminalDeliveries removes only terminal delivery rows after their
// retention interval. Select IDs first so an empty candidate set does not issue
// a SQLite write, and repeat the status/age predicates on delete to avoid
// deleting a row that became active between the two statements.
func (w *SpaceNotificationWorker) pruneTerminalDeliveries(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-w.options.DeliveryRetention)
	terminalStatuses := []string{SpaceNotifyDeliveryDelivered, SpaceNotifyDeliveryExpired, SpaceNotifyDeliveryFailed}
	var ids []uint
	if err := w.db.Client().WithContext(ctx).
		Model(&models.SpaceNotifyDelivery{}).
		Where("status IN ? AND updated_at <= ?", terminalStatuses, cutoff).
		Order("updated_at ASC, id ASC").
		Limit(spaceDeliveryCleanupBatchSize).
		Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result := w.db.Client().WithContext(ctx).
		Where("id IN ? AND status IN ? AND updated_at <= ?", ids, terminalStatuses, cutoff).
		Delete(&models.SpaceNotifyDelivery{})
	return result.RowsAffected, result.Error
}

func (w *SpaceNotificationWorker) fail(ctx context.Context, key string, cause error, now time.Time) error {
	return w.db.Transaction(ctx, func(tx *db.DB) error {
		var row models.SpaceNotifyDelivery
		if err := tx.Client().WithContext(ctx).Where("idempotency_key = ?", key).First(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if row.Status == "delivered" || row.Status == "expired" || row.Status == "failed" {
			return nil
		}
		attempt := row.AttemptCount + 1
		status := "retry"
		var next *time.Time
		if !now.Before(row.ExpiresAt) {
			status = "expired"
		} else if attempt >= w.options.MaxAttempts {
			status = "failed"
		} else {
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
			if candidate.Before(row.ExpiresAt) {
				next = &candidate
			} else {
				status = "expired"
			}
		}
		return tx.Client().WithContext(ctx).Model(&models.SpaceNotifyDelivery{}).Where("id = ?", row.ID).Updates(map[string]any{"status": status, "attempt_count": attempt, "next_attempt_at": next, "last_error": truncateNotificationError(cause), "updated_at": now}).Error
	})
}

func truncateNotificationError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 1000 {
		return value[:1000]
	}
	return value
}

// queueSpaceNotifyWriteForwarding is used by notifyWrite reception and
// reconciliation only after upsertSpaceWriterSnapshot accepts a new revision.
// Same-revision hash matches and older snapshots are idempotent/no-op and must
// not call this function; same-revision hash conflicts fail before forwarding.
// It is called inside the writer transaction.
func queueSpaceNotifyWriteForwarding(ctx context.Context, tx *db.DB, spaceRef, author, rev string, digest, payload []byte, now time.Time) error {
	var regs []models.SpaceNotifyRegistration
	if err := tx.Client().WithContext(ctx).Where("space = ? AND expires_at > ?", spaceRef, now).Order("service ASC").Find(&regs).Error; err != nil {
		return err
	}
	for _, reg := range regs {
		d := &models.SpaceNotifyDelivery{IdempotencyKey: notificationIdempotencyKey(SpaceNotifyWriteLXM, spaceRef, reg.Service, author, rev), Kind: SpaceNotifyWriteLXM, Space: spaceRef, Service: reg.Service, Author: author, Rev: rev, Hash: append([]byte(nil), digest...), Payload: append([]byte(nil), payload...), Status: "pending", ExpiresAt: now.Add(SpaceNotifyDeliveryTTL), CreatedAt: now, UpdatedAt: now}
		if err := tx.Client().WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "idempotency_key"}}, DoNothing: true}).Create(d).Error; err != nil {
			return err
		}
	}
	return nil
}

func queueSpaceNotifyDeletedForwarding(ctx context.Context, tx *db.DB, spaceRef string, now time.Time) error {
	payload, err := jsonSpaceDeletedPayload(spaceRef)
	if err != nil {
		return err
	}
	var regs []models.SpaceNotifyRegistration
	if err := tx.Client().WithContext(ctx).Where("space = ? AND expires_at > ?", spaceRef, now).Order("service ASC").Find(&regs).Error; err != nil {
		return err
	}
	for _, reg := range regs {
		d := &models.SpaceNotifyDelivery{IdempotencyKey: notificationIdempotencyKey(SpaceNotifySpaceDeletedLXM, spaceRef, reg.Service), Kind: SpaceNotifySpaceDeletedLXM, Space: spaceRef, Service: reg.Service, Deleted: true, Payload: payload, Status: "pending", ExpiresAt: now.Add(SpaceNotifyDeliveryTTL), CreatedAt: now, UpdatedAt: now}
		if err := tx.Client().WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "idempotency_key"}}, DoNothing: true}).Create(d).Error; err != nil {
			return err
		}
	}
	return nil
}

func jsonSpaceDeletedPayload(spaceRef string) ([]byte, error) {
	return json.Marshal(struct {
		Space string `json:"space"`
	}{Space: spaceRef})
}

// SpaceNotificationRepoSnapshot is the bounded listRepos metadata used by
// reconciliation. A partial page never causes absent writers to be deleted.
type SpaceNotificationRepoSnapshot struct {
	Repo string
	Rev  string
	Hash []byte
	Host string
}

func (w *SpaceNotificationWorker) ReconcileSpaceWriters(ctx context.Context, spaceRef string, snapshots []SpaceNotificationRepoSnapshot, limit int) (int, error) {
	if w == nil || w.db == nil {
		return 0, errors.New("notification worker has no database")
	}
	parsed, err := space.ParseSpaceURI(spaceRef)
	if err != nil {
		return 0, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if len(snapshots) > limit {
		snapshots = snapshots[:limit]
	}
	snapshots = append([]SpaceNotificationRepoSnapshot(nil), snapshots...)
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].Repo < snapshots[j].Repo })
	now := w.now()
	count := 0
	err = w.db.Transaction(ctx, func(tx *db.DB) error {
		for _, snapshot := range snapshots {
			if _, err := syntax.ParseDID(snapshot.Repo); err != nil {
				return fmt.Errorf("invalid reconciliation repo: %w", err)
			}
			if _, err := syntax.ParseTID(snapshot.Rev); err != nil {
				return fmt.Errorf("invalid reconciliation rev: %w", err)
			}
			digest, err := spaceNotifyDigest(snapshot.Hash)
			if err != nil {
				return fmt.Errorf("invalid reconciliation hash: %w", err)
			}
			accepted, err := upsertSpaceWriterSnapshot(ctx, tx, parsed.String(), snapshot.Repo, snapshot.Host, snapshot.Rev, digest, now, &now)
			if err != nil {
				return err
			}
			if !accepted {
				continue
			}
			payload, err := spaceNotifyWritePayload(parsed.String(), snapshot.Repo, snapshot.Rev, digest)
			if err != nil {
				return err
			}
			if err := queueSpaceNotifyWriteForwarding(ctx, tx, parsed.String(), snapshot.Repo, snapshot.Rev, digest, payload, now); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (w *SpaceNotificationWorker) ReconcileNotifyWriters(ctx context.Context, spaceRef string, snapshots []SpaceNotificationRepoSnapshot, limit int) (int, error) {
	return w.ReconcileSpaceWriters(ctx, spaceRef, snapshots, limit)
}

// QueueSpaceDeletedNotifications records the tombstone and fans out durable
// deletion deliveries; it performs no network I/O.
func (s *Server) QueueSpaceDeletedNotifications(ctx context.Context, spaceRef, source string) error {
	return s.RecordSpaceNotifySpaceDeleted(ctx, spaceRef, source, true)
}
