package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// enqueueSpaceRepoNotifyWrite records a write notification in the durable
// outbox. It intentionally performs no endpoint resolution or network I/O;
// the later worker can consume these rows after the repo transaction commits.
func enqueueSpaceRepoNotifyWrite(ctx context.Context, tx *db.DB, spaceURI, author, rev string, hash []byte, now time.Time) error {
	var registrations []models.SpaceNotifyRegistration
	if err := tx.Client().WithContext(ctx).Where("space = ? AND expires_at > ?", spaceURI, now).Find(&registrations).Error; err != nil {
		return err
	}
	digest, err := spaceNotifyDigest(hash)
	if err != nil {
		return err
	}
	payload, err := spaceNotifyWritePayload(spaceURI, author, rev, digest)
	if err != nil {
		return err
	}
	for _, registration := range registrations {
		key := notificationIdempotencyKey(SpaceNotifyWriteLXM, spaceURI, registration.Service, author, rev)
		var existing models.SpaceNotifyDelivery
		findErr := tx.Client().WithContext(ctx).Where("idempotency_key = ?", key).First(&existing).Error
		if findErr == nil {
			continue
		}
		if !isRecordNotFound(findErr) {
			return findErr
		}
		delivery := models.SpaceNotifyDelivery{
			IdempotencyKey: key,
			Kind:           SpaceNotifyWriteLXM,
			Space:          spaceURI,
			Service:        registration.Service,
			Author:         author,
			Rev:            rev,
			Hash:           append([]byte(nil), digest...),
			Payload:        payload,
			Status:         "pending",
			ExpiresAt:      now.Add(SpaceNotifyDeliveryTTL),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := tx.Create(ctx, &delivery, nil).Error; err != nil {
			return err
		}
	}
	return nil
}

func isRecordNotFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }

func parseSpaceNotificationService(raw string) (string, error) {
	if err := validateManagingApp(raw); err != nil {
		return "", err
	}
	return raw, nil
}

const (
	SpaceNotifyWriteLXM        = "com.atproto.space.notifyWrite"
	SpaceNotifySpaceDeletedLXM = "com.atproto.space.notifySpaceDeleted"
	SpaceNotifyRegistrationTTL = 24 * time.Hour
	SpaceNotifyDeliveryTTL     = 7 * 24 * time.Hour
)

// SpaceNotificationResolver is optional: registration can persist a service
// identifier without doing network I/O, while hosts that have a resolver may
// reject an unresolvable service eagerly.
type SpaceNotificationResolver interface {
	Resolve(context.Context, string) (string, error)
}
type SpaceNotificationResolverFunc func(context.Context, string) (string, error)

func (f SpaceNotificationResolverFunc) Resolve(ctx context.Context, service string) (string, error) {
	if f == nil {
		return "", errors.New("nil notification resolver")
	}
	return f(ctx, service)
}

var (
	spaceNotificationResolvers sync.Map // map[*Server]SpaceNotificationResolver
	spaceNotificationClocks    sync.Map // map[*Server]func() time.Time
)

func (s *Server) SetSpaceNotificationResolver(r SpaceNotificationResolver) {
	if s == nil {
		return
	}
	if r == nil {
		spaceNotificationResolvers.Delete(s)
	} else {
		spaceNotificationResolvers.Store(s, r)
	}
}
func spaceNotificationResolver(s *Server) SpaceNotificationResolver {
	if s == nil {
		return nil
	}
	value, _ := spaceNotificationResolvers.Load(s)
	r, _ := value.(SpaceNotificationResolver)
	return r
}
func (s *Server) SetSpaceNotificationClock(now func() time.Time) {
	if s == nil {
		return
	}
	if now == nil {
		spaceNotificationClocks.Delete(s)
	} else {
		spaceNotificationClocks.Store(s, now)
	}
}
func spaceNotificationClock(s *Server) func() time.Time {
	if s != nil {
		if value, ok := spaceNotificationClocks.Load(s); ok {
			if now, valid := value.(func() time.Time); valid && now != nil {
				return now
			}
		}
	}
	return time.Now
}

func ParseSpaceNotificationHash(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("empty notification hash")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(raw)
	}
	if err != nil {
		decoded, err = hex.DecodeString(raw)
	}
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("notification hash must be a SHA-256 digest")
	}
	return decoded, nil
}

func spaceNotifyDigest(raw []byte) ([]byte, error) {
	if len(raw) == space.LtHashStateBytes {
		value, err := space.NewLtHash(raw)
		if err != nil {
			return nil, err
		}
		return value.Digest(), nil
	}
	if len(raw) == sha256.Size {
		return append([]byte(nil), raw...), nil
	}
	return nil, errors.New("invalid LtHash state or digest")
}
func spaceNotifyWritePayload(uri, author, rev string, digest []byte) ([]byte, error) {
	return json.Marshal(map[string]string{"space": uri, "repo": author, "rev": rev, "hash": base64.RawURLEncoding.EncodeToString(digest)})
}
func notificationIdempotencyKey(kind, uri, service string, parts ...string) string {
	values := []string{kind, uri, service}
	values = append(values, parts...)
	return strings.Join(values, "\\x00")
}

// ErrSpaceNotifyRevisionConflict indicates that a notification reused an
// existing revision with a different hash. The conflicting snapshot is never
// persisted or forwarded.
var ErrSpaceNotifyRevisionConflict = errors.New("space notification revision has conflicting hash")

// upsertSpaceWriterSnapshot accepts a snapshot only when it inserts a writer or
// advances its revision. The conditional upsert is the serialization point for
// both SQLite and PostgreSQL; a read-then-save would allow an older concurrent
// snapshot to overwrite a newer one.
//
// A same-revision snapshot with the same hash is an idempotent duplicate and
// returns accepted=false. It is deliberately not forwarded again because the
// original revision already owns its idempotency key. A same-revision hash
// conflict returns ErrSpaceNotifyRevisionConflict; an older snapshot is
// ignored without error.
func upsertSpaceWriterSnapshot(ctx context.Context, tx *db.DB, spaceURI, author, host, rev string, digest []byte, now time.Time, lastNotifiedAt *time.Time) (bool, error) {
	writer := &models.SpaceWriter{
		Space:     spaceURI,
		Author:    author,
		Host:      host,
		Rev:       rev,
		Hash:      append([]byte(nil), digest...),
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if lastNotifiedAt != nil {
		writer.LastNotifiedAt = lastNotifiedAt
	}
	updates := map[string]any{
		"host":       host,
		"rev":        rev,
		"hash":       append([]byte(nil), digest...),
		"status":     "active",
		"deleted_at": nil,
		"updated_at": now,
	}
	if lastNotifiedAt != nil {
		updates["last_notified_at"] = lastNotifiedAt
	}
	result := tx.Client().WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "space"}, {Name: "author"}},
		DoUpdates: clause.Assignments(updates),
		Where: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "space_writers.rev = ? OR space_writers.rev < excluded.rev", Vars: []any{""}},
		}},
	}).Create(writer)
	if result.Error != nil {
		return false, result.Error
	}
	if result.RowsAffected > 0 {
		return true, nil
	}

	var current models.SpaceWriter
	if err := tx.Client().WithContext(ctx).Where("space = ? AND author = ?", spaceURI, author).First(&current).Error; err != nil {
		return false, err
	}
	if current.Rev == rev {
		if !bytes.Equal(current.Hash, digest) {
			return false, fmt.Errorf("%w: space=%s author=%s rev=%s", ErrSpaceNotifyRevisionConflict, spaceURI, author, rev)
		}
		return false, nil
	}
	if current.Rev > rev {
		return false, nil
	}
	// The conditional upsert should report one affected row whenever the
	// current revision is older. Do not forward if a driver reports otherwise.
	return false, fmt.Errorf("conditional space writer upsert did not advance revision: current=%q incoming=%q", current.Rev, rev)
}

func (s *Server) RecordSpaceNotifyWrite(ctx context.Context, uri, author, rev string, hash []byte, source string) error {
	ref, err := space.ParseSpaceURI(uri)
	if err != nil {
		return err
	}
	if _, err := syntax.ParseDID(author); err != nil {
		return err
	}
	if _, err := syntax.ParseTID(rev); err != nil {
		return err
	}
	digest, err := spaceNotifyDigest(hash)
	if err != nil {
		return err
	}
	if err := s.checkSpaceAvailable(ctx, ref.String(), string(ref.AuthorityDID)); err != nil {
		return err
	}
	return s.db.Transaction(ctx, func(tx *db.DB) error {
		now := spaceNotificationClock(s)().UTC()
		accepted, err := upsertSpaceWriterSnapshot(ctx, tx, ref.String(), author, source, rev, digest, now, nil)
		if err != nil {
			return err
		}
		if !accepted {
			return nil
		}
		payload, err := spaceNotifyWritePayload(ref.String(), author, rev, digest)
		if err != nil {
			return err
		}
		return queueSpaceNotifyWriteForwarding(ctx, tx, ref.String(), author, rev, digest, payload, now)
	})
}

func (s *Server) RecordSpaceNotifySpaceDeleted(ctx context.Context, uri, source string, queueForwarding bool) error {
	ref, err := space.ParseSpaceURI(uri)
	if err != nil {
		return err
	}
	now := spaceNotificationClock(s)().UTC()
	return s.db.Transaction(ctx, func(tx *db.DB) error {
		tomb := &models.SpaceTombstone{Space: ref.String(), OwnerDID: string(ref.AuthorityDID), SourceDID: source, SourceNotification: SpaceNotifySpaceDeletedLXM, DeletedAt: now}
		if err := tx.Client().WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "space"}}, DoUpdates: clause.Assignments(map[string]any{"owner_did": tomb.OwnerDID, "source_did": source, "source_notification": SpaceNotifySpaceDeletedLXM, "deleted_at": now})}).Create(tomb).Error; err != nil {
			return err
		}
		// Retain locally hosted member repositories unchanged. The tombstone is
		// the host-wide credential revocation check; OAuth read_self remains
		// available for cleanup and migration recovery.
		if err := tx.Client().WithContext(ctx).Model(&models.SpaceWriter{}).Where("space = ?", ref.String()).Updates(map[string]any{"status": "deleted", "deleted_at": now}).Error; err != nil {
			return err
		}
		if queueForwarding {
			return queueSpaceNotifyDeletedForwarding(ctx, tx, ref.String(), now)
		}
		return nil
	})
}
