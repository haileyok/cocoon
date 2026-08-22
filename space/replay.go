package space

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

var (
	ErrReplay                 = errors.New("replay detected")
	ErrNilReplayStore         = errors.New("nil replay store")
	ErrBatchReplayUnavailable = errors.New("atomic replay batch store unavailable")
)

// ReplayArtifact is one validated, single-use token/proof replay entry. A
// batch must be committed all at once: no artifact may be persisted if any
// artifact in the batch is already consumed.
type ReplayArtifact struct {
	JTI       string
	TokenType string
	ExpiresAt time.Time
}

// ReplayStore consumes a globally unique JTI exactly once. Implementations
// must make the check-and-insert atomic; callers invoke it only after a token
// or proof has passed signature and semantic validation.
type ReplayStore interface {
	Consume(ctx context.Context, jti, tokenType string, expiresAt time.Time) error
}

// BatchReplayStore extends ReplayStore with all-or-nothing batch consumption.
// Production exchange paths must require this interface rather than falling
// back to sequential Consume calls.
type BatchReplayStore interface {
	ReplayStore
	ConsumeBatch(ctx context.Context, artifacts []ReplayArtifact) error
}

// MemoryReplayStore is concurrency-safe and useful for tests or explicitly
// ephemeral deployments. It is not durable across process restarts.
type MemoryReplayStore struct {
	mu    sync.Mutex
	items map[string]time.Time
	now   func() time.Time
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return NewMemoryReplayStoreWithClock(time.Now)
}

// NewMemoryReplayStoreWithClock makes expiry deterministic in tests.
func NewMemoryReplayStoreWithClock(now func() time.Time) *MemoryReplayStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayStore{items: make(map[string]time.Time), now: now}
}
func (s *MemoryReplayStore) Consume(ctx context.Context, jti, tokenType string, expiresAt time.Time) error {
	return s.ConsumeBatch(ctx, []ReplayArtifact{{JTI: jti, TokenType: tokenType, ExpiresAt: expiresAt}})
}

// ConsumeBatch checks every artifact and inserts every fresh artifact while
// holding the same mutex. If validation or replay detection fails, the map is
// unchanged.
func (s *MemoryReplayStore) ConsumeBatch(_ context.Context, artifacts []ReplayArtifact) error {
	if s == nil {
		return ErrNilReplayStore
	}
	if len(artifacts) == 0 {
		return errors.New("empty replay batch")
	}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.JTI == "" {
			return errors.New("empty replay jti")
		}
		if _, duplicate := seen[artifact.JTI]; duplicate {
			return ErrReplay
		}
		seen[artifact.JTI] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]time.Time)
	}
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	for key, expiry := range s.items {
		// Keep the entry at the exact deadline. This matches DPoP's
		// inclusive max-age boundary; it expires immediately after it.
		if expiry.Before(now) {
			delete(s.items, key)
		}
	}
	for _, artifact := range artifacts {
		if _, exists := s.items[artifact.JTI]; exists {
			return ErrReplay
		}
	}
	for _, artifact := range artifacts {
		s.items[artifact.JTI] = artifact.ExpiresAt
	}
	return nil
}

// GORMReplayStore persists replay consumption in models.SpaceReplayJTI. The
// schema is included by models.SpaceModels; migrations remain the server's
// responsibility. A unique primary-key insert gives the required atomicity.
type GORMReplayStore struct{ DB *gorm.DB }

func NewGORMReplayStore(db *gorm.DB) *GORMReplayStore { return &GORMReplayStore{DB: db} }
func (s *GORMReplayStore) Consume(ctx context.Context, jti, tokenType string, expiresAt time.Time) error {
	return s.ConsumeBatch(ctx, []ReplayArtifact{{JTI: jti, TokenType: tokenType, ExpiresAt: expiresAt}})
}

// ConsumeBatch inserts all replay rows in one database transaction. Any
// duplicate or other error rolls the transaction back, so no earlier artifact
// in the batch is burned.
func (s *GORMReplayStore) ConsumeBatch(ctx context.Context, artifacts []ReplayArtifact) error {
	if s == nil || s.DB == nil {
		return ErrNilReplayStore
	}
	if len(artifacts) == 0 {
		return errors.New("empty replay batch")
	}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.JTI == "" {
			return errors.New("empty replay jti")
		}
		if _, duplicate := seen[artifact.JTI]; duplicate {
			return ErrReplay
		}
		seen[artifact.JTI] = struct{}{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, artifact := range artifacts {
			row := &models.SpaceReplayJTI{JTI: artifact.JTI, TokenType: artifact.TokenType, ExpiresAt: artifact.ExpiresAt}
			if err := tx.Create(row).Error; err != nil {
				if isUniqueViolation(err) {
					return ErrReplay
				}
				return err
			}
		}
		return nil
	})
}
func isUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key") || strings.Contains(msg, "primary key")
}
