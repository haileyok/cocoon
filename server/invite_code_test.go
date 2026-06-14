package server

import (
	"context"
	"sync"
	"testing"

	"github.com/haileyok/cocoon/models"
)

func (s *Server) insertInviteCode(t *testing.T, code string, uses int) {
	t.Helper()
	if err := s.db.Create(context.Background(), &models.InviteCode{
		Code:              code,
		RemainingUseCount: uses,
	}, nil).Error; err != nil {
		t.Fatalf("insert invite code: %v", err)
	}
}

func (s *Server) inviteRemaining(t *testing.T, code string) int {
	t.Helper()
	var ic models.InviteCode
	if err := s.db.Raw(context.Background(), "SELECT * FROM invite_codes WHERE code = ?", nil, code).Scan(&ic).Error; err != nil {
		t.Fatalf("read invite code: %v", err)
	}
	return ic.RemainingUseCount
}

func TestConsumeInviteCode(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	s.insertInviteCode(t, "single-use", 1)

	ok, err := s.consumeInviteCode(ctx, "single-use")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if !ok {
		t.Fatal("first consume should succeed")
	}
	if got := s.inviteRemaining(t, "single-use"); got != 0 {
		t.Fatalf("remaining = %d, want 0", got)
	}

	ok, err = s.consumeInviteCode(ctx, "single-use")
	if err != nil {
		t.Fatalf("consume (exhausted): %v", err)
	}
	if ok {
		t.Fatal("second consume should fail once exhausted")
	}
	if got := s.inviteRemaining(t, "single-use"); got != 0 {
		t.Fatalf("remaining went to %d; must never drop below 0", got)
	}

	ok, err = s.consumeInviteCode(ctx, "does-not-exist")
	if err != nil {
		t.Fatalf("consume (missing): %v", err)
	}
	if ok {
		t.Fatal("consuming a nonexistent code should fail")
	}
}

// TestConsumeInviteCodeConcurrent proves the consume is atomic: with a 1-use
// code and many concurrent callers, exactly one wins and the count never goes
// negative. A naive "remaining_use_count - 1" would let every caller succeed.
func TestConsumeInviteCodeConcurrent(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)

	// Serialize at the connection level so the test exercises the conditional
	// UPDATE's correctness rather than SQLite write-lock contention.
	if sqlDB, err := s.db.Client().DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	} else {
		t.Fatalf("get sql db: %v", err)
	}

	const uses = 1
	const goroutines = 25
	s.insertInviteCode(t, "race", uses)

	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ok, err := s.consumeInviteCode(ctx, "race")
			if err != nil {
				t.Errorf("consume: %v", err)
				return
			}
			if ok {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != uses {
		t.Fatalf("successful consumes = %d, want %d", successes, uses)
	}
	if got := s.inviteRemaining(t, "race"); got != 0 {
		t.Fatalf("remaining = %d, want 0 (must never go negative)", got)
	}
}
