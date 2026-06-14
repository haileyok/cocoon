package server

import (
	"context"

	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

func (s *Server) getActorByHandle(ctx context.Context, handle string) (*models.Actor, error) {
	var actor models.Actor
	if err := s.db.First(ctx, &actor, models.Actor{Handle: handle}).Error; err != nil {
		return nil, err
	}
	if actor.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &actor, nil
}

func (s *Server) getRepoByEmail(ctx context.Context, email string) (*models.Repo, error) {
	var repo models.Repo
	if err := s.db.First(ctx, &repo, models.Repo{Email: email}).Error; err != nil {
		return nil, err
	}
	if repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}

func (s *Server) getRepoActorByEmail(ctx context.Context, email string) (*models.RepoActor, error) {
	var repo models.RepoActor
	if err := s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email= ?", nil, email).Scan(&repo).Error; err != nil {
		return nil, err
	}
	if repo.Repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}

// consumeInviteCode atomically claims one use of an invite code. It returns
// false when the code does not exist or has no remaining uses. The conditional
// update guarantees a single-use code can be consumed at most once, even under
// concurrent createAccount requests, and never drives the count below zero.
func (s *Server) consumeInviteCode(ctx context.Context, code string) (bool, error) {
	res := s.db.Exec(ctx, "UPDATE invite_codes SET remaining_use_count = remaining_use_count - 1 WHERE code = ? AND remaining_use_count > 0", nil, code)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (s *Server) getRepoActorByDid(ctx context.Context, did string) (*models.RepoActor, error) {
	var repo models.RepoActor
	if err := s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?", nil, did).Scan(&repo).Error; err != nil {
		return nil, err
	}
	if repo.Repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}
