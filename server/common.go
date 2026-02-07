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
