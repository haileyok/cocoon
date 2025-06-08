package server

import (
	"github.com/haileyok/cocoon/models"
)

func (s *Server) getActorByHandle(handle string) (*models.Actor, error) {
	var actor models.Actor
	if err := s.db.First(&actor, models.Actor{Handle: handle}).Error; err != nil {
		return nil, err
	}
	return &actor, nil
}

func (s *Server) getRepoByEmail(email string) (*models.Repo, error) {
	var repo models.Repo
	if err := s.db.First(&repo, models.Repo{Email: email}).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}

func (s *Server) getRepoActorByEmail(email string) (*models.RepoActor, error) {
	var repo models.RepoActor
	if err := s.db.Raw("SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email= ?", nil, email).Scan(&repo).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}

func (s *Server) getRepoActorByDid(did string) (*models.RepoActor, error) {
	var repo models.RepoActor
	if err := s.db.Raw("SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?", nil, did).Scan(&repo).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}
