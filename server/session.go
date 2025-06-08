package server

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/haileyok/cocoon/models"
)

type Session struct {
	AccessToken  string
	RefreshToken string
}

func (s *Server) createSession(repo *models.Repo) (*Session, error) {
	now := time.Now()
	accexp := now.Add(3 * time.Hour)
	refexp := now.Add(7 * 24 * time.Hour)
	jti := uuid.NewString()

	accessClaims := jwt.MapClaims{
		"scope": "com.atproto.access",
		"aud":   s.config.Did,
		"sub":   repo.Did,
		"iat":   now.UTC().Unix(),
		"exp":   accexp.UTC().Unix(),
		"jti":   jti,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	accessString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		return nil, err
	}

	refreshClaims := jwt.MapClaims{
		"scope": "com.atproto.refresh",
		"aud":   s.config.Did,
		"sub":   repo.Did,
		"iat":   now.UTC().Unix(),
		"exp":   refexp.UTC().Unix(),
		"jti":   jti,
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaims)
	refreshString, err := refreshToken.SignedString(s.privateKey)
	if err != nil {
		return nil, err
	}

	if err := s.db.Create(&models.Token{
		Token:        accessString,
		Did:          repo.Did,
		RefreshToken: refreshString,
		CreatedAt:    now,
		ExpiresAt:    accexp,
	}, nil).Error; err != nil {
		return nil, err
	}

	if err := s.db.Create(&models.RefreshToken{
		Token:     refreshString,
		Did:       repo.Did,
		CreatedAt: now,
		ExpiresAt: refexp,
	}, nil).Error; err != nil {
		return nil, err
	}

	return &Session{
		AccessToken:  accessString,
		RefreshToken: refreshString,
	}, nil
}
