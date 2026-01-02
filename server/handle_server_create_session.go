package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ComAtprotoServerCreateSessionRequest struct {
	Identifier      string  `json:"identifier" validate:"required"`
	Password        string  `json:"password" validate:"required"`
	AuthFactorToken *string `json:"authFactorToken,omitempty"`
}

type ComAtprotoServerCreateSessionResponse struct {
	AccessJwt       string  `json:"accessJwt"`
	RefreshJwt      string  `json:"refreshJwt"`
	Handle          string  `json:"handle"`
	Did             string  `json:"did"`
	Email           string  `json:"email"`
	EmailConfirmed  bool    `json:"emailConfirmed"`
	EmailAuthFactor bool    `json:"emailAuthFactor"`
	Active          bool    `json:"active"`
	Status          *string `json:"status,omitempty"`
}

func (s *Server) handleCreateSession(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerCreateSession")

	var req ComAtprotoServerCreateSessionRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding request", "endpoint", "com.atproto.server.serverCreateSession", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		var verr ValidationError
		if errors.As(err, &verr) {
			if verr.Field == "Identifier" {
				return helpers.InputError(e, to.StringPtr("InvalidRequest"))
			}

			if verr.Field == "Password" {
				return helpers.InputError(e, to.StringPtr("InvalidRequest"))
			}
		}
	}

	req.Identifier = strings.ToLower(req.Identifier)
	var idtype string
	if _, err := syntax.ParseDID(req.Identifier); err == nil {
		idtype = "did"
	} else if _, err := syntax.ParseHandle(req.Identifier); err == nil {
		idtype = "handle"
	} else {
		idtype = "email"
	}

	var repo models.RepoActor
	var err error
	switch idtype {
	case "did":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?", nil, req.Identifier).Scan(&repo).Error
	case "handle":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM actors a LEFT JOIN repos r ON a.did = r.did WHERE a.handle = ?", nil, req.Identifier).Scan(&repo).Error
	case "email":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email = ?", nil, req.Identifier).Scan(&repo).Error
	}

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return helpers.InputError(e, to.StringPtr("InvalidRequest"))
		}

		logger.Error("erorr looking up repo", "endpoint", "com.atproto.server.createSession", "error", err)
		return helpers.ServerError(e, nil)
	}

	// if repo requires auth factor token and one hasn't been provided, return error prompting for one
	if repo.EmailAuthFactor && (req.AuthFactorToken == nil || *req.AuthFactorToken == "") {
		err = s.createAndSendAuthCode(ctx, repo)
		if err != nil {
			s.logger.Error("sending auth code", "error", err)
			return helpers.ServerError(e, nil)
		}

		return helpers.InputError(e, to.StringPtr("AuthFactorTokenRequired"))
	}

	// if auth factor is required, now check that the one provided is valid
	if repo.EmailAuthFactor {
		if repo.AuthCode == nil || repo.AuthCodeExpiresAt == nil {
			err = s.createAndSendAuthCode(ctx, repo)
			if err != nil {
				s.logger.Error("sending auth code", "error", err)
				return helpers.ServerError(e, nil)
			}

			return helpers.InputError(e, to.StringPtr("AuthFactorTokenRequired"))
		}

		if *repo.AuthCode != *req.AuthFactorToken {
			return helpers.InvalidTokenError(e)
		}

		if time.Now().UTC().After(*repo.AuthCodeExpiresAt) {
			return helpers.ExpiredTokenError(e)
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			logger.Error("erorr comparing hash and password", "error", err)
		}
		return helpers.InputError(e, to.StringPtr("InvalidRequest"))
	}

	sess, err := s.createSession(ctx, &repo.Repo)
	if err != nil {
		logger.Error("error creating session", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, ComAtprotoServerCreateSessionResponse{
		AccessJwt:       sess.AccessToken,
		RefreshJwt:      sess.RefreshToken,
		Handle:          repo.Handle,
		Did:             repo.Repo.Did,
		Email:           repo.Email,
		EmailConfirmed:  repo.EmailConfirmedAt != nil,
		EmailAuthFactor: repo.EmailAuthFactor,
		Active:          repo.Active(),
		Status:          repo.Status(),
	})
}

func (s *Server) createAndSendAuthCode(ctx context.Context, repo models.RepoActor) error {
	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	if err := s.db.Exec(ctx, "UPDATE repos SET auth_code = ?, auth_code_expires_at = ? WHERE did = ?", nil, code, eat, repo.Repo.Did).Error; err != nil {
		return fmt.Errorf("updating repo: %w", err)
	}

	if err := s.sendAuthCode(repo.Email, repo.Handle, code); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	return nil
}
