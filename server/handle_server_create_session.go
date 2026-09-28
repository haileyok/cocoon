package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			logger.Error("erorr comparing hash and password", "error", err)
		}
		return helpers.InputError(e, to.StringPtr("InvalidRequest"))
	}

	// The Bluesky app shows its "check your email" code box for any
	// AuthFactorTokenRequired, so authenticator codes, YubiKey OTPs, and
	// backup codes all arrive through authFactorToken.
	token := ""
	if req.AuthFactorToken != nil {
		token = *req.AuthFactorToken
	}
	res, err := s.checkSecondFactor(ctx, &repo, token)
	if errors.Is(err, errYubiCloudUnavailable) {
		return e.JSON(http.StatusServiceUnavailable, map[string]string{
			"error":   "YubiKeyCheckUnavailable",
			"message": "Couldn't check your YubiKey with Yubico right now. Try again shortly, or use another sign-in method.",
		})
	}
	if err != nil {
		logger.Error("checking second factor", "error", err)
		return helpers.ServerError(e, nil)
	}
	if res != secondFactorOK {
		return secondFactorXrpcError(e, res)
	}

	hasSecondFactor, err := s.hasSecondFactor(ctx, &repo.Repo)
	if err != nil {
		logger.Error("checking second factor", "error", err)
		return helpers.ServerError(e, nil)
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
		EmailAuthFactor: hasSecondFactor,
		Active:          repo.Active(),
		Status:          repo.Status(),
	})
}

func (s *Server) clearTwoFactorCode(ctx context.Context, did string) error {
	return s.db.Exec(ctx, "UPDATE repos SET two_factor_code = NULL, two_factor_code_expires_at = NULL WHERE did = ?", nil, did).Error
}

func (s *Server) createAndSendTwoFactorCode(ctx context.Context, repo models.RepoActor) error {
	// TODO: when implementing a new type of 2FA there should be some logic in here to send the
	// right type of code

	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	if err := s.db.Exec(ctx, "UPDATE repos SET two_factor_code = ?, two_factor_code_expires_at = ? WHERE did = ?", nil, code, eat, repo.Repo.Did).Error; err != nil {
		return fmt.Errorf("updating repo: %w", err)
	}

	if err := s.sendTwoFactorCode(repo.Email, repo.Handle, code); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	return nil
}
