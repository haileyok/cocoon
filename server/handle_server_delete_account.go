package server

import (
	"context"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type ComAtprotoServerDeleteAccountRequest struct {
	Did      string `json:"did" validate:"required"`
	Password string `json:"password" validate:"required"`
	Token    string `json:"token" validate:"required"`
}

func (s *Server) handleServerDeleteAccount(e echo.Context) error {
	var req ComAtprotoServerDeleteAccountRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(&req); err != nil {
		s.logger.Error("error validating", "error", err)
		return helpers.ServerError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(req.Did)
	if err != nil {
		s.logger.Error("error getting repo", "error", err)
		return echo.NewHTTPError(400, "account not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(urepo.Repo.Password), []byte(req.Password)); err != nil {
		s.logger.Error("password mismatch", "error", err)
		return echo.NewHTTPError(401, "Invalid did or password")
	}

	if urepo.Repo.AccountDeleteCode == nil || urepo.Repo.AccountDeleteCodeExpiresAt == nil {
		s.logger.Error("no deletion token found for account")
		return echo.NewHTTPError(400, map[string]interface{}{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
	}

	if *urepo.Repo.AccountDeleteCode != req.Token {
		s.logger.Error("deletion token mismatch")
		return echo.NewHTTPError(400, map[string]interface{}{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
	}

	if time.Now().UTC().After(*urepo.Repo.AccountDeleteCodeExpiresAt) {
		s.logger.Error("deletion token expired")
		return echo.NewHTTPError(400, map[string]interface{}{
			"error":   "ExpiredToken",
			"message": "Token is expired",
		})
	}

	if err := s.db.Exec("DELETE FROM blocks WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting blocks", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM records WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting records", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM blobs WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting blobs", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM tokens WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting tokens", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM refresh_tokens WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting refresh tokens", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM reserved_keys WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting reserved keys", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM invite_codes WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting invite codes", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM actors WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting actor", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec("DELETE FROM repos WHERE did = ?", nil, req.Did).Error; err != nil {
		s.logger.Error("error deleting repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: false,
			Did:    req.Did,
			Status: to.StringPtr("deleted"),
			Seq:    time.Now().UnixMicro(),
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	return e.NoContent(200)
}
