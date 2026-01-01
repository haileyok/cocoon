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
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerDeleteAccount")

	var req ComAtprotoServerDeleteAccountRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(&req); err != nil {
		logger.Error("error validating", "error", err)
		return helpers.ServerError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(ctx, req.Did)
	if err != nil {
		logger.Error("error getting repo", "error", err)
		return echo.NewHTTPError(400, "account not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(urepo.Repo.Password), []byte(req.Password)); err != nil {
		logger.Error("password mismatch", "error", err)
		return echo.NewHTTPError(401, "Invalid did or password")
	}

	if urepo.Repo.AccountDeleteCode == nil || urepo.Repo.AccountDeleteCodeExpiresAt == nil {
		logger.Error("no deletion token found for account")
		return echo.NewHTTPError(400, map[string]interface{}{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
	}

	if *urepo.Repo.AccountDeleteCode != req.Token {
		logger.Error("deletion token mismatch")
		return echo.NewHTTPError(400, map[string]interface{}{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
	}

	if time.Now().UTC().After(*urepo.Repo.AccountDeleteCodeExpiresAt) {
		logger.Error("deletion token expired")
		return echo.NewHTTPError(400, map[string]interface{}{
			"error":   "ExpiredToken",
			"message": "Token is expired",
		})
	}

	tx := s.db.BeginDangerously(ctx)
	if tx.Error != nil {
		logger.Error("error starting transaction", "error", tx.Error)
		return helpers.ServerError(e, nil)
	}

	status := "error"
	func() {
		if status == "error" {
			if err := tx.Rollback().Error; err != nil {
				logger.Error("error rolling back after delete failure", "err", err)
			}
		}
	}()

	if err := tx.Exec("DELETE FROM blocks WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting blocks", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM records WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting records", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM blobs WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting blobs", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM tokens WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting tokens", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM refresh_tokens WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting refresh tokens", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM reserved_keys WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting reserved keys", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM invite_codes WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting invite codes", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM actors WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting actor", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM repos WHERE did = ?", nil, req.Did).Error; err != nil {
		logger.Error("error deleting repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	status = "ok"

	if err := tx.Commit().Error; err != nil {
		logger.Error("error committing transaction", "error", err)
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
