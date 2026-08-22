package server

import (
	"context"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm/clause"
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

	tx := s.db.Begin(ctx)
	if tx.Error != nil {
		logger.Error("error starting transaction", "error", tx.Error)
		return helpers.ServerError(e, nil)
	}

	status := "error"
	defer func() {
		if status == "error" {
			if err := tx.Rollback().Error; err != nil {
				logger.Error("error rolling back after delete failure", "err", err)
			}
		}
	}()

	// Space deletion is part of the account transaction. Snapshot the owned
	// spaces before removing account-authored rows so each authority space can
	// retain its durable tombstone and enqueue only active deletion deliveries.
	var ownedSpaces []models.SimpleSpace
	if err := tx.WithContext(ctx).Where("owner_did = ?", req.Did).Find(&ownedSpaces).Error; err != nil {
		logger.Error("error finding owned spaces", "error", err)
		return helpers.ServerError(e, nil)
	}
	ownedSpaceURIs := make([]string, 0, len(ownedSpaces))
	spaceDB := db.NewDB(tx)
	deletedAt := time.Now().UTC()
	for _, ownedSpace := range ownedSpaces {
		ownedSpaceURIs = append(ownedSpaceURIs, ownedSpace.URI)
		// markSimpleSpaceDeleted predates expiry-aware fanout and reads all
		// registrations. Remove expired registrations first so its equivalent
		// durable deletion semantics cannot queue stale recipients.
		if err := tx.WithContext(ctx).Where("space = ? AND expires_at <= ?", ownedSpace.URI, deletedAt).Delete(&models.SpaceNotifyRegistration{}).Error; err != nil {
			logger.Error("error deleting expired space registrations", "error", err)
			return helpers.ServerError(e, nil)
		}
		if err := tx.WithContext(ctx).Model(&models.SimpleSpace{}).Where("uri = ?", ownedSpace.URI).Updates(map[string]any{
			"deleted":    true,
			"deleted_at": deletedAt,
			"updated_at": deletedAt,
		}).Error; err != nil {
			logger.Error("error marking space deleted", "error", err)
			return helpers.ServerError(e, nil)
		}
		tombstone := models.SpaceTombstone{
			Space:     ownedSpace.URI,
			OwnerDID:  ownedSpace.OwnerDID,
			SourceDID: req.Did,
			DeletedAt: deletedAt,
		}
		if err := tx.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "space"}},
			DoNothing: true,
		}).Create(&tombstone).Error; err != nil {
			logger.Error("error creating space tombstone", "error", err)
			return helpers.ServerError(e, nil)
		}
		if err := markSimpleSpaceDeleted(spaceDB, ctx, ownedSpace.URI, req.Did, deletedAt); err != nil {
			logger.Error("error deleting owned space data", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	// A write delivery is owned by its Author. Deleting these before repo
	// metadata prevents a worker restart from forwarding a write for a deleted
	// account. Deletion deliveries have no Author and are intentionally kept.
	if err := tx.WithContext(ctx).Where("author = ? AND kind = ?", req.Did, SpaceNotifyWriteLXM).Delete(&models.SpaceNotifyDelivery{}).Error; err != nil {
		logger.Error("error deleting authored space write deliveries", "error", err)
		return helpers.ServerError(e, nil)
	}

	// Remove all permissioned data authored by the account, including repos in
	// spaces owned by another authority. Remote-authored repos in this account's
	// spaces are retained by markSimpleSpaceDeleted and are not matched here.
	for _, model := range []any{&models.SpaceRecord{}, &models.SpaceBlobRef{}, &models.SpaceRepoOp{}, &models.SpaceRepo{}, &models.SpaceWriter{}} {
		if err := tx.WithContext(ctx).Where("author = ?", req.Did).Delete(model).Error; err != nil {
			logger.Error("error deleting authored space data", "error", err)
			return helpers.ServerError(e, nil)
		}
	}
	// Membership in another authority's space is account-owned state. Members
	// of this account's deleted spaces were already marked removed by the
	// durable space-deletion helper, preserving that revocation history.
	if err := tx.WithContext(ctx).Where("did = ?", req.Did).Delete(&models.SimpleSpaceMember{}).Error; err != nil {
		logger.Error("error deleting account space memberships", "error", err)
		return helpers.ServerError(e, nil)
	}
	if len(ownedSpaceURIs) > 0 {
		// Registrations are only needed to fan out the deletion event. Keep the
		// outbox rows, then remove the subscriptions themselves.
		if err := tx.WithContext(ctx).Where("space IN ?", ownedSpaceURIs).Delete(&models.SpaceNotifyRegistration{}).Error; err != nil {
			logger.Error("error deleting owned space registrations", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	if err := tx.Exec("DELETE FROM blocks WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting blocks", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM records WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting records", "error", err)
		return helpers.ServerError(e, nil)
	}

	// Public blobs with a positive RefCount or a surviving permissioned
	// SpaceBlobRef are still referenced. Do not remove their underlying object
	// merely because the uploading account is being deleted. Invalid CIDs are
	// skipped conservatively; the normal cleanup path removes their parts too.
	var accountBlobs []models.Blob
	if err := tx.WithContext(ctx).Where("did = ? AND ref_count <= ?", req.Did, 0).Find(&accountBlobs).Error; err != nil {
		logger.Error("error finding deletable blobs", "error", err)
		return helpers.ServerError(e, nil)
	}
	for _, blob := range accountBlobs {
		blobCID, err := cid.Cast(blob.Cid)
		if err != nil {
			logger.Warn("skipping blob with invalid CID during account deletion", "did", req.Did, "blob_id", blob.ID, "error", err)
			continue
		}
		var survivingRefs int64
		if err := tx.WithContext(ctx).Model(&models.SpaceBlobRef{}).Where("cid = ?", blobCID.String()).Count(&survivingRefs).Error; err != nil {
			logger.Error("error checking permissioned blob references", "error", err)
			return helpers.ServerError(e, nil)
		}
		if survivingRefs > 0 {
			continue
		}
		if err := tx.Exec("DELETE FROM blob_parts WHERE blob_id = ?", blob.ID).Error; err != nil {
			logger.Error("error deleting blob parts", "error", err)
			return helpers.ServerError(e, nil)
		}
		if err := tx.Exec("DELETE FROM blobs WHERE id = ?", blob.ID).Error; err != nil {
			logger.Error("error deleting blob", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	if err := tx.Exec("DELETE FROM tokens WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting tokens", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM refresh_tokens WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting refresh tokens", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM reserved_keys WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting reserved keys", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM invite_codes WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting invite codes", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM actors WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting actor", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Exec("DELETE FROM repos WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := tx.Commit().Error; err != nil {
		logger.Error("error committing transaction", "error", err)
		return helpers.ServerError(e, nil)
	}
	status = "ok"

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
