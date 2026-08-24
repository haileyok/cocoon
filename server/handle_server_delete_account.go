package server

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ComAtprotoServerDeleteAccountRequest struct {
	Did      string `json:"did" validate:"required"`
	Password string `json:"password" validate:"required"`
	Token    string `json:"token" validate:"required"`
}

func enqueueBlobDeletion(ctx context.Context, tx *db.DB, blob models.Blob, config *S3Config, now time.Time) error {
	bucket, objectKey, err := blobS3Target(blob, config)
	if err != nil {
		return err
	}
	idempotencyKey := blobDeletionIdempotencyKey(bucket, objectKey)
	var existing models.BlobDeletion
	findErr := tx.Client().WithContext(ctx).Where("idempotency_key = ?", idempotencyKey).First(&existing).Error
	if findErr == nil {
		// Repair rows produced by older versions that failed to snapshot the
		// bucket, while preserving any already-snapshotted immutable target.
		updates := map[string]any{"updated_at": now}
		if existing.Bucket == "" {
			updates["bucket"] = bucket
		}
		if existing.ObjectKey == "" {
			updates["object_key"] = objectKey
		}
		// Rows written by versions that terminally failed at MaxAttempts must
		// become eligible again when the same immutable generation is observed.
		if existing.Status == BlobDeletionFailed {
			updates["status"] = BlobDeletionPending
			updates["attempt_count"] = 0
			updates["next_attempt_at"] = nil
			updates["last_error"] = ""
		}
		return tx.Client().WithContext(ctx).Model(&models.BlobDeletion{}).Where("id = ?", existing.ID).Updates(updates).Error
	}
	if !errors.Is(findErr, gorm.ErrRecordNotFound) {
		return findErr
	}
	deletion := &models.BlobDeletion{
		IdempotencyKey: idempotencyKey,
		Bucket:         bucket,
		ObjectKey:      objectKey,
		Status:         BlobDeletionPending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return tx.Create(ctx, deletion, nil).Error
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
		if err := markSimpleSpaceDeleted(spaceDB, ctx, ownedSpace.URI, req.Did, deletedAt, s.s3Config); err != nil {
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

	// Blob storage is author-namespaced, so all blobs uploaded by the account
	// are owned by it regardless of public ref_count or permissioned references
	// using the same CID. Remove their parts before the blob rows.
	var accountBlobs []models.Blob
	if err := tx.WithContext(ctx).Where("did = ?", req.Did).Find(&accountBlobs).Error; err != nil {
		logger.Error("error finding account blobs", "error", err)
		return helpers.ServerError(e, nil)
	}
	for _, blob := range accountBlobs {
		if blob.Storage == "s3" {
			// Resolve and snapshot the exact generation before deleting metadata.
			// A missing bucket is a configuration/data error, so returning here
			// rolls back the entire account deletion rather than losing the blob.
			if err := enqueueBlobDeletion(ctx, db.NewDB(tx), blob, s.s3Config, deletedAt); err != nil {
				logger.Error("error enqueueing S3 blob deletion", "error", err)
				return helpers.ServerError(e, nil)
			}
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
