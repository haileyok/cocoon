package server

import (
	"context"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"gorm.io/gorm/clause"
)

// Reliable notifySpaceDeleted delivery (the reference's
// space-notifications.ts at bluesky-social/atproto ac0c9f15). The authority
// tells every service registered when a space was deleted, retrying network
// failures and transient statuses with backoff until delivery succeeds or the
// service's registration expires. A service that still missed it learns of
// the deletion when its credential renewal answers SpaceDeleted.

const lxmNotifySpaceDeleted = "com.atproto.space.notifySpaceDeleted"

// notifySpaceDeleted tells each recipient, queueing retryable failures.
func (s *Server) notifySpaceDeleted(ctx context.Context, ref space.Ref, recipients []models.SpaceCredentialRecipient) {
	uri := ref.String()
	for _, r := range recipients {
		err := s.sendNotify(ctx, ref.Authority, r.ServiceDid, lxmNotifySpaceDeleted, map[string]any{"space": uri})
		if err == nil {
			continue
		}
		if !isRetryableNotify(err) {
			s.logger.Warn("space deleted notification will not be retried", "space", uri, "service", r.ServiceDid, "err", err)
			continue
		}
		expiresAt, perr := time.Parse(time.RFC3339Nano, r.ExpiresAt)
		if perr != nil {
			s.logger.Error("bad registration expiry", "space", uri, "service", r.ServiceDid, "expiresAt", r.ExpiresAt, "err", perr)
			continue
		}
		row := models.SpaceDeletedNotificationRetry{
			Space: uri, Service: r.ServiceDid, Attempts: 1,
			RetryAt: nextRetryAt(1).UnixMilli(), ExpiresAt: expiresAt.UnixMilli(),
		}
		if err := s.db.Client().WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "space"}, {Name: "service"}},
			DoUpdates: clause.AssignmentColumns([]string{"attempts", "retry_at", "expires_at"}),
		}).Create(&row).Error; err != nil {
			s.logger.Error("could not queue space deleted notification", "space", uri, "service", r.ServiceDid, "err", err)
			continue
		}
		s.logger.Warn("space deleted notification queued for retry", "space", uri, "service", r.ServiceDid, "err", err)
	}
}

// retrySpaceDeletedNotifications resends due deletion notifications.
func (s *Server) retrySpaceDeletedNotifications(ctx context.Context) {
	// Bounded: a row whose reschedule fails would otherwise be reselected
	// forever, holding up the write-notification retries on this worker.
	for pass := 0; pass < 100; pass++ {
		var due []models.SpaceDeletedNotificationRetry
		if err := s.db.Client().WithContext(ctx).Where("retry_at <= ?", time.Now().UnixMilli()).Order("retry_at").Limit(5).Find(&due).Error; err != nil || len(due) == 0 {
			return
		}
		for _, r := range due {
			s.retrySpaceDeletedOne(ctx, r)
		}
	}
}

func (s *Server) retrySpaceDeletedOne(ctx context.Context, r models.SpaceDeletedNotificationRetry) {
	if r.ExpiresAt <= time.Now().UnixMilli() {
		s.clearSpaceDeletedRetry(ctx, r)
		s.logger.Warn("space deleted notification expired with its registration", "space", r.Space, "service", r.Service)
		return
	}
	ref, err := space.ParseRef(r.Space)
	if err != nil {
		s.clearSpaceDeletedRetry(ctx, r)
		return
	}
	authority, err := s.getRepoActorByDid(ctx, ref.Authority)
	if err != nil {
		if notFound(err) {
			// Deleting the authority's account deleted its spaces with it,
			// which services learn from the account event.
			s.clearSpaceDeletedRetry(ctx, r)
		} else {
			s.rescheduleSpaceDeleted(ctx, r)
		}
		return
	}
	if authority.Repo.Deactivated || authority.Repo.TakedownRef != nil {
		s.rescheduleSpaceDeleted(ctx, r)
		return
	}
	sp, err := s.spaceStore(nil, ref.Authority).getSpace(r.Space)
	if err != nil {
		s.rescheduleSpaceDeleted(ctx, r)
		return
	}
	if sp == nil || sp.DeletedAt == nil {
		// Recreated since: telling the service now would purge its new copy.
		s.clearSpaceDeletedRetry(ctx, r)
		return
	}
	if err := s.sendNotify(ctx, ref.Authority, r.Service, lxmNotifySpaceDeleted, map[string]any{"space": r.Space}); err != nil {
		if !isRetryableNotify(err) {
			s.clearSpaceDeletedRetry(ctx, r)
			s.logger.Warn("space deleted notification will not be retried", "space", r.Space, "service", r.Service, "err", err)
			return
		}
		s.rescheduleSpaceDeleted(ctx, r)
		s.logger.Warn("space deleted notification retry failed", "space", r.Space, "service", r.Service, "err", err)
		return
	}
	s.clearSpaceDeletedRetry(ctx, r)
}

// Matching retry_at leaves alone a row a later deletion re-queued.
func (s *Server) rescheduleSpaceDeleted(ctx context.Context, r models.SpaceDeletedNotificationRetry) {
	at := nextRetryAt(r.Attempts + 1).UnixMilli()
	if at > r.ExpiresAt {
		at = r.ExpiresAt
	}
	if err := s.db.Client().WithContext(ctx).Model(&models.SpaceDeletedNotificationRetry{}).
		Where("space = ? AND service = ? AND retry_at = ?", r.Space, r.Service, r.RetryAt).
		Updates(map[string]any{"attempts": r.Attempts + 1, "retry_at": at}).Error; err != nil {
		s.logger.Error("could not reschedule space deleted notification", "space", r.Space, "service", r.Service, "err", err)
	}
}

func (s *Server) clearSpaceDeletedRetry(ctx context.Context, r models.SpaceDeletedNotificationRetry) {
	if err := s.db.Client().WithContext(ctx).Where("space = ? AND service = ? AND retry_at = ?", r.Space, r.Service, r.RetryAt).Delete(&models.SpaceDeletedNotificationRetry{}).Error; err != nil {
		s.logger.Error("could not clear space deleted notification retry", "err", err)
	}
}
