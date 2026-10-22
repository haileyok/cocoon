package server

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
)

// Accounts created before #atproto_kem keys existed (the October 22, 2026
// Spaces alpha) have none, so syncers can't establish a shared secret for
// their space repos and space-credential reads of them fail. This gives each
// one a key, following the reference's kem-key-backfill.ts at
// bluesky-social/atproto ac0c9f15: when this PDS holds a rotation key for the
// account and is its current PDS, it publishes the key to PLC and emits an
// #identity event. Otherwise (did:web accounts, accounts that removed this
// PDS's rotation key or migrated away) it stores a key the account must
// publish itself, which getRecommendedDidCredentials then includes.
//
// An account's key is stored only after it is published, so a stored key
// marks the account done and a run cut short resumes where it left off.
// Failed accounts are retried until every account has a key. Like the space
// notification worker, this assumes one Cocoon process per database.

const kemBackfillRetryEvery = time.Minute

func (s *Server) kemKeyBackfillRoutine(ctx context.Context) {
	for {
		failed, err := s.backfillKemKeys(ctx)
		if err == nil && failed == 0 {
			s.logger.Info("kem key backfill complete")
			return
		}
		s.logger.Warn("kem key backfill will retry", "failed", failed, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(kemBackfillRetryEvery):
		}
	}
}

// backfillKemKeys gives every account without a KEM key one, returning how
// many failed.
func (s *Server) backfillKemKeys(ctx context.Context) (int, error) {
	failed := 0
	cursor := ""
	for ctx.Err() == nil {
		var dids []string
		if err := s.db.Client().WithContext(ctx).Model(&models.Repo{}).
			Where("kem_key IS NULL AND did > ?", cursor).Order("did").Limit(100).
			Pluck("did", &dids).Error; err != nil {
			return failed, err
		}
		if len(dids) == 0 {
			break
		}
		for _, did := range dids {
			if ctx.Err() != nil {
				break
			}
			if err := s.backfillKemKey(ctx, did); err != nil {
				failed++
				s.logger.Error("failed to backfill kem key", "did", did, "err", err)
			}
		}
		cursor = dids[len(dids)-1]
	}
	return failed, ctx.Err()
}

func (s *Server) backfillKemKey(ctx context.Context, did string) error {
	kemKey, kemDidKey, err := newKemKey()
	if err != nil {
		return err
	}
	published, err := s.publishKemKey(ctx, did, kemDidKey)
	if err != nil {
		return err
	}
	if !published {
		s.logger.Warn("cannot publish kem key, account must update its did doc", "did", did)
	}
	if err := s.db.Client().WithContext(ctx).Model(&models.Repo{}).
		Where("did = ? AND kem_key IS NULL", did).
		Update("kem_key", kemKey.Bytes()).Error; err != nil {
		return err
	}
	if published {
		if err := s.passport.BustDoc(ctx, did); err != nil {
			s.logger.Warn("error busting did doc", "did", did, "err", err)
		}
		s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
			RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
				Did:  did,
				Seq:  time.Now().UnixMicro(), // TODO: no
				Time: time.Now().Format(util.ISO8601),
			},
		})
	}
	return nil
}

// publishKemKey adds the key to the account's PLC document, reporting false
// when this PDS can't: not a did:plc, a tombstoned or legacy document, no
// rotation key of this PDS, or another PDS.
func (s *Server) publishKemKey(ctx context.Context, did, kemDidKey string) (bool, error) {
	if !strings.HasPrefix(did, "did:plc:") || s.plcClient == nil {
		return false, nil
	}
	rotationKey, err := s.plcClient.RotationKeyDID()
	if err != nil {
		return false, err
	}
	lastOp, lastCid, err := s.plcClient.GetLastOp(ctx, did)
	if err != nil {
		return false, err
	}
	// A tombstone or a legacy create op carries no rotationKeys or services.
	if !slices.Contains(lastOp.RotationKeys, rotationKey) {
		return false, nil
	}
	if lastOp.Services["atproto_pds"].Endpoint != s.plcClient.PdsEndpoint() {
		return false, nil
	}
	methods := make(map[string]string, len(lastOp.VerificationMethods)+1)
	for k, v := range lastOp.VerificationMethods {
		methods[k] = v
	}
	methods["atproto_kem"] = kemDidKey
	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: methods,
		RotationKeys:        lastOp.RotationKeys,
		AlsoKnownAs:         lastOp.AlsoKnownAs,
		Services:            lastOp.Services,
		Prev:                &lastCid,
	}
	// SignOp signs with the PDS rotation key; its key argument is unused.
	if err := s.plcClient.SignOp((*atcrypto.PrivateKeyK256)(nil), &op); err != nil {
		return false, err
	}
	if err := s.plcClient.SendOperation(ctx, did, &op); err != nil {
		return false, err
	}
	return true, nil
}
