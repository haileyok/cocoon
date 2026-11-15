package server

import (
	"sort"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm/clause"
)

// The writer set, notify registrations and bulk repo operations of the space
// store, following the reference's actor-store/space/transactor.ts at
// bluesky-social/atproto d4def6e9.

type writerSequence struct {
	spaceRev     string
	prevSpaceRev string
}

// lockSpace serializes the space's sequence, and avoids SQLite read-to-write
// upgrades, by writing before reading.
func (st *spaceStore) lockSpace(uri string) error {
	return st.db.Model(&models.Space{}).Where("did = ? AND uri = ?", st.did, uri).UpdateColumn("uri", uri).Error
}

// getSpaceRev is the space's current revision: the latest in its writer set,
// removals included. Empty before the space's first update. Only kept for the
// spaces this account is the authority for.
func (st *spaceStore) getSpaceRev(uri string) (string, error) {
	var rows []models.SpaceWriter
	if err := st.db.Where("did = ? AND space = ?", st.did, uri).Order("space_rev desc").Limit(1).Find(&rows).Error; err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].SpaceRev, nil
}

func (st *spaceStore) nextSpaceRev(uri string) (*writerSequence, error) {
	prev, err := st.getSpaceRev(uri)
	if err != nil {
		return nil, err
	}
	return &writerSequence{spaceRev: nextTID(prev), prevSpaceRev: prev}, nil
}

func (st *spaceStore) getWriter(uri, writer string) (*models.SpaceWriter, error) {
	var cur models.SpaceWriter
	err := st.db.Where("did = ? AND space = ? AND writer_did = ?", st.did, uri, writer).Take(&cur).Error
	if notFound(err) {
		return nil, nil
	}
	return &cur, err
}

// recordWriter records a newer repo state for a writer and advances the
// space's sequence. Nil when the state is not newer than the last. A newer
// write from a removed writer adds it back to the writer set.
func (st *spaceStore) recordWriter(uri, writer, repoRev string, data []byte) (*writerSequence, error) {
	if err := st.lockSpace(uri); err != nil {
		return nil, err
	}
	sp, err := st.getSpace(uri)
	if err != nil {
		return nil, err
	}
	if sp == nil || sp.DeletedAt != nil {
		return nil, errSpaceNotFound()
	}
	cur, err := st.getWriter(uri, writer)
	if err != nil {
		return nil, err
	}
	if cur != nil && cur.RepoRev >= repoRev {
		return nil, nil
	}
	seq, err := st.nextSpaceRev(uri)
	if err != nil {
		return nil, err
	}
	row := models.SpaceWriter{Did: st.did, Space: uri, WriterDid: writer, RepoRev: repoRev, SpaceRev: seq.spaceRev, Data: data}
	if err := st.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&row).Error; err != nil {
		return nil, err
	}
	// UpdateAll doesn't clear a column set to its zero value.
	if err := st.db.Model(&models.SpaceWriter{}).Where("did = ? AND space = ? AND writer_did = ?", st.did, uri, writer).Update("removed_at", nil).Error; err != nil {
		return nil, err
	}
	return seq, nil
}

// removeWriter removes a repo from the writer set and advances the space
// sequence. The row stays behind, marked removed, so that listWriters can
// report the removal. Nil if the repo is not in the writer set.
func (st *spaceStore) removeWriter(uri, writer string) (*writerSequence, error) {
	if err := st.lockSpace(uri); err != nil {
		return nil, err
	}
	cur, err := st.getWriter(uri, writer)
	if err != nil || cur == nil || cur.RemovedAt != nil {
		return nil, err
	}
	seq, err := st.nextSpaceRev(uri)
	if err != nil {
		return nil, err
	}
	err = st.db.Model(&models.SpaceWriter{}).Where("did = ? AND space = ? AND writer_did = ?", st.did, uri, writer).
		Updates(map[string]any{"space_rev": seq.spaceRev, "removed_at": nowISO()}).Error
	return seq, err
}

// importWriters replaces a space's writer set with the one exported by its
// previous host.
func (st *spaceStore) importWriters(uri string, writers []space.SpaceMetaWriter) error {
	if err := st.db.Where("did = ? AND space = ?", st.did, uri).Delete(&models.SpaceWriter{}).Error; err != nil {
		return err
	}
	for _, w := range writers {
		row := models.SpaceWriter{Did: st.did, Space: uri, WriterDid: w.Did, RepoRev: w.RepoRev, SpaceRev: w.SpaceRev, Data: w.Data}
		if err := st.db.Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

// listWriters pages the writer set in sequence order. It includes removed
// writers, so that removals reach syncers. A limit of 0 lists every writer.
func (st *spaceStore) listWriters(uri string, limit int, cursor string) ([]models.SpaceWriter, error) {
	q := st.db.Where("did = ? AND space = ?", st.did, uri).Order("space_rev asc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if cursor != "" {
		q = q.Where("space_rev > ?", cursor)
	}
	var rows []models.SpaceWriter
	qerr := q.Find(&rows).Error
	return rows, qerr
}

// clearRecords deletes every record outside the keep collections and clears
// the oplog, leaving the repo at a new rev. Nil if there was nothing to
// delete.
func (st *spaceStore) clearRecords(uri string, keep []string) (*spaceCommit, error) {
	state, err := st.getRepoState(uri)
	if err != nil || state == nil {
		return nil, err
	}
	blobs, err := st.dropSpaceBlobRefs(uri, keep)
	if err != nil {
		return nil, err
	}
	q := st.db.Where("did = ? AND space = ?", st.did, uri)
	if len(keep) > 0 {
		q = q.Where("collection NOT IN ?", keep)
	}
	res := q.Delete(&models.SpaceRecord{})
	if res.Error != nil || res.RowsAffected == 0 {
		return nil, res.Error
	}
	if err := st.db.Where("did = ? AND space = ?", st.did, uri).Delete(&models.SpaceRecordOplog{}).Error; err != nil {
		return nil, err
	}
	var kept []models.SpaceRecord
	if err := st.db.Select("collection", "rkey", "cid").Where("did = ? AND space = ?", st.did, uri).Find(&kept).Error; err != nil {
		return nil, err
	}
	repo := space.NewRepoCommit()
	for _, r := range kept {
		c, err := cid.Decode(r.Cid)
		if err != nil {
			return nil, err
		}
		repo.Add(r.Collection, r.Rkey, c)
	}
	prevRev := ""
	if state.Rev != nil {
		prevRev = *state.Rev
	}
	rev := nextTID(prevRev)
	setHash := repo.SetHash.State()
	if err := st.db.Model(&models.SpaceRepo{}).Where("did = ? AND space = ?", st.did, uri).Updates(map[string]any{"set_hash": setHash, "rev": rev}).Error; err != nil {
		return nil, err
	}
	if err := st.gcBlobs(blobs); err != nil {
		return nil, err
	}
	return &spaceCommit{Rev: rev, SetHash: setHash}, nil
}

// importRepo imports the account's repo from its previous host, replacing
// whatever this host held for it. Like a migrated public repo, it takes a new
// rev here and none of its history. Its records are taken as they are,
// including those the PDS publishes from a space's configuration. Its blobs
// are uploaded afterwards, so they're associated without being checked.
func (st *spaceStore) importRepo(ref space.Ref, records []space.VerifiedRecord) error {
	if err := st.ensureRepo(ref); err != nil {
		return err
	}
	uri := ref.String()
	oldBlobs, err := st.dropSpaceBlobRefs(uri, nil)
	if err != nil {
		return err
	}
	for _, m := range []any{&models.SpaceRecord{}, &models.SpaceRecordOplog{}} {
		if err := st.db.Where("did = ? AND space = ?", st.did, uri).Delete(m).Error; err != nil {
			return err
		}
	}
	state, err := st.getRepoState(uri)
	if err != nil {
		return err
	}
	prevRev := ""
	if state != nil && state.Rev != nil {
		prevRev = *state.Rev
	}
	rev := nextTID(prevRev)
	indexedAt := nowISO()
	repo := space.NewRepoCommit()
	for _, r := range records {
		// Stored re-encoded, as any other write is. A record that wasn't
		// canonical DRISL in the archive would no longer match its cid, nor
		// the commit data.
		b, err := atdata.MarshalCBOR(r.Record)
		if err != nil || !space.CidForCBOR(b).Equals(r.Cid) {
			return errInvalid("InvalidRepoFile", "Invalid STAR: record is not canonical DRISL at %s/%s", r.Collection, r.Rkey)
		}
		recURI := ref.RecordURI(st.did, r.Collection, r.Rkey)
		row := models.SpaceRecord{
			Uri: recURI, Did: st.did, Space: uri, Collection: r.Collection, Rkey: r.Rkey,
			Cid: r.Cid.String(), Value: b, RepoRev: rev, IndexedAt: indexedAt,
		}
		if err := st.db.Create(&row).Error; err != nil {
			return err
		}
		var blobs []cid.Cid
		for _, blob := range atdata.ExtractBlobs(r.Record) {
			blobs = append(blobs, blob.Ref.CID())
		}
		if err := st.setRecordBlobs(recURI, blobs); err != nil {
			return err
		}
		repo.Add(r.Collection, r.Rkey, r.Cid)
	}
	if err := st.db.Model(&models.SpaceRepo{}).Where("did = ? AND space = ?", st.did, uri).Updates(map[string]any{"set_hash": repo.SetHash.State(), "rev": rev}).Error; err != nil {
		return err
	}
	return st.gcBlobs(oldBlobs)
}

// Notify registrations. Re-registering the same endpoint and token renews the
// registration.

// putNotifyRegistration checks the space in the same transaction, so a
// registration can't survive a concurrent deletion of the space.
func (st *spaceStore) putNotifyRegistration(uri, endpoint, token, expiresAt string) error {
	if err := st.lockSpace(uri); err != nil {
		return err
	}
	sp, err := st.getSpace(uri)
	if err != nil {
		return err
	}
	if sp == nil {
		return errSpaceNotFound()
	}
	if sp.DeletedAt != nil {
		return errInvalid("SpaceDeleted", "Space has been deleted")
	}
	row := models.SpaceNotifyRegistration{Did: st.did, Space: uri, Endpoint: endpoint, Token: token, ExpiresAt: expiresAt}
	return st.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "did"}, {Name: "space"}, {Name: "endpoint"}, {Name: "token"}},
		DoUpdates: clause.Assignments(map[string]any{"expires_at": expiresAt, "expiry_notified": false}),
	}).Create(&row).Error
}

// getNotifyRegistrations includes lapsed registrations.
func (st *spaceStore) getNotifyRegistrations(uri string) ([]models.SpaceNotifyRegistration, error) {
	var rows []models.SpaceNotifyRegistration
	qerr := st.db.Where("did = ? AND space = ?", st.did, uri).Find(&rows).Error
	return rows, qerr
}

func (st *spaceStore) getNotifyRegistration(uri, endpoint, token string) (*models.SpaceNotifyRegistration, error) {
	var row models.SpaceNotifyRegistration
	err := st.db.Where("did = ? AND space = ? AND endpoint = ? AND token = ?", st.did, uri, endpoint, token).Take(&row).Error
	if notFound(err) {
		return nil, nil
	}
	return &row, err
}

// claimLapsedNotifyRegistrations marks the lapsed registrations that have yet
// to be sent an expiry notice, and returns them. Each lapse is claimed once,
// so a syncer is sent a single expiry notice however many updates follow.
func (st *spaceStore) claimLapsedNotifyRegistrations(uri, now string) ([]models.SpaceNotifyRegistration, error) {
	var lapsed []models.SpaceNotifyRegistration
	if err := st.db.Where("did = ? AND space = ? AND expires_at <= ? AND expiry_notified = ?", st.did, uri, now, false).Find(&lapsed).Error; err != nil {
		return nil, err
	}
	var claimed []models.SpaceNotifyRegistration
	for _, r := range lapsed {
		res := st.db.Model(&models.SpaceNotifyRegistration{}).
			Where("did = ? AND space = ? AND endpoint = ? AND token = ? AND expiry_notified = ?", st.did, uri, r.Endpoint, r.Token, false).
			Update("expiry_notified", true)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 1 {
			claimed = append(claimed, r)
		}
	}
	sort.Slice(claimed, func(i, j int) bool {
		return claimed[i].Endpoint+claimed[i].Token < claimed[j].Endpoint+claimed[j].Token
	})
	return claimed, nil
}

func (st *spaceStore) removeNotifyRegistration(uri, endpoint, token string) error {
	return st.db.Where("did = ? AND space = ? AND endpoint = ? AND token = ?", st.did, uri, endpoint, token).Delete(&models.SpaceNotifyRegistration{}).Error
}

// removeLapsedNotifyRegistration leaves alone a registration renewed since
// lapsedBy.
func (st *spaceStore) removeLapsedNotifyRegistration(uri, endpoint, token string, lapsedBy time.Time) error {
	return st.db.Where("did = ? AND space = ? AND endpoint = ? AND token = ? AND expires_at <= ?", st.did, uri, endpoint, token, isoTime(lapsedBy)).Delete(&models.SpaceNotifyRegistration{}).Error
}
