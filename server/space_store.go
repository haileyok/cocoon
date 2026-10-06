package server

import (
	"errors"

	"github.com/haileyok/cocoon/internal/space"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// The space store follows the reference's SpaceReader and SpaceTransactor
// (packages/pds/src/actor-store/space), scoped by the owning account's DID.

type spaceStore struct {
	db  *gorm.DB
	did string
}

func (s *Server) spaceStore(tx *gorm.DB, did string) *spaceStore {
	if tx == nil {
		tx = s.db.Client()
	}
	return &spaceStore{db: tx, did: did}
}

func notFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }

func (st *spaceStore) getSpace(uri string) (*models.Space, error) {
	var row models.Space
	err := st.db.Where("did = ? AND uri = ?", st.did, uri).Take(&row).Error
	if notFound(err) {
		return nil, nil
	}
	return &row, err
}

func (st *spaceStore) getSpaceConfig(uri string) (*models.SimplespaceConfig, error) {
	var row models.SimplespaceConfig
	err := st.db.Where("did = ? AND uri = ?", st.did, uri).Take(&row).Error
	if notFound(err) {
		return nil, nil
	}
	return &row, err
}

// getActiveSpaceConfig returns the config of a live space, or SpaceNotFound.
func (st *spaceStore) getActiveSpaceConfig(uri string) (*models.SimplespaceConfig, error) {
	sp, err := st.getSpace(uri)
	if err != nil {
		return nil, err
	}
	cfg, err := st.getSpaceConfig(uri)
	if err != nil {
		return nil, err
	}
	if sp == nil || sp.DeletedAt != nil || cfg == nil {
		return nil, errSpaceNotFound()
	}
	return cfg, nil
}

func (st *spaceStore) ensureSpace(ref space.Ref) error {
	uri := ref.String()
	row := models.Space{Did: st.did, Uri: uri, Authority: ref.Authority, Type: ref.Type, CreatedAt: nowISO()}
	if err := st.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "did"}, {Name: "uri"}},
		DoUpdates: clause.Assignments(map[string]any{"deleted_at": nil}),
	}).Create(&row).Error; err != nil {
		return err
	}
	return st.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SpaceRepo{Did: st.did, Space: uri}).Error
}

func (st *spaceStore) createSpace(ref space.Ref, cfg models.SimplespaceConfig) error {
	if err := st.ensureSpace(ref); err != nil {
		return err
	}
	cfg.Did, cfg.Uri = st.did, ref.String()
	return st.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&cfg).Error
}

func (st *spaceStore) updateSpaceConfig(uri string, set map[string]any) error {
	if len(set) == 0 {
		return nil
	}
	return st.db.Model(&models.SimplespaceConfig{}).Where("did = ? AND uri = ?", st.did, uri).Updates(set).Error
}

func (st *spaceStore) listSpaces(limit int, cursor, typ, authority string) ([]models.Space, error) {
	q := st.db.Where("did = ? AND deleted_at IS NULL", st.did).Order("uri asc").Limit(limit)
	if authority != "" {
		q = q.Where("authority = ?", authority)
	}
	if typ != "" {
		q = q.Where("type = ?", typ)
	}
	if cursor != "" {
		q = q.Where("uri > ?", cursor)
	}
	var rows []models.Space
	return rows, q.Find(&rows).Error
}

func (st *spaceStore) getRepoState(uri string) (*models.SpaceRepo, error) {
	var row models.SpaceRepo
	err := st.db.Where("did = ? AND space = ?", st.did, uri).Take(&row).Error
	if notFound(err) {
		return nil, nil
	}
	return &row, err
}

func (st *spaceStore) getRecord(uri string) (*models.SpaceRecord, error) {
	var row models.SpaceRecord
	err := st.db.Where("did = ? AND uri = ?", st.did, uri).Take(&row).Error
	if notFound(err) {
		return nil, nil
	}
	return &row, err
}

func (st *spaceStore) getRecordCid(uri string) (*cid.Cid, error) {
	rec, err := st.getRecord(uri)
	if err != nil || rec == nil {
		return nil, err
	}
	c, err := cid.Decode(rec.Cid)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (st *spaceStore) listRecords(uri string, limit int, cursor string, reverse bool, collection string) ([]models.SpaceRecord, error) {
	q := st.db.Where("did = ? AND space = ?", st.did, uri).Limit(limit)
	if reverse {
		q = q.Order("uri asc")
	} else {
		q = q.Order("uri desc")
	}
	if collection != "" {
		q = q.Where("collection = ?", collection)
	}
	if cursor != "" {
		if reverse {
			q = q.Where("uri > ?", cursor)
		} else {
			q = q.Where("uri < ?", cursor)
		}
	}
	var rows []models.SpaceRecord
	return rows, q.Find(&rows).Error
}

// allRecords returns every record of this account's repo in a space, ordered
// by uri.
func (st *spaceStore) allRecords(uri string) ([]models.SpaceRecord, error) {
	var rows []models.SpaceRecord
	return rows, st.db.Where("did = ? AND space = ?", st.did, uri).Order("uri asc").Find(&rows).Error
}

type oplogRow struct {
	models.SpaceRecordOplog
	Value []byte
}

// listRepoOps pages the oplog. Joining on the op's cid as well as its uri
// leaves out the values of ops a later one superseded.
func (st *spaceStore) listRepoOps(uri string, limit int, since string, cursorRev string, cursorIdx int, hasCursor bool) ([]oplogRow, error) {
	q := st.db.Table("space_record_oplogs AS o").
		Select("o.*, r.value AS value").
		Joins("LEFT JOIN space_records r ON r.uri = o.uri AND r.cid = o.cid AND r.did = o.did").
		Where("o.did = ? AND o.space = ?", st.did, uri).
		Order("o.rev asc").Order("o.idx asc").Limit(limit)
	if since != "" {
		q = q.Where("o.rev > ?", since)
	}
	if hasCursor {
		q = q.Where("(o.rev > ? OR (o.rev = ? AND o.idx > ?))", cursorRev, cursorRev, cursorIdx)
	}
	var rows []oplogRow
	return rows, q.Scan(&rows).Error
}

func (st *spaceStore) hasRecord(uri string) (bool, error) {
	var n int64
	err := st.db.Model(&models.SpaceRecord{}).Where("did = ? AND uri = ?", st.did, uri).Count(&n).Error
	return n > 0, err
}

func (st *spaceStore) getMember(uri, member string) (*models.SimplespaceMember, error) {
	var row models.SimplespaceMember
	err := st.db.Where("did = ? AND space = ? AND member_did = ?", st.did, uri, member).Take(&row).Error
	if notFound(err) {
		return nil, nil
	}
	return &row, err
}

func (st *spaceStore) putMember(uri, member string, read, write bool) error {
	return st.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&models.SimplespaceMember{Did: st.did, Space: uri, MemberDid: member, Read: read, Write: write}).Error
}

func (st *spaceStore) removeMember(uri, member string) error {
	return st.db.Where("did = ? AND space = ? AND member_did = ?", st.did, uri, member).Delete(&models.SimplespaceMember{}).Error
}

func (st *spaceStore) listMembers(uri string, limit int, cursor string) ([]models.SimplespaceMember, error) {
	q := st.db.Where("did = ? AND space = ?", st.did, uri).Order("member_did asc").Limit(limit)
	if cursor != "" {
		q = q.Where("member_did > ?", cursor)
	}
	var rows []models.SimplespaceMember
	return rows, q.Find(&rows).Error
}

// spaceWrite is a prepared space write.
type spaceWrite struct {
	Action     string // create, update, delete
	Collection string
	Rkey       string
	Uri        string
	Record     *space.SerializedRecord
	Status     string // validationStatus, empty when not validated
	Blobs      []cid.Cid
}

type spaceCommit struct {
	Rev     string
	SetHash []byte
}

// applyWrites applies a batch as one commit sharing a single rev. Each write
// sees the ones before it. It returns nil for an empty batch.
func (st *spaceStore) applyWrites(ref space.Ref, writes []spaceWrite) (*spaceCommit, error) {
	if len(writes) == 0 {
		return nil, nil
	}
	if err := st.ensureSpace(ref); err != nil {
		return nil, err
	}
	uri := ref.String()
	state, err := st.getRepoState(uri)
	if err != nil {
		return nil, err
	}
	var setHash []byte
	prevRev := ""
	if state != nil {
		setHash = state.SetHash
		if state.Rev != nil {
			prevRev = *state.Rev
		}
	}
	repo, err := space.RepoCommitFromState(setHash)
	if err != nil {
		return nil, err
	}
	rev := nextTID(prevRev)
	if err := st.assertBlobsUploaded(writes); err != nil {
		return nil, err
	}
	var ops []models.SpaceRecordOplog
	var dropped []string
	for _, w := range writes {
		prev, err := st.getRecordCid(w.Uri)
		if err != nil {
			return nil, err
		}
		if prev != nil {
			old, err := st.recordBlobs(w.Uri)
			if err != nil {
				return nil, err
			}
			dropped = append(dropped, old...)
		}
		var cur *cid.Cid
		switch w.Action {
		case "delete":
			if prev == nil {
				return nil, errInvalid("RecordNotFound", "Record not found: %s/%s", w.Collection, w.Rkey)
			}
			if err := st.db.Where("did = ? AND uri = ?", st.did, w.Uri).Delete(&models.SpaceRecord{}).Error; err != nil {
				return nil, err
			}
			if err := st.db.Where("record_uri = ?", w.Uri).Delete(&models.SpaceRecordBlob{}).Error; err != nil {
				return nil, err
			}
		default:
			if w.Action == "create" && prev != nil {
				return nil, errInvalid("RecordAlreadyExists", "Record already exists: %s/%s", w.Collection, w.Rkey)
			}
			if w.Action == "update" && prev == nil {
				return nil, errInvalid("RecordNotFound", "Record not found: %s/%s", w.Collection, w.Rkey)
			}
			row := models.SpaceRecord{
				Uri: w.Uri, Did: st.did, Space: uri, Collection: w.Collection, Rkey: w.Rkey,
				Cid: w.Record.Cid.String(), Value: w.Record.Bytes, RepoRev: rev, IndexedAt: nowISO(),
			}
			if err := st.db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "uri"}},
				DoUpdates: clause.AssignmentColumns([]string{"cid", "value", "repo_rev", "indexed_at"}),
			}).Create(&row).Error; err != nil {
				return nil, err
			}
			c := w.Record.Cid
			cur = &c
			if err := st.setRecordBlobs(w.Uri, w.Blobs); err != nil {
				return nil, err
			}
		}
		repo.ApplyOp(space.RepoOp{Collection: w.Collection, Rkey: w.Rkey, Cid: cur, Prev: prev})
		op := models.SpaceRecordOplog{Did: st.did, Space: uri, Rev: rev, Idx: len(ops), Action: w.Action, Uri: w.Uri, Collection: w.Collection, Rkey: w.Rkey}
		if cur != nil {
			s := cur.String()
			op.Cid = &s
		}
		if prev != nil {
			s := prev.String()
			op.Prev = &s
		}
		ops = append(ops, op)
	}
	state2 := repo.SetHash.State()
	if err := st.db.Model(&models.SpaceRepo{}).Where("did = ? AND space = ?", st.did, uri).Updates(map[string]any{"set_hash": state2, "rev": rev}).Error; err != nil {
		return nil, err
	}
	if err := st.db.Create(&ops).Error; err != nil {
		return nil, err
	}
	if err := st.gcBlobs(dropped); err != nil {
		return nil, err
	}
	return &spaceCommit{Rev: rev, SetHash: state2}, nil
}

// setRecordBlobs replaces the blobs a space record references.
func (st *spaceStore) setRecordBlobs(recordURI string, blobs []cid.Cid) error {
	if err := st.db.Where("record_uri = ?", recordURI).Delete(&models.SpaceRecordBlob{}).Error; err != nil {
		return err
	}
	for _, b := range blobs {
		if err := st.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SpaceRecordBlob{Did: st.did, BlobCid: b.String(), RecordUri: recordURI}).Error; err != nil {
			return err
		}
	}
	return nil
}

// activeRecipients lists the services registered for a governed space whose
// registration has not expired.
func (st *spaceStore) activeRecipients(uri string) ([]models.SpaceCredentialRecipient, error) {
	var rows []models.SpaceCredentialRecipient
	return rows, st.db.Where("did = ? AND space = ? AND expires_at > ?", st.did, uri, nowISO()).Find(&rows).Error
}

// deleteSpace deletes a governed space along with this account's own repo in
// it. The space row stays as a tombstone.
func (st *spaceStore) deleteSpace(uri string) error {
	if err := st.db.Model(&models.Space{}).Where("did = ? AND uri = ?", st.did, uri).Update("deleted_at", nowISO()).Error; err != nil {
		return err
	}
	var blobCids []string
	if err := st.db.Raw("SELECT DISTINCT blob_cid FROM space_record_blobs WHERE did = ? AND record_uri IN (SELECT uri FROM space_records WHERE did = ? AND space = ?)", st.did, st.did, uri).Scan(&blobCids).Error; err != nil {
		return err
	}
	if err := st.db.Exec("DELETE FROM space_record_blobs WHERE did = ? AND record_uri IN (SELECT uri FROM space_records WHERE did = ? AND space = ?)", st.did, st.did, uri).Error; err != nil {
		return err
	}
	if err := st.db.Where("did = ? AND uri = ?", st.did, uri).Delete(&models.SimplespaceConfig{}).Error; err != nil {
		return err
	}
	for _, m := range []any{&models.SimplespaceMember{}, &models.SpaceWriter{}, &models.SpaceCredentialRecipient{}, &models.SpaceRecord{}, &models.SpaceRecordOplog{}, &models.SpaceRepo{}} {
		if err := st.db.Where("did = ? AND space = ?", st.did, uri).Delete(m).Error; err != nil {
			return err
		}
	}
	return st.gcBlobs(blobCids)
}

// buildSignedCommit signs the repo's current state for one reader. Nil when
// the repo has never been written to.
func buildSignedCommit(ref space.Ref, author string, state *models.SpaceRepo, key space.Signer) (*space.SignedCommit, error) {
	if state == nil || state.SetHash == nil || state.Rev == nil {
		return nil, nil
	}
	repo, err := space.RepoCommitFromState(state.SetHash)
	if err != nil {
		return nil, err
	}
	c, err := repo.Sign(space.CommitCtx{Space: ref.String(), Author: author, Rev: *state.Rev}, key)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
