package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SpaceRepoOpType is the operation applied to one current record.
type SpaceRepoOpType string

const (
	SpaceRepoOpCreate SpaceRepoOpType = "create"
	SpaceRepoOpUpdate SpaceRepoOpType = "update"
	SpaceRepoOpDelete SpaceRepoOpType = "delete"
	SpaceRepoOpPut    SpaceRepoOpType = "put"

	// Short aliases make callers that model applyWrites operations concise.
	SpaceRepoCreate = SpaceRepoOpCreate
	SpaceRepoUpdate = SpaceRepoOpUpdate
	SpaceRepoDelete = SpaceRepoOpDelete
	SpaceRepoPut    = SpaceRepoOpPut
)

// SpaceRepoOperation is a validated mutation in an Apply batch. Rkey may be
// empty only for create/put operations; create then receives a generated TID.
type SpaceRepoOperation struct {
	Type       SpaceRepoOpType
	Collection string
	Rkey       string
	Record     any
}

// SpaceRepoAction is the concrete mutation selected after resolving an
// operation against the current repository state. In particular, a put is
// reported as create or update, never as put.
type SpaceRepoAction struct {
	Type       SpaceRepoOpType
	Collection string
	Rkey       string
}

// SpaceRepoActionAuthorizer authorizes the concrete action selected inside the
// serialized Apply transaction. It must return nil to permit the mutation.
type SpaceRepoActionAuthorizer func(SpaceRepoAction) error

// SpaceRepoAllowedActions is a small authorization contract for callers that
// already have a set of permitted concrete actions.
type SpaceRepoAllowedActions map[SpaceRepoOpType]bool

func (a SpaceRepoAllowedActions) Authorize(action SpaceRepoAction) error {
	if a[action.Type] {
		return nil
	}
	return &SpaceRepoInsufficientScopeError{Action: action}
}

// SpaceRepoInsufficientScopeError identifies a concrete action rejected by an
// action authorizer. Callers can map it to their protocol's scope response.
type SpaceRepoInsufficientScopeError struct {
	Action SpaceRepoAction
}

func (e *SpaceRepoInsufficientScopeError) Error() string {
	if e == nil {
		return "insufficient scope"
	}
	return fmt.Sprintf("insufficient scope for %s action on %s/%s", e.Action.Type, e.Action.Collection, e.Action.Rkey)
}

// SpaceRepoWrite is a compatibility spelling for SpaceRepoOperation.
type SpaceRepoWrite = SpaceRepoOperation

// SpaceRepoChange describes one operation's resulting CID and prior CID.
type SpaceRepoChange struct {
	Type        SpaceRepoOpType
	Collection  string
	Rkey        string
	CID         string
	PreviousCID string
	URI         string
}

// SpaceRepoBatch is the result of one atomic batch. All changes use Rev.
type SpaceRepoBatch struct {
	Space   string
	Author  string
	Rev     string
	LtHash  []byte
	Changes []SpaceRepoChange
}

// SpaceRepoFailureStage names points at which tests may force a transaction to
// fail. The hook is intentionally not used by production code unless a caller
// installs one explicitly.
type SpaceRepoFailureStage string

const (
	SpaceRepoFailureAfterRepoCreation   SpaceRepoFailureStage = "after-repo-creation"
	SpaceRepoFailureAfterRecordMutation SpaceRepoFailureStage = "after-record-mutation"
	SpaceRepoFailureAfterBlobMutation   SpaceRepoFailureStage = "after-blob-mutation"
	SpaceRepoFailureAfterOplogInsertion SpaceRepoFailureStage = "after-oplog-insertion"
	SpaceRepoFailureAfterHeadUpdate     SpaceRepoFailureStage = "after-head-update"

	// Short names are useful in table-driven tests.
	FailureAfterRepoCreation   = SpaceRepoFailureAfterRepoCreation
	FailureAfterRecordMutation = SpaceRepoFailureAfterRecordMutation
	FailureAfterBlobMutation   = SpaceRepoFailureAfterBlobMutation
	FailureAfterOplogInsertion = SpaceRepoFailureAfterOplogInsertion
	FailureAfterHeadUpdate     = SpaceRepoFailureAfterHeadUpdate
)

// SpaceRepoFailureHook is called inside the transaction at a named stage.
type SpaceRepoFailureHook func(SpaceRepoFailureStage) error

// SpaceRepoMan owns permissioned-space repo persistence. It deliberately does
// not expose XRPC/auth behavior: callers provide the already-authorized author.
type SpaceRepoMan struct {
	db                *db.DB
	s3Config          *S3Config
	clock             *syntax.TIDClock
	host              string
	notificationClock func() time.Time

	failureMu   sync.RWMutex
	failureHook SpaceRepoFailureHook

	headMu sync.RWMutex
	heads  map[string]SpaceRepoBatch
}

// keyedRepoLocks serializes a repo across managers in this process. The key is
// canonical space URI plus author DID, not merely one of those components.
var keyedRepoLocks sync.Map // map[string]*sync.Mutex
var spaceRepoClock = syntax.NewTIDClock(0)

func repoLock(key string) *sync.Mutex {
	candidate := new(sync.Mutex)
	actual, _ := keyedRepoLocks.LoadOrStore(key, candidate)
	return actual.(*sync.Mutex)
}

// NewSpaceRepoMan constructs the persistence manager for a server.
func NewSpaceRepoMan(s *Server) *SpaceRepoMan {
	host := ""
	if s != nil && s.config != nil {
		host = s.config.Did
	}
	return &SpaceRepoMan{
		db:                s.db,
		s3Config:          s.s3Config,
		clock:             spaceRepoClock,
		host:              host,
		notificationClock: spaceNotificationClock(s),
		heads:             make(map[string]SpaceRepoBatch),
	}
}

// NewSpaceRepoManager is an alias for callers using the longer name.
func NewSpaceRepoManager(s *Server) *SpaceRepoMan { return NewSpaceRepoMan(s) }

// SetFailureHook installs a test-only transaction failure hook and returns a
// restore function. A nil hook disables injection.
func (m *SpaceRepoMan) SetFailureHook(hook SpaceRepoFailureHook) func() {
	m.failureMu.Lock()
	previous := m.failureHook
	m.failureHook = hook
	m.failureMu.Unlock()
	return func() {
		m.failureMu.Lock()
		m.failureHook = previous
		m.failureMu.Unlock()
	}
}

// SetFailureStage is a convenience test hook that fails once at stage.
func (m *SpaceRepoMan) SetFailureStage(stage SpaceRepoFailureStage) func() {
	var once sync.Once
	return m.SetFailureHook(func(got SpaceRepoFailureStage) error {
		if got != stage {
			return nil
		}
		var err error
		once.Do(func() { err = fmt.Errorf("injected space repo failure at %s", stage) })
		return err
	})
}

func (m *SpaceRepoMan) fail(stage SpaceRepoFailureStage) error {
	m.failureMu.RLock()
	hook := m.failureHook
	m.failureMu.RUnlock()
	if hook == nil {
		return nil
	}
	return hook(stage)
}

// Apply atomically applies operations to one author's repo in one space.
func (m *SpaceRepoMan) Apply(ctx context.Context, spaceRef, author string, operations []SpaceRepoOperation) (SpaceRepoBatch, error) {
	return m.apply(ctx, spaceRef, author, operations, nil)
}

// ApplyWithAuthorization atomically applies operations and invokes authorize
// after each operation's concrete create/update/delete action is resolved from
// current state, while the repository lock and transaction are held.
func (m *SpaceRepoMan) ApplyWithAuthorization(ctx context.Context, spaceRef, author string, operations []SpaceRepoOperation, authorize SpaceRepoActionAuthorizer) (SpaceRepoBatch, error) {
	return m.apply(ctx, spaceRef, author, operations, authorize)
}

func (m *SpaceRepoMan) apply(ctx context.Context, spaceRef, author string, operations []SpaceRepoOperation, authorize SpaceRepoActionAuthorizer) (SpaceRepoBatch, error) {
	canonicalSpace, _, err := validateSpaceRepoIdentity(spaceRef, author)
	if err != nil {
		return SpaceRepoBatch{}, err
	}
	if len(operations) == 0 {
		return SpaceRepoBatch{}, errors.New("space repo batch must not be empty")
	}

	lock := repoLock(canonicalSpace + "\x00" + author)
	lock.Lock()
	defer lock.Unlock()

	var result SpaceRepoBatch
	err = m.db.Transaction(ctx, func(tx *db.DB) error {
		var repo models.SpaceRepo
		q := tx.Client().WithContext(ctx).Where("space = ? AND author = ?", canonicalSpace, author)
		// SQLite does not understand FOR UPDATE. The process lock above provides
		// its serialization; PostgreSQL also gets a database row lock.
		if tx.Client().Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		repoErr := q.First(&repo).Error
		if errors.Is(repoErr, gorm.ErrRecordNotFound) {
			initial, initErr := space.NewLtHash()
			if initErr != nil {
				return initErr
			}
			repo = models.SpaceRepo{Space: canonicalSpace, Author: author, LtHash: initial.State()}
			if err := tx.Create(ctx, &repo, nil).Error; err != nil {
				return fmt.Errorf("create space repo: %w", err)
			}
		} else if repoErr != nil {
			return fmt.Errorf("load space repo: %w", repoErr)
		}
		if err := m.fail(SpaceRepoFailureAfterRepoCreation); err != nil {
			return err
		}

		var existing []models.SpaceRecord
		if err := tx.Client().WithContext(ctx).Where("space = ? AND author = ?", canonicalSpace, author).Find(&existing).Error; err != nil {
			return fmt.Errorf("load space records: %w", err)
		}
		old := make(map[string]models.SpaceRecord, len(existing))
		state := make(map[string]*spaceRecordState, len(existing))
		for _, row := range existing {
			key := recordKey(row.Collection, row.Rkey)
			copyRow := row
			copyRow.CanonicalCBOR = append([]byte(nil), row.CanonicalCBOR...)
			old[key] = copyRow
			state[key] = &spaceRecordState{row: copyRow}
		}

		hash, err := space.NewLtHash(repo.LtHash)
		if err != nil {
			return fmt.Errorf("load repo LtHash: %w", err)
		}
		changes := make([]SpaceRepoChange, 0, len(operations))
		prepared := make([]preparedSpaceOp, 0, len(operations))
		for idx, input := range operations {
			change, op, err := m.prepareOperation(input, canonicalSpace, author, state, hash, authorize)
			if err != nil {
				return fmt.Errorf("operation %d: %w", idx, err)
			}
			prepared = append(prepared, op)
			changes = append(changes, change)
		}

		// Blob namespace checks happen before any record/ref/op/head mutation.
		seenBlobs := make(map[string]struct{})
		for _, op := range prepared {
			for _, blobRef := range op.blobRefs {
				key := blobRef.CID.String()
				if _, ok := seenBlobs[key]; ok {
					continue
				}
				seenBlobs[key] = struct{}{}
				blobQuery := tx.Client().WithContext(ctx).Where("did = ? AND cid = ?", author, blobRef.CID.Bytes()).Order("id DESC")
				if tx.Client().Name() == "postgres" {
					// Serialize Space publication with public zero-ref cleanup. A
					// count-only query would allow a new SpaceBlobRef to commit after
					// cleanup observed the old count.
					blobQuery = blobQuery.Clauses(clause.Locking{Strength: "UPDATE"})
				}
				var blobs []models.Blob
				if err := blobQuery.Find(&blobs).Error; err != nil {
					return fmt.Errorf("check blob %s: %w", key, err)
				}
				if len(blobs) == 0 {
					return fmt.Errorf("blob %s is not uploaded by author %s", key, author)
				}
				if blobRef.MetadataKnown {
					matched := false
					knownBlobs := 0
					mimeMismatch := false
					for _, blob := range blobs {
						// Rows created before MIME/size persistence have neither
						// value. Preserve their existing references; all new uploads
						// carry both fields and are checked strictly.
						if blob.MimeType == "" && blob.Size == 0 {
							continue
						}
						knownBlobs++
						if blob.MimeType != blobRef.MimeType {
							mimeMismatch = true
							continue
						}
						if blob.Size == blobRef.Size {
							matched = true
							break
						}
					}
					if knownBlobs > 0 && !matched {
						if mimeMismatch {
							return fmt.Errorf("blob %s MIME type does not match uploaded blob", key)
						}
						return fmt.Errorf("blob %s size does not match uploaded blob", key)
					}
				}
			}
		}

		// Persist only the final state of each touched record. This makes a
		// create+delete batch atomic without leaving a transient row behind.
		touched := make(map[string]struct{})
		for _, op := range prepared {
			touched[recordKey(op.collection, op.rkey)] = struct{}{}
		}
		touchedKeys := make([]string, 0, len(touched))
		for key := range touched {
			touchedKeys = append(touchedKeys, key)
		}
		sort.Strings(touchedKeys)
		for _, key := range touchedKeys {
			before, hadBefore := old[key]
			after, hasAfter := state[key]
			switch {
			case !hadBefore && hasAfter:
				if err := tx.Create(ctx, &after.row, nil).Error; err != nil {
					return fmt.Errorf("create space record %s: %w", key, err)
				}
			case hadBefore && !hasAfter:
				if err := tx.Client().WithContext(ctx).Where("space = ? AND author = ? AND collection = ? AND rkey = ?", canonicalSpace, author, before.Collection, before.Rkey).Delete(&models.SpaceRecord{}).Error; err != nil {
					return fmt.Errorf("delete space record %s: %w", key, err)
				}
			case hadBefore && hasAfter:
				if err := tx.Save(ctx, &after.row, nil).Error; err != nil {
					return fmt.Errorf("update space record %s: %w", key, err)
				}
			}
		}
		if err := m.fail(SpaceRepoFailureAfterRecordMutation); err != nil {
			return err
		}

		cleanupCIDs := make(map[string]struct{})
		for _, key := range touchedKeys {
			before, hadBefore := old[key]
			if hadBefore {
				// Capture the actual persisted refs before deleting them. Existing
				// records loaded above intentionally do not need to decode their
				// values just to release their permissioned blob references.
				var oldRefs []models.SpaceBlobRef
				if err := tx.Client().WithContext(ctx).Where("space = ? AND author = ? AND collection = ? AND rkey = ?", canonicalSpace, author, before.Collection, before.Rkey).Find(&oldRefs).Error; err != nil {
					return fmt.Errorf("load old blob refs %s: %w", key, err)
				}
				for _, ref := range oldRefs {
					cleanupCIDs[ref.CID] = struct{}{}
				}
				if err := tx.Client().WithContext(ctx).Where("space = ? AND author = ? AND collection = ? AND rkey = ?", canonicalSpace, author, before.Collection, before.Rkey).Delete(&models.SpaceBlobRef{}).Error; err != nil {
					return fmt.Errorf("delete old blob refs %s: %w", key, err)
				}
			}
			if after, ok := state[key]; ok {
				for _, blobCID := range after.blobs {
					ref := models.SpaceBlobRef{Space: canonicalSpace, Author: author, Collection: after.row.Collection, Rkey: after.row.Rkey, CID: blobCID.String()}
					if err := tx.Create(ctx, &ref, nil).Error; err != nil {
						return fmt.Errorf("create blob ref %s: %w", key, err)
					}
				}
			}
		}
		// A SpaceBlobRef is a visibility reference just like a public
		// ref_count. Clean each CID only after this transaction's ref deletes
		// are visible, while retaining it if another Space ref or public ref
		// still exists.
		for rawCID := range cleanupCIDs {
			blobCID, err := cid.Parse(rawCID)
			if err != nil {
				return fmt.Errorf("parse released blob ref %s: %w", rawCID, err)
			}
			if err := cleanupUnreferencedBlobsForCID(ctx, tx, author, blobCID.Bytes(), m.s3Config); err != nil {
				return fmt.Errorf("cleanup released blob %s: %w", rawCID, err)
			}
		}
		if err := m.fail(SpaceRepoFailureAfterBlobMutation); err != nil {
			return err
		}

		rev := m.nextTID()
		for idx, op := range prepared {
			opRow := models.SpaceRepoOp{Space: canonicalSpace, Author: author, Rev: rev, Idx: idx, Collection: op.collection, Rkey: op.rkey}
			if op.cid != "" {
				current := op.cid
				opRow.CurrentCID = &current
			}
			if op.previousCID != "" {
				previous := op.previousCID
				opRow.PreviousCID = &previous
			}
			if err := tx.Create(ctx, &opRow, nil).Error; err != nil {
				return fmt.Errorf("insert space repo op %d: %w", idx, err)
			}
		}
		if err := m.fail(SpaceRepoFailureAfterOplogInsertion); err != nil {
			return err
		}

		repo.Rev = rev
		repo.LtHash = hash.State()
		if err := tx.Save(ctx, &repo, nil).Error; err != nil {
			return fmt.Errorf("update space repo head: %w", err)
		}
		// Keep the local writer set in the same transaction as the repo head. The
		// writer row stores the notification digest (not the serialized LtHash
		// state), and the conditional upsert prevents an older snapshot from
		// regressing metadata learned from another host.
		now := m.notificationClock
		if now == nil {
			now = spaceNotificationClock(nil)
		}
		notificationNow := now().UTC()
		digest, err := spaceNotifyDigest(repo.LtHash)
		if err != nil {
			return fmt.Errorf("digest Space repo LtHash: %w", err)
		}
		accepted, err := upsertSpaceWriterSnapshot(ctx, tx, canonicalSpace, author, m.host, rev, digest, notificationNow, nil)
		if err != nil {
			return fmt.Errorf("upsert local Space writer: %w", err)
		}
		// The notification is an ordinary database outbox row. It is deliberately
		// inserted before the transaction callback returns, and contains only the
		// metadata needed by notifyWrite; no record value, collection, rkey, CID,
		// or blob bytes ever cross this boundary. Endpoint resolution and sending
		// are worker concerns, so a resolver cannot cause a repo transaction to
		// block on or call the network. Do not forward a snapshot that the
		// monotonic writer upsert rejected as stale.
		if accepted {
			if err := enqueueSpaceRepoNotifyWrite(ctx, tx, canonicalSpace, author, rev, digest, notificationNow); err != nil {
				return fmt.Errorf("enqueue Space notifyWrite: %w", err)
			}
		}
		if err := m.fail(SpaceRepoFailureAfterHeadUpdate); err != nil {
			return err
		}
		result = SpaceRepoBatch{Space: canonicalSpace, Author: author, Rev: rev, LtHash: append([]byte(nil), repo.LtHash...), Changes: changes}
		return nil
	})
	if err != nil {
		return SpaceRepoBatch{}, err
	}

	// The cache is intentionally updated only after Transaction commits.
	m.headMu.Lock()
	m.heads[canonicalSpace+"\x00"+author] = result
	m.headMu.Unlock()
	return result, nil
}

// ApplyWrites is an alias matching the atproto operation name.
func (m *SpaceRepoMan) ApplyWrites(ctx context.Context, spaceRef, author string, operations []SpaceRepoOperation) (SpaceRepoBatch, error) {
	return m.Apply(ctx, spaceRef, author, operations)
}

// PutRecord applies an upsert operation. A blank rkey generates one when the
// record does not already exist (a nonblank rkey is always used as supplied).
func (m *SpaceRepoMan) PutRecord(ctx context.Context, spaceRef, author, collection, rkey string, record any) (SpaceRepoBatch, error) {
	return m.Apply(ctx, spaceRef, author, []SpaceRepoOperation{{Type: SpaceRepoOpPut, Collection: collection, Rkey: rkey, Record: record}})
}

// PutRecordWithAuthorization applies an upsert while authorizing its concrete
// create/update action inside the serialized transaction.
func (m *SpaceRepoMan) PutRecordWithAuthorization(ctx context.Context, spaceRef, author, collection, rkey string, record any, authorize SpaceRepoActionAuthorizer) (SpaceRepoBatch, error) {
	return m.ApplyWithAuthorization(ctx, spaceRef, author, []SpaceRepoOperation{{Type: SpaceRepoOpPut, Collection: collection, Rkey: rkey, Record: record}}, authorize)
}

// DeleteRecord applies a strict delete. Missing records are errors; an endpoint
// needing idempotent deletion should check GetRecord before calling this method.
func (m *SpaceRepoMan) DeleteRecord(ctx context.Context, spaceRef, author, collection, rkey string) (SpaceRepoBatch, error) {
	return m.Apply(ctx, spaceRef, author, []SpaceRepoOperation{{Type: SpaceRepoOpDelete, Collection: collection, Rkey: rkey}})
}

type spaceRecordState struct {
	row   models.SpaceRecord
	blobs []cid.Cid
}

type preparedSpaceOp struct {
	typeName    SpaceRepoOpType
	collection  string
	rkey        string
	cid         string
	previousCID string
	cbor        []byte
	blobs       []cid.Cid
	blobRefs    []blobReferenceMetadata
}

func (m *SpaceRepoMan) prepareOperation(input SpaceRepoOperation, canonicalSpace, author string, state map[string]*spaceRecordState, hash *space.LtHash, authorize SpaceRepoActionAuthorizer) (SpaceRepoChange, preparedSpaceOp, error) {
	typ := normalizeSpaceRepoOpType(input.Type)
	if typ == "" {
		return SpaceRepoChange{}, preparedSpaceOp{}, fmt.Errorf("unknown operation type %q", input.Type)
	}
	collection, err := validateCollection(input.Collection)
	if err != nil {
		return SpaceRepoChange{}, preparedSpaceOp{}, err
	}
	rkey := input.Rkey
	if typ == SpaceRepoOpCreate || typ == SpaceRepoOpPut {
		if rkey == "" {
			rkey = m.nextTID()
		}
	}
	if rkey == "" {
		return SpaceRepoChange{}, preparedSpaceOp{}, errors.New("rkey is required for update/delete")
	}
	rkey, err = validateRkey(rkey)
	if err != nil {
		return SpaceRepoChange{}, preparedSpaceOp{}, err
	}
	key := recordKey(collection, rkey)
	current, exists := state[key]
	if typ == SpaceRepoOpPut {
		if exists {
			typ = SpaceRepoOpUpdate
		} else {
			typ = SpaceRepoOpCreate
		}
	}
	if typ == SpaceRepoOpCreate && exists {
		return SpaceRepoChange{}, preparedSpaceOp{}, fmt.Errorf("record %s/%s already exists", collection, rkey)
	}
	if (typ == SpaceRepoOpUpdate || typ == SpaceRepoOpDelete) && !exists {
		return SpaceRepoChange{}, preparedSpaceOp{}, fmt.Errorf("record %s/%s does not exist", collection, rkey)
	}
	if authorize != nil {
		if err := authorize(SpaceRepoAction{Type: typ, Collection: collection, Rkey: rkey}); err != nil {
			return SpaceRepoChange{}, preparedSpaceOp{}, err
		}
	}

	op := preparedSpaceOp{typeName: typ, collection: collection, rkey: rkey}
	change := SpaceRepoChange{Type: typ, Collection: collection, Rkey: rkey, URI: canonicalSpace + "/" + author + "/" + collection + "/" + rkey}
	if exists {
		op.previousCID = current.row.CID
		change.PreviousCID = current.row.CID
		hash.Remove(space.FormatElement(collection, rkey, current.row.CID))
	}
	if typ == SpaceRepoOpDelete {
		delete(state, key)
		return change, op, nil
	}
	if input.Record == nil {
		return SpaceRepoChange{}, preparedSpaceOp{}, errors.New("record is required for create/update/put")
	}
	recordMap, err := normalizeSpaceRecord(input.Record)
	if err != nil {
		return SpaceRepoChange{}, preparedSpaceOp{}, err
	}
	data, err := atdata.MarshalCBOR(recordMap)
	if err != nil {
		return SpaceRepoChange{}, preparedSpaceOp{}, fmt.Errorf("canonical DAG-CBOR: %w", err)
	}
	recordCID, err := space.CIDForCBOR(data)
	if err != nil {
		return SpaceRepoChange{}, preparedSpaceOp{}, fmt.Errorf("record CID: %w", err)
	}
	blobRefs, err := getBlobReferencesFromCbor(data)
	if err != nil {
		return SpaceRepoChange{}, preparedSpaceOp{}, fmt.Errorf("record blob refs: %w", err)
	}
	blobCIDs := make([]cid.Cid, 0, len(blobRefs))
	for _, blobRef := range blobRefs {
		blobCIDs = append(blobCIDs, blobRef.CID)
	}
	op.cid = recordCID.String()
	op.cbor = data
	op.blobs = blobCIDs
	op.blobRefs = blobRefs
	change.CID = op.cid
	state[key] = &spaceRecordState{row: models.SpaceRecord{Space: canonicalSpace, Author: author, Collection: collection, Rkey: rkey, CID: op.cid, CanonicalCBOR: append([]byte(nil), data...)}, blobs: blobCIDs}
	hash.Add(space.FormatElement(collection, rkey, op.cid))
	return change, op, nil
}

func normalizeSpaceRepoOpType(raw SpaceRepoOpType) SpaceRepoOpType {
	value := string(raw)
	if pos := strings.LastIndexByte(value, '#'); pos >= 0 {
		value = value[pos+1:]
	}
	switch SpaceRepoOpType(strings.ToLower(value)) {
	case SpaceRepoOpCreate:
		return SpaceRepoOpCreate
	case SpaceRepoOpUpdate:
		return SpaceRepoOpUpdate
	case SpaceRepoOpDelete:
		return SpaceRepoOpDelete
	case SpaceRepoOpPut:
		return SpaceRepoOpPut
	default:
		return ""
	}
}

func normalizeSpaceRecord(record any) (map[string]any, error) {
	switch value := record.(type) {
	case map[string]any:
		return value, nil
	case *map[string]any:
		if value != nil {
			return *value, nil
		}
	case MarshalableMap:
		return map[string]any(value), nil
	case *MarshalableMap:
		if value != nil {
			return map[string]any(*value), nil
		}
	}
	return nil, errors.New("record must be a map[string]any")
}

func validateSpaceRepoIdentity(spaceRef, author string) (string, space.SpaceRef, error) {
	parsedSpace, err := space.ParseSpaceRef(spaceRef)
	if err != nil {
		return "", space.SpaceRef{}, fmt.Errorf("space ref: %w", err)
	}
	parsedAuthor, err := syntax.ParseDID(author)
	if err != nil || string(parsedAuthor) != author {
		if err == nil {
			err = errors.New("DID is not canonical")
		}
		return "", space.SpaceRef{}, fmt.Errorf("author DID: %w", err)
	}
	return parsedSpace.String(), parsedSpace, nil
}

func validateCollection(collection string) (string, error) {
	parsed, err := syntax.ParseNSID(collection)
	if err != nil || string(parsed) != collection {
		if err == nil {
			err = errors.New("NSID is not canonical")
		}
		return "", fmt.Errorf("collection: %w", err)
	}
	return string(parsed), nil
}

func validateRkey(rkey string) (string, error) {
	parsed, err := syntax.ParseRecordKey(rkey)
	if err != nil || string(parsed) != rkey {
		if err == nil {
			err = errors.New("record key is not canonical")
		}
		return "", fmt.Errorf("rkey: %w", err)
	}
	return string(parsed), nil
}

func recordKey(collection, rkey string) string { return collection + "\x00" + rkey }

func (m *SpaceRepoMan) nextTID() string { return m.clock.Next().String() }

// GetRepo returns the current head for a space/author pair.
func (m *SpaceRepoMan) GetRepo(ctx context.Context, spaceRef, author string) (models.SpaceRepo, error) {
	canonical, _, err := validateSpaceRepoIdentity(spaceRef, author)
	if err != nil {
		return models.SpaceRepo{}, err
	}
	var repo models.SpaceRepo
	err = m.db.Client().WithContext(ctx).Where("space = ? AND author = ?", canonical, author).First(&repo).Error
	return repo, err
}

// GetRecord returns one current record.
func (m *SpaceRepoMan) GetRecord(ctx context.Context, spaceRef, author, collection, rkey string) (*models.SpaceRecord, error) {
	canonical, _, err := validateSpaceRepoIdentity(spaceRef, author)
	if err != nil {
		return nil, err
	}
	collection, err = validateCollection(collection)
	if err != nil {
		return nil, err
	}
	rkey, err = validateRkey(rkey)
	if err != nil {
		return nil, err
	}
	var row models.SpaceRecord
	err = m.db.Client().WithContext(ctx).Where("space = ? AND author = ? AND collection = ? AND rkey = ?", canonical, author, collection, rkey).First(&row).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// ListRecords lists current records in canonical path order. Cursor is the
// previous collection/rkey path (or empty for the first page).
func (m *SpaceRepoMan) ListRecords(ctx context.Context, spaceRef, author, cursor string, limit int) ([]models.SpaceRecord, string, error) {
	canonical, _, err := validateSpaceRepoIdentity(spaceRef, author)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var rows []models.SpaceRecord
	if err := m.db.Client().WithContext(ctx).Where("space = ? AND author = ?", canonical, author).Order("collection ASC, rkey ASC").Find(&rows).Error; err != nil {
		return nil, "", err
	}
	if cursor != "" {
		filtered := rows[:0]
		for _, row := range rows {
			if row.Collection+"/"+row.Rkey > cursor {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[len(rows)-1].Collection + "/" + rows[len(rows)-1].Rkey
	}
	return rows, next, nil
}

// ListCurrentRecords is an explicit alias for ListRecords.
func (m *SpaceRepoMan) ListCurrentRecords(ctx context.Context, spaceRef, author, cursor string, limit int) ([]models.SpaceRecord, string, error) {
	return m.ListRecords(ctx, spaceRef, author, cursor, limit)
}

// ListOps lists the append-only operation log in revision/index order. Cursor
// is encoded as revision + ":" + decimal index.
func (m *SpaceRepoMan) ListOps(ctx context.Context, spaceRef, author, cursor string, limit int) ([]models.SpaceRepoOp, string, error) {
	canonical, _, err := validateSpaceRepoIdentity(spaceRef, author)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var rows []models.SpaceRepoOp
	if err := m.db.Client().WithContext(ctx).Where("space = ? AND author = ?", canonical, author).Order("rev ASC, idx ASC").Find(&rows).Error; err != nil {
		return nil, "", err
	}
	if cursor != "" {
		pos := strings.LastIndexByte(cursor, ':')
		if pos < 1 {
			return nil, "", errors.New("invalid ops cursor")
		}
		idx, parseErr := strconv.Atoi(cursor[pos+1:])
		if parseErr != nil {
			return nil, "", errors.New("invalid ops cursor index")
		}
		rev := cursor[:pos]
		filtered := rows[:0]
		for _, row := range rows {
			if row.Rev > rev || (row.Rev == rev && row.Idx > idx) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = last.Rev + ":" + strconv.Itoa(last.Idx)
	}
	return rows, next, nil
}

// ListOperations is an alias for ListOps.
func (m *SpaceRepoMan) ListOperations(ctx context.Context, spaceRef, author, cursor string, limit int) ([]models.SpaceRepoOp, string, error) {
	return m.ListOps(ctx, spaceRef, author, cursor, limit)
}
