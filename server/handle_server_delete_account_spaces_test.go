package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// TestAccountDeleteCascadesSpaceDataAndNotifies exercises the account-delete
// transaction against the same durable rows used by the Spaces handlers. In
// particular, a deleted authority space retains its tombstone and deletion
// outbox entry while account-authored permissioned data and write deliveries
// are removed.
func TestAccountDeleteCascadesSpaceDataAndNotifies(t *testing.T) {
	s := newTestServer(t)
	s.evtman = newTestEvtman(t)
	owner := s.createTestAccount(t, "space-delete-owner.pds.test")
	member := s.createTestAccount(t, "space-delete-member.pds.test")
	other := s.createTestAccount(t, "space-delete-other.pds.test")

	ownedRef, err := space.NewSpaceURI(owner.Did, "com.example.space", "owned")
	if err != nil {
		t.Fatal(err)
	}
	foreignRef, err := space.NewSpaceURI(other.Did, "com.example.space", "foreign")
	if err != nil {
		t.Fatal(err)
	}
	ownedSpace := ownedRef.String()
	foreignSpace := foreignRef.String()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := s.db.Create(ctx, &models.SimpleSpace{
		URI: ownedSpace, OwnerDID: owner.Did, Type: "com.example.space", SKey: "owned", Policy: "public", AppAccess: "open",
	}, nil).Error; err != nil {
		t.Fatalf("create owned space: %v", err)
	}
	if err := s.db.Create(ctx, &models.SimpleSpace{
		URI: foreignSpace, OwnerDID: other.Did, Type: "com.example.space", SKey: "foreign", Policy: "public", AppAccess: "open",
	}, nil).Error; err != nil {
		t.Fatalf("create foreign space: %v", err)
	}
	if err := s.db.Create(ctx, &models.SpaceNotifyRegistration{Space: ownedSpace, Service: "did:web:active.example#space", ExpiresAt: now.Add(time.Hour)}, nil).Error; err != nil {
		t.Fatalf("create active registration: %v", err)
	}
	if err := s.db.Create(ctx, &models.SpaceNotifyRegistration{Space: ownedSpace, Service: "did:web:expired.example#space", ExpiresAt: now.Add(-time.Hour)}, nil).Error; err != nil {
		t.Fatalf("create expired registration: %v", err)
	}
	if err := s.db.Create(ctx, &models.SimpleSpaceMember{Space: ownedSpace, DID: owner.Did}, nil).Error; err != nil {
		t.Fatalf("create owner membership: %v", err)
	}
	if err := s.db.Create(ctx, &models.SimpleSpaceMember{Space: ownedSpace, DID: member.Did}, nil).Error; err != nil {
		t.Fatalf("create member membership: %v", err)
	}

	ltHash, err := space.NewLtHash()
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range []models.SpaceRepo{
		{Space: ownedSpace, Author: owner.Did, Rev: "3jzfc7ia", LtHash: ltHash.State()},
		{Space: ownedSpace, Author: member.Did, Rev: "3jzfc7ib", LtHash: ltHash.State()},
		{Space: foreignSpace, Author: owner.Did, Rev: "3jzfc7ic", LtHash: ltHash.State()},
	} {
		if err := s.db.Create(ctx, &repo, nil).Error; err != nil {
			t.Fatalf("create repo %s/%s: %v", repo.Space, repo.Author, err)
		}
	}
	if err := s.db.Create(ctx, &models.SpaceRecord{Space: ownedSpace, Author: owner.Did, Collection: "com.example.record", Rkey: "owned", CID: "bafkreiowned", CanonicalCBOR: []byte("owned")}, nil).Error; err != nil {
		t.Fatalf("create owned record: %v", err)
	}
	if err := s.db.Create(ctx, &models.SpaceRecord{Space: foreignSpace, Author: owner.Did, Collection: "com.example.record", Rkey: "foreign", CID: "bafkreiforeign", CanonicalCBOR: []byte("foreign")}, nil).Error; err != nil {
		t.Fatalf("create foreign record: %v", err)
	}
	if err := s.db.Create(ctx, &models.SpaceRepoOp{Space: ownedSpace, Author: owner.Did, Rev: "3jzfc7ia", Idx: 0, Collection: "com.example.record", Rkey: "owned"}, nil).Error; err != nil {
		t.Fatalf("create owned op: %v", err)
	}
	if err := s.db.Create(ctx, &models.SpaceRepoOp{Space: foreignSpace, Author: owner.Did, Rev: "3jzfc7ic", Idx: 0, Collection: "com.example.record", Rkey: "foreign"}, nil).Error; err != nil {
		t.Fatalf("create foreign op: %v", err)
	}

	sharedCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum([]byte("shared-space-blob"))
	if err != nil {
		t.Fatal(err)
	}
	sharedBlob := &models.Blob{Did: owner.Did, Cid: sharedCID.Bytes(), RefCount: 0, Storage: "sqlite"}
	if err := s.db.Create(ctx, sharedBlob, nil).Error; err != nil {
		t.Fatalf("create shared blob: %v", err)
	}
	if err := s.db.Create(ctx, &models.BlobPart{BlobID: sharedBlob.ID, Idx: 0, Data: []byte("retained")}, nil).Error; err != nil {
		t.Fatalf("create shared blob part: %v", err)
	}
	if err := s.db.Create(ctx, &models.SpaceBlobRef{Space: ownedSpace, Author: member.Did, Collection: "com.example.record", Rkey: "remote", CID: sharedCID.String()}, nil).Error; err != nil {
		t.Fatalf("create remote blob ref: %v", err)
	}
	publicCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum([]byte("public-space-blob"))
	if err != nil {
		t.Fatal(err)
	}
	publicBlob := &models.Blob{Did: owner.Did, Cid: publicCID.Bytes(), RefCount: 1, Storage: "sqlite"}
	if err := s.db.Create(ctx, publicBlob, nil).Error; err != nil {
		t.Fatalf("create public blob: %v", err)
	}
	if err := s.db.Create(ctx, &models.BlobPart{BlobID: publicBlob.ID, Idx: 0, Data: []byte("public")}, nil).Error; err != nil {
		t.Fatalf("create public blob part: %v", err)
	}

	// These rows model both retryable and terminal stale writes. They must be
	// removed by author/kind, while the deletion outbox row created below must
	// survive the registration cleanup.
	for _, delivery := range []models.SpaceNotifyDelivery{
		{IdempotencyKey: "owner-pending-write", Kind: SpaceNotifyWriteLXM, Space: ownedSpace, Service: "did:web:active.example#space", Author: owner.Did, Rev: "3jzfc7ia", Status: SpaceNotifyDeliveryPending, ExpiresAt: now.Add(time.Hour)},
		{IdempotencyKey: "owner-terminal-write", Kind: SpaceNotifyWriteLXM, Space: foreignSpace, Service: "did:web:terminal.example#space", Author: owner.Did, Rev: "3jzfc7ic", Status: SpaceNotifyDeliveryDelivered, ExpiresAt: now.Add(time.Hour)},
	} {
		if err := s.db.Create(ctx, &delivery, nil).Error; err != nil {
			t.Fatalf("create stale delivery: %v", err)
		}
	}
	const replayJTI = "account-delete-replay-must-remain"
	if err := s.db.Create(ctx, &models.SpaceReplayJTI{JTI: replayJTI, TokenType: "delegation", ExpiresAt: now.Add(time.Hour)}, nil).Error; err != nil {
		t.Fatalf("create replay row: %v", err)
	}

	deleteCode := "delete-space-account"
	deleteExpiry := now.Add(time.Hour)
	if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", owner.Did).Updates(map[string]any{
		"account_delete_code":            deleteCode,
		"account_delete_code_expires_at": deleteExpiry,
	}).Error; err != nil {
		t.Fatalf("set delete code: %v", err)
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.deleteAccount", `{"did":"`+owner.Did+`","password":"`+owner.Password+`","token":"`+deleteCode+`"}`, nil)
	if err := s.handleServerDeleteAccount(e); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body=%s", rec.Code, rec.Body.String())
	}

	var deletedSpace models.SimpleSpace
	if err := s.db.First(ctx, &deletedSpace, "uri = ?", ownedSpace).Error; err != nil {
		t.Fatalf("load deleted space: %v", err)
	}
	if !deletedSpace.Deleted || deletedSpace.DeletedAt == nil {
		t.Fatalf("space was not tombstoned in place: %+v", deletedSpace)
	}
	var tombstone models.SpaceTombstone
	if err := s.db.First(ctx, &tombstone, "space = ?", ownedSpace).Error; err != nil {
		t.Fatalf("load authority tombstone: %v", err)
	}
	if tombstone.OwnerDID != owner.Did || tombstone.SourceDID != owner.Did {
		t.Fatalf("unexpected tombstone: %+v", tombstone)
	}
	for _, model := range []any{&models.SpaceRecord{}, &models.SpaceRepoOp{}, &models.SpaceBlobRef{}} {
		var count int64
		if err := s.db.Client().Model(model).Where("author = ?", owner.Did).Count(&count).Error; err != nil {
			t.Fatalf("count authored data: %v", err)
		}
		if count != 0 {
			t.Fatalf("authored %T rows remain: %d", model, count)
		}
	}
	var remoteRepo models.SpaceRepo
	if err := s.db.First(ctx, &remoteRepo, "space = ? AND author = ?", ownedSpace, member.Did).Error; err != nil {
		t.Fatalf("remote member repo was deleted: %v", err)
	}
	var remoteMember models.SimpleSpaceMember
	if err := s.db.First(ctx, &remoteMember, "space = ? AND did = ?", ownedSpace, member.Did).Error; err != nil {
		t.Fatalf("remote member state missing: %v", err)
	}
	if remoteMember.RemovedAt == nil {
		t.Fatal("remote member was not revoked with authority-space deletion")
	}
	var registrationCount int64
	if err := s.db.Client().Model(&models.SpaceNotifyRegistration{}).Where("space = ?", ownedSpace).Count(&registrationCount).Error; err != nil {
		t.Fatal(err)
	}
	if registrationCount != 0 {
		t.Fatalf("owned-space registrations remain: %d", registrationCount)
	}
	var deliveries []models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ?", ownedSpace).Find(&deliveries).Error; err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].Kind != SpaceNotifySpaceDeletedLXM || !deliveries[0].Deleted {
		t.Fatalf("owned-space deliveries = %+v, want only deletion delivery", deliveries)
	}
	if deliveries[0].Service != "did:web:active.example#space" {
		t.Fatalf("deletion delivery service = %q, want active registration", deliveries[0].Service)
	}
	var staleWriteCount int64
	if err := s.db.Client().Model(&models.SpaceNotifyDelivery{}).Where("author = ? AND kind = ?", owner.Did, SpaceNotifyWriteLXM).Count(&staleWriteCount).Error; err != nil {
		t.Fatal(err)
	}
	if staleWriteCount != 0 {
		t.Fatalf("stale owner write deliveries remain: %d", staleWriteCount)
	}
	var replay models.SpaceReplayJTI
	if err := s.db.First(ctx, &replay, "jti = ?", replayJTI).Error; err != nil {
		t.Fatalf("global replay row was removed: %v", err)
	}
	var retainedShared models.Blob
	if err := s.db.First(ctx, &retainedShared, "id = ?", sharedBlob.ID).Error; err != nil {
		t.Fatalf("shared permissioned blob was deleted: %v", err)
	}
	var retainedPublic models.Blob
	if err := s.db.First(ctx, &retainedPublic, "id = ?", publicBlob.ID).Error; err != nil {
		t.Fatalf("public-referenced blob was deleted: %v", err)
	}

	// Reopen the SQLite file in a fresh GORM handle to prove tombstone and
	// deletion outbox durability is not an in-memory test-server artifact.
	type sqliteDatabase struct {
		File string
	}
	var databases []sqliteDatabase
	if err := s.db.Client().Raw("PRAGMA database_list").Scan(&databases).Error; err != nil {
		t.Fatalf("database path: %v", err)
	}
	if len(databases) == 0 || databases[0].File == "" {
		t.Fatalf("database path unavailable: %+v", databases)
	}
	reopened, err := gorm.Open(sqlite.Open(databases[0].File), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	if sqlDB, err := reopened.DB(); err == nil {
		defer sqlDB.Close()
	}
	var reopenedTombstone models.SpaceTombstone
	if err := reopened.Where("space = ?", ownedSpace).First(&reopenedTombstone).Error; err != nil {
		t.Fatalf("reopened tombstone: %v", err)
	}
	var reopenedDeliveries []models.SpaceNotifyDelivery
	if err := reopened.Where("space = ?", ownedSpace).Find(&reopenedDeliveries).Error; err != nil {
		t.Fatalf("reopened deletion outbox: %v", err)
	}
	if len(reopenedDeliveries) != 1 || reopenedDeliveries[0].Kind != SpaceNotifySpaceDeletedLXM {
		t.Fatalf("reopened deliveries = %+v", reopenedDeliveries)
	}
}
