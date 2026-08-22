package models

import (
	"bytes"
	"path/filepath"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func openSpaceSchemaDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "spaces.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

func TestSpaceModelsMigrateSQLite(t *testing.T) {
	db := openSpaceSchemaDB(t)

	if err := db.AutoMigrate(SpaceModels()...); err != nil {
		t.Fatalf("migrate space models: %v", err)
	}
	for _, model := range SpaceModels() {
		if !db.Migrator().HasTable(model) {
			t.Errorf("missing table for %T", model)
		}
	}
	if !db.Migrator().HasIndex(&SpaceRepo{}, "idx_space_repos_space_author") {
		t.Error("missing SpaceRepo space/author index")
	}
}

func TestSpaceCompositeKeysIsolateSpacesAndAuthors(t *testing.T) {
	db := openSpaceSchemaDB(t)
	if err := db.AutoMigrate(SpaceModels()...); err != nil {
		t.Fatalf("migrate space models: %v", err)
	}

	state := bytes.Repeat([]byte{0x5a}, 2048)
	rows := []SpaceRepo{
		{Space: "at://did:example:authority/space/com.example/one", Author: "did:example:alice", Rev: "r1", LtHash: state},
		{Space: "at://did:example:authority/space/com.example/two", Author: "did:example:alice", Rev: "r1", LtHash: state},
		{Space: "at://did:example:authority/space/com.example/one", Author: "did:example:bob", Rev: "r1", LtHash: state},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("create isolated repos: %v", err)
	}

	var count int64
	if err := db.Model(&SpaceRepo{}).Count(&count).Error; err != nil {
		t.Fatalf("count repos: %v", err)
	}
	if count != int64(len(rows)) {
		t.Fatalf("repo count = %d, want %d", count, len(rows))
	}

	var gotRepo SpaceRepo
	if err := db.First(&gotRepo, "space = ? AND author = ?", rows[0].Space, rows[0].Author).Error; err != nil {
		t.Fatalf("read repo: %v", err)
	}
	if !bytes.Equal(gotRepo.LtHash, state) {
		t.Fatalf("LtHash state changed during persistence: got %d bytes, want %d", len(gotRepo.LtHash), len(state))
	}

	duplicate := rows[0]
	if err := db.Create(&duplicate).Error; err == nil {
		t.Fatal("duplicate space/author repo was accepted")
	}

	records := []SpaceRecord{
		{Space: rows[0].Space, Author: rows[0].Author, Collection: "com.example.post", Rkey: "one", CID: "cid-a", CanonicalCBOR: []byte{0xa1, 0x61, 0x61, 0x01}},
		{Space: rows[1].Space, Author: rows[1].Author, Collection: "com.example.post", Rkey: "one", CID: "cid-b", CanonicalCBOR: []byte{0xa1, 0x61, 0x61, 0x02}},
	}
	if err := db.Create(&records).Error; err != nil {
		t.Fatalf("create isolated records: %v", err)
	}
}

func TestSpaceRepoOpCIDsAreNullable(t *testing.T) {
	db := openSpaceSchemaDB(t)
	if err := db.AutoMigrate(SpaceModels()...); err != nil {
		t.Fatalf("migrate space models: %v", err)
	}

	op := SpaceRepoOp{
		Space:      "at://did:example:authority/space/com.example/one",
		Author:     "did:example:alice",
		Rev:        "r1",
		Idx:        0,
		Collection: "com.example.post",
		Rkey:       "one",
	}
	if err := db.Create(&op).Error; err != nil {
		t.Fatalf("create op with nil CIDs: %v", err)
	}

	var got SpaceRepoOp
	if err := db.First(&got, "space = ? AND author = ? AND rev = ? AND idx = ?", op.Space, op.Author, op.Rev, op.Idx).Error; err != nil {
		t.Fatalf("read op: %v", err)
	}
	if got.CurrentCID != nil || got.PreviousCID != nil {
		t.Fatalf("nil CIDs were not preserved: current=%v previous=%v", got.CurrentCID, got.PreviousCID)
	}
}

func TestSpaceTombstoneIsUnique(t *testing.T) {
	db := openSpaceSchemaDB(t)
	if err := db.AutoMigrate(SpaceModels()...); err != nil {
		t.Fatalf("migrate space models: %v", err)
	}

	tombstone := SpaceTombstone{Space: "at://did:example:authority/space/com.example/one"}
	if err := db.Create(&tombstone).Error; err != nil {
		t.Fatalf("create tombstone: %v", err)
	}
	if err := db.Create(&tombstone).Error; err == nil {
		t.Fatal("duplicate space tombstone was accepted")
	}
}
