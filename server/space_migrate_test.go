package server

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Tables left by the experimental spaces support that was merged and then
// reverted (#125, #136), with the same names as today's tables but different
// keys. Copied from that version's models.
type legacySpaceRepo struct {
	Space     string     `gorm:"primaryKey;index:idx_space_repos_space_author"`
	Author    string     `gorm:"primaryKey;index:idx_space_repos_space_author"`
	Rev       string     `gorm:"index:idx_space_repos_rev,sort:desc"`
	LtHash    []byte     `gorm:"not null"`
	Status    string     `gorm:"index:idx_space_repos_status"`
	Deleted   bool       `gorm:"index:idx_space_repos_deleted"`
	DeletedAt *time.Time `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (legacySpaceRepo) TableName() string { return "space_repos" }

type legacySpaceRecord struct {
	Space         string `gorm:"primaryKey;index:idx_space_records_space_author"`
	Author        string `gorm:"primaryKey;index:idx_space_records_space_author"`
	Collection    string `gorm:"primaryKey;index:idx_space_records_record"`
	Rkey          string `gorm:"primaryKey;index:idx_space_records_record"`
	CID           string `gorm:"column:cid"`
	CanonicalCBOR []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (legacySpaceRecord) TableName() string { return "space_records" }

type legacySpaceWriter struct {
	Space          string `gorm:"primaryKey;index:idx_space_writers_space"`
	Author         string `gorm:"primaryKey;index:idx_space_writers_space"`
	Host           string
	Rev            string
	Hash           []byte
	LastNotifiedAt *time.Time `gorm:"index"`
	Status         string     `gorm:"index:idx_space_writers_status"`
	DeletedAt      *time.Time `gorm:"index"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (legacySpaceWriter) TableName() string { return "space_writers" }

func openLegacySpaceDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "legacy.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := gdb.AutoMigrate(&legacySpaceRepo{}, &legacySpaceRecord{}, &legacySpaceWriter{}); err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&legacySpaceRecord{Space: "at://did:plc:old/space/x/y", Author: "did:plc:old", Collection: "c", Rkey: "r", CID: "bafyold"}).Error; err != nil {
		t.Fatal(err)
	}
	return gdb
}

// A PDS that ran the reverted experiment can't create today's space tables
// with a plain AutoMigrate, which is what left a live PDS without
// space_used_jtis (credential exchange failed with a 500).
func TestLegacySpaceTablesBreakPlainAutoMigrate(t *testing.T) {
	gdb := openLegacySpaceDB(t)
	if err := gdb.AutoMigrate(models.SpaceModels()...); err == nil {
		t.Fatal("expected plain AutoMigrate to fail over the legacy tables")
	}
}

func TestMigrateSpaceTablesMovesLegacyTablesAside(t *testing.T) {
	gdb := openLegacySpaceDB(t)
	if err := migrateSpaceTables(gdb, slog.Default()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	m := gdb.Migrator()
	for _, model := range models.SpaceModels() {
		if !m.HasTable(model) {
			t.Fatalf("table for %T was not created", model)
		}
	}
	for _, col := range []string{"uri", "did"} {
		if !m.HasColumn(&models.SpaceRecord{}, col) {
			t.Fatalf("space_records is missing %s", col)
		}
	}

	// The old rows survive in a renamed table.
	var legacy []string
	if err := gdb.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'space_records_legacy%'").Scan(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if len(legacy) != 1 {
		t.Fatalf("expected one renamed legacy space_records table, got %v", legacy)
	}
	var n int64
	if err := gdb.Table(legacy[0]).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("legacy rows not preserved: n=%d err=%v", n, err)
	}

	// Today's tables work, including the one the live failure hit.
	if err := gdb.Create(&models.SpaceUsedJti{Namespace: "delegation:did:plc:a", Jti: "j", ExpiresAt: 1}).Error; err != nil {
		t.Fatalf("space_used_jtis unusable: %v", err)
	}
	rec := models.SpaceRecord{Uri: "at://x", Did: "did:plc:a", Space: "at://did:plc:a/space/t/s", Collection: "c", Rkey: "r", Cid: "bafy", Value: []byte{1}, RepoRev: "1", IndexedAt: "now"}
	if err := gdb.Create(&rec).Error; err != nil {
		t.Fatalf("space_records unusable: %v", err)
	}

	// Running again (every startup) changes nothing.
	if err := migrateSpaceTables(gdb, slog.Default()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := gdb.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'space_%legacy%'").Scan(&legacy).Error; err != nil || len(legacy) != 3 {
		t.Fatalf("expected the three legacy tables once each, got %v (err %v)", legacy, err)
	}
}
