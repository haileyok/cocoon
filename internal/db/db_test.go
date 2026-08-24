package db

import (
	"context"
	"errors"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type transactionTestRow struct {
	ID    uint `gorm:"primaryKey"`
	Value string
}

func newTransactionTestDB(t *testing.T) *DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(t.TempDir()+"/transaction.db"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(&transactionTestRow{}); err != nil {
		t.Fatal(err)
	}
	return NewDB(gdb)
}

func TestTransactionCommitsCallbackWrites(t *testing.T) {
	db := newTransactionTestDB(t)
	ctx := context.Background()
	if err := db.Transaction(ctx, func(tx *DB) error {
		return tx.Create(ctx, &transactionTestRow{Value: "committed"}, nil).Error
	}); err != nil {
		t.Fatal(err)
	}

	var count int64
	if err := db.Client().Model(&transactionTestRow{}).Where("value = ?", "committed").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("committed row count = %d, want 1", count)
	}
}

func TestTransactionRollsBackCallbackWrites(t *testing.T) {
	db := newTransactionTestDB(t)
	ctx := context.Background()
	rollback := errors.New("rollback")
	err := db.Transaction(ctx, func(tx *DB) error {
		if err := tx.Create(ctx, &transactionTestRow{Value: "rolled-back"}, nil).Error; err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("Transaction error = %v, want %v", err, rollback)
	}

	var count int64
	if err := db.Client().Model(&transactionTestRow{}).Where("value = ?", "rolled-back").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back row count = %d, want 0", count)
	}
}
