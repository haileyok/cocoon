package server

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

// migrateSpaceTables creates or updates the space tables.
//
// The experimental spaces support that was merged and then reverted (#125,
// #136) created space_records, space_repos and space_writers with different
// primary keys. AutoMigrate can't change a primary key, and it stops at the
// first table it fails on, so a PDS that ran that version was left without
// most of today's space tables. A table whose primary key columns don't
// match is renamed aside, keeping its rows, and recreated.
//
// Each table migrates on its own so one failure doesn't block the rest. All
// failures are returned together.
func migrateSpaceTables(db *gorm.DB, logger *slog.Logger) error {
	var errs []error
	for _, model := range models.SpaceModels() {
		if err := moveIncompatibleTable(db, model, logger); err != nil {
			errs = append(errs, fmt.Errorf("%T: %w", model, err))
			continue
		}
		if err := db.AutoMigrate(model); err != nil {
			errs = append(errs, fmt.Errorf("%T: %w", model, err))
		}
	}
	return errors.Join(errs...)
}

// moveIncompatibleTable renames model's table if it exists without all of the
// model's primary key columns.
func moveIncompatibleTable(db *gorm.DB, model any, logger *slog.Logger) error {
	m := db.Migrator()
	if !m.HasTable(model) {
		return nil
	}
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		return err
	}
	var missing []string
	for _, col := range stmt.Schema.PrimaryFieldDBNames {
		if !m.HasColumn(model, col) {
			missing = append(missing, col)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	table := stmt.Schema.Table
	legacy := fmt.Sprintf("%s_legacy_%d", table, time.Now().Unix())
	logger.Warn("moving aside a space table from an older version", "table", table, "renamed_to", legacy, "missing_columns", missing)
	if err := m.RenameTable(table, legacy); err != nil {
		return err
	}
	// Postgres keeps the primary key index's name with the renamed table,
	// which would clash with the new table's.
	if db.Dialector.Name() == "postgres" {
		if err := db.Exec(fmt.Sprintf(`ALTER INDEX IF EXISTS %q RENAME TO %q`, table+"_pkey", legacy+"_pkey")).Error; err != nil {
			return err
		}
	}
	return nil
}
