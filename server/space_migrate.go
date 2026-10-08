package server

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
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

// moveIncompatibleTable renames model's table if it is a different table
// under the same name: it lacks a column the model requires (a primary key,
// or NOT NULL without a default, which AutoMigrate can't add to a table with
// rows) and has columns the model doesn't know. A table that only lacks a
// newly required column is left alone, since its rows are real data.
func moveIncompatibleTable(db *gorm.DB, model any, logger *slog.Logger) error {
	m := db.Migrator()
	if !m.HasTable(model) {
		return nil
	}
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		return err
	}
	// Read the real column list; the SQLite driver's HasColumn only
	// pattern-matches the table's CREATE statement.
	cols, err := m.ColumnTypes(model)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(cols))
	for _, c := range cols {
		have[strings.ToLower(c.Name())] = true
	}
	var missing, unknown []string
	for _, f := range stmt.Schema.Fields {
		if f.DBName == "" {
			continue
		}
		required := f.PrimaryKey || (f.NotNull && !f.HasDefaultValue)
		if required && !have[strings.ToLower(f.DBName)] {
			missing = append(missing, f.DBName)
		}
	}
	for _, c := range cols {
		if stmt.Schema.LookUpField(c.Name()) == nil {
			unknown = append(unknown, c.Name())
		}
	}
	if len(missing) == 0 || len(unknown) == 0 {
		return nil
	}

	table := stmt.Schema.Table
	legacy := fmt.Sprintf("%s_legacy_%d", table, time.Now().Unix())
	logger.Warn("moving aside a space table from an older version", "table", table, "renamed_to", legacy, "missing_columns", missing, "unknown_columns", unknown)
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
