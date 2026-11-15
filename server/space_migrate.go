package server

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	legacyErr := migrateSimplespace(db, logger)
	if legacyErr != nil {
		errs = append(errs, fmt.Errorf("simplespace tables: %w", legacyErr))
	}
	for _, model := range models.SpaceModels() {
		// Until the legacy tables are converted, don't create the tables that
		// replace them: an empty memberspace_members next to a legacy
		// simplespace_members would hide the rows from the next attempt.
		if legacyErr != nil {
			switch model.(type) {
			case *models.SpacePolicy, *models.MemberspaceMember:
				continue
			}
		}
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

// migrateSimplespace upgrades the tables of the October 22 alpha, as the
// reference's actor store migrations 006 to 009 do:
//
//   - each simplespace_configs row becomes a baseline policy in space_policies,
//     the member lists of spaces that become managedspaces are deleted, the
//     config table is dropped, and simplespace_members is renamed
//     memberspace_members;
//   - registerNotify registrations name a service rather than an endpoint and
//     have no token, so they can't be carried over: syncers re-register the
//     next time they authorize. They and the pending deletion notices queued
//     for them are dropped.
//
// Each step runs only if its legacy table is still there.
func migrateSimplespace(db *gorm.DB, logger *slog.Logger) error {
	m := db.Migrator()
	if m.HasTable("simplespace_configs") {
		if err := db.AutoMigrate(&models.SpacePolicy{}); err != nil {
			return err
		}
		err := db.Transaction(func(tx *gorm.DB) error {
			type config struct {
				Did              string
				Uri              string
				ReadPolicy       string
				ReadManagingApp  *string
				WritePolicy      string
				WriteManagingApp *string
				AppAccessType    string
				AppAllowed       string
			}
			var rows []config
			if err := tx.Table("simplespace_configs").Find(&rows).Error; err != nil {
				return err
			}
			members := "memberspace_members"
			if tx.Migrator().HasTable("simplespace_members") {
				members = "simplespace_members"
			}
			for _, c := range rows {
				policy := legacyConfigToPolicy(c.ReadPolicy, c.ReadManagingApp, c.WritePolicy, c.WriteManagingApp, c.AppAccessType, c.AppAllowed)
				j, err := policy.marshal()
				if err != nil {
					return err
				}
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SpacePolicy{Did: c.Did, Uri: c.Uri, PolicyJson: j}).Error; err != nil {
					return err
				}
				if !policy.isMember() && tx.Migrator().HasTable(members) {
					if err := tx.Exec("DELETE FROM "+members+" WHERE did = ? AND space = ?", c.Did, c.Uri).Error; err != nil {
						return err
					}
				}
				if (c.ReadManagingApp != nil || c.WriteManagingApp != nil) && (c.ReadPolicy != "managing-app" || c.WritePolicy != "managing-app" || c.AppAccessType != "open") {
					logger.Warn("a space with a mixed configuration changed access: its managing app is now asked about both reads and writes", "space", c.Uri, "managingApp", policy.ManagingApp)
				}
			}
			return tx.Migrator().DropTable("simplespace_configs")
		})
		if err != nil {
			return err
		}
	}
	if m.HasTable("simplespace_members") {
		if m.HasTable("memberspace_members") {
			// Both exist when a rename was interrupted. Keep every member, in
			// one transaction with the drop, so a failure can't leave a stale
			// legacy table that a later attempt would merge back.
			err := db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Exec("INSERT INTO memberspace_members (did, space, member_did, " + quoteCol(tx, "read") + ", " + quoteCol(tx, "write") + ") " +
					"SELECT s.did, s.space, s.member_did, s." + quoteCol(tx, "read") + ", s." + quoteCol(tx, "write") + " FROM simplespace_members s " +
					"WHERE NOT EXISTS (SELECT 1 FROM memberspace_members m WHERE m.did = s.did AND m.space = s.space AND m.member_did = s.member_did)").Error; err != nil {
					return err
				}
				return tx.Migrator().DropTable("simplespace_members")
			})
			if err != nil {
				return err
			}
		} else if err := m.RenameTable("simplespace_members", "memberspace_members"); err != nil {
			return err
		}
	}
	for _, table := range []string{"space_credential_recipients", "space_deleted_notification_retries"} {
		if m.HasTable(table) {
			if err := m.DropTable(table); err != nil {
				return err
			}
		}
	}
	return nil
}

func quoteCol(db *gorm.DB, name string) string {
	var b strings.Builder
	db.Dialector.QuoteTo(&b, name)
	return b.String()
}
