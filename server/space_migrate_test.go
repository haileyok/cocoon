package server

// The space table migration: bringing a live PDS's space tables up to date
// without losing the rows it holds.
//
// Nothing here ports a reference test. The reference applies its actor-store
// Kysely migrations (bluesky-social/atproto d4def6e9, actor-store/db/migrations
// 006-space-policy through 009-space-notify-registration) automatically at
// boot, so it has no such suite; Cocoon renames and recreates tables instead,
// and this file pins that behavior down.
//
// Two generations of legacy tables are covered:
//
//   - the reverted experimental spaces support (#125, #136), whose space_repos,
//     space_records and space_writers use different primary keys under the same
//     names;
//   - the October 22 alpha's simplespace tables (simplespace_configs,
//     simplespace_members, space_credential_recipients,
//     space_deleted_notification_retries), which migrateSimplespace converts
//     into today's space_policies and memberspace_members.

import (
	"encoding/json"
	"log/slog"
	"path/filepath"
	"reflect"
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

// The October 22 alpha's simplespace tables. Copied from that version's models.
type legacySimplespaceConfig struct {
	Did              string `gorm:"primaryKey"`
	Uri              string `gorm:"primaryKey"`
	ReadPolicy       string `gorm:"not null"`
	ReadManagingApp  *string
	WritePolicy      string `gorm:"not null"`
	WriteManagingApp *string
	AppAccessType    string `gorm:"not null"`
	AppAllowed       string `gorm:"not null"` // JSON array of client IDs
}

func (legacySimplespaceConfig) TableName() string { return "simplespace_configs" }

type legacySimplespaceMember struct {
	Did       string `gorm:"primaryKey"`
	Space     string `gorm:"primaryKey"`
	MemberDid string `gorm:"primaryKey"`
	Read      bool   `gorm:"not null"`
	Write     bool   `gorm:"not null"`
}

func (legacySimplespaceMember) TableName() string { return "simplespace_members" }

func openSpaceMigrateDB(t *testing.T) *gorm.DB {
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
	return gdb
}

func openLegacySpaceDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb := openSpaceMigrateDB(t)
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
func TestSpaceMigrateLegacyTablesBreakPlainAutoMigrate(t *testing.T) {
	gdb := openLegacySpaceDB(t)
	if err := gdb.AutoMigrate(models.SpaceModels()...); err == nil {
		t.Fatal("expected plain AutoMigrate to fail over the legacy tables")
	}
}

// The live PDS first ran #176's plain AutoMigrate over the legacy tables,
// which added uri to space_records before failing on did, so the table had
// today's primary key column but not its other required ones.
func TestSpaceMigrateAfterFailedPlainMigration(t *testing.T) {
	gdb := openLegacySpaceDB(t)
	_ = gdb.AutoMigrate(models.SpaceModels()...) // what #176 did; the error was ignored
	if !gdb.Migrator().HasColumn(&models.SpaceRecord{}, "uri") || gdb.Migrator().HasColumn(&models.SpaceRecord{}, "did") {
		t.Fatal("setup: expected space_records with uri but without did")
	}
	if err := migrateSpaceTables(gdb, slog.Default()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, model := range models.SpaceModels() {
		if !gdb.Migrator().HasTable(model) {
			t.Fatalf("table for %T was not created", model)
		}
	}
	rec := models.SpaceRecord{Uri: "at://x", Did: "did:plc:a", Space: "at://did:plc:a/space/t/s", Collection: "c", Rkey: "r", Cid: "bafy", Value: []byte{1}, RepoRev: "1", IndexedAt: "now"}
	if err := gdb.Create(&rec).Error; err != nil {
		t.Fatalf("space_records unusable: %v", err)
	}
	var got models.SpaceRecord
	if err := gdb.Where("did = ? AND uri = ?", rec.Did, rec.Uri).First(&got).Error; err != nil {
		t.Fatalf("query by did failed: %v", err)
	}
}

// A current table that only lacks a column a newer model requires is left
// for AutoMigrate, never moved aside: its rows are real data.
func TestSpaceMigrateKeepsCurrentTables(t *testing.T) {
	gdb := openLegacySpaceDB(t)
	if err := gdb.Migrator().DropTable(&legacySpaceRecord{}, &legacySpaceRepo{}, &legacySpaceWriter{}); err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec("CREATE TABLE space_used_jtis (namespace text, jti text, PRIMARY KEY (namespace, jti))").Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec("INSERT INTO space_used_jtis (namespace, jti) VALUES ('n', 'j')").Error; err != nil {
		t.Fatal(err)
	}
	_ = migrateSpaceTables(gdb, slog.Default())
	var n int64
	if err := gdb.Table("space_used_jtis").Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("current table was moved or emptied: n=%d err=%v", n, err)
	}
}

func TestSpaceMigrateMovesLegacyTablesAside(t *testing.T) {
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

// simplespaceFixtures is a legacy DB holding one space per config shape, plus
// the tables of the October 22 alpha that no longer exist.
type simplespaceFixtures struct {
	db   *gorm.DB
	apps map[string]string
}

func strp(s string) *string { return &s }

// openSimplespaceDB builds a database as the October 22 alpha left it.
func openSimplespaceDB(t *testing.T) *simplespaceFixtures {
	t.Helper()
	gdb := openSpaceMigrateDB(t)
	if err := gdb.AutoMigrate(&legacySimplespaceConfig{}, &legacySimplespaceMember{}); err != nil {
		t.Fatal(err)
	}
	// The two tables the November protocol dropped.
	for _, stmt := range []string{
		`CREATE TABLE space_credential_recipients (did text NOT NULL, space text NOT NULL, service_did text NOT NULL, service_endpoint text NOT NULL, expires_at text NOT NULL, PRIMARY KEY (did, space, service_did))`,
		`CREATE TABLE space_deleted_notification_retries (space text NOT NULL, service text NOT NULL, attempts integer NOT NULL, retry_at integer NOT NULL, expires_at integer NOT NULL, PRIMARY KEY (space, service))`,
		`INSERT INTO space_credential_recipients VALUES ('did:plc:authority', 'at://did:plc:authority/space/x/managed-read', 'did:plc:syncer', 'https://syncer.example', '2026-10-23T00:00:00.000Z')`,
		`INSERT INTO space_deleted_notification_retries VALUES ('at://did:plc:authority/space/x/managed-read', 'did:plc:syncer', 1, 1, 2)`,
	} {
		if err := gdb.Exec(stmt).Error; err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	const (
		authority = "did:plc:authority"
		appRead   = "did:plc:readapp#atproto_space"
		appWrite  = "did:plc:writeapp#atproto_space"
	)
	spaceOf := func(skey string) string {
		return "at://" + authority + "/space/com.example.group/" + skey
	}
	configs := []legacySimplespaceConfig{
		// A managing app on the read side.
		{Did: authority, Uri: spaceOf("managed-read"), ReadPolicy: "managing-app", ReadManagingApp: strp(appRead),
			WritePolicy: "managing-app", WriteManagingApp: strp(appRead), AppAccessType: "open", AppAllowed: "[]"},
		// A managing app on the write side only: it becomes the managing app of
		// a space that asks it about both reads and writes.
		{Did: authority, Uri: spaceOf("managed-write"), ReadPolicy: "public",
			WritePolicy: "managing-app", WriteManagingApp: strp(appWrite), AppAccessType: "open", AppAllowed: "[]"},
		// A member-list space that is neither public nor restricted by app.
		{Did: authority, Uri: spaceOf("members-private"), ReadPolicy: "member-list", WritePolicy: "member-list",
			AppAccessType: "open", AppAllowed: "[]"},
		// A public space with an app allow-list.
		{Did: authority, Uri: spaceOf("members-public"), ReadPolicy: "public", WritePolicy: "public",
			AppAccessType: "allowList", AppAllowed: `["https://app.example","did:web:app.example"]`},
		// A public space with an app allow-list stored as an empty array.
		{Did: authority, Uri: spaceOf("members-empty-allowlist"), ReadPolicy: "member-list", WritePolicy: "public",
			AppAccessType: "allowList", AppAllowed: "[]"},
	}
	for _, c := range configs {
		if err := gdb.Create(&c).Error; err != nil {
			t.Fatal(err)
		}
		for i, member := range []string{"did:plc:one", "did:plc:two"} {
			if err := gdb.Create(&legacySimplespaceMember{Did: authority, Space: c.Uri, MemberDid: member, Read: true, Write: i == 0}).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	return &simplespaceFixtures{
		db:   gdb,
		apps: map[string]string{"read": appRead, "write": appWrite},
	}
}

func (f *simplespaceFixtures) space(skey string) string {
	return "at://did:plc:authority/space/com.example.group/" + skey
}

// storedPolicies reads the migrated policies.
func (f *simplespaceFixtures) storedPolicies(t *testing.T) map[string]*spacePolicy {
	t.Helper()
	var rows []models.SpacePolicy
	if err := f.db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := make(map[string]*spacePolicy, len(rows))
	for _, r := range rows {
		p, err := parseStoredPolicy(r.PolicyJson)
		if err != nil {
			t.Fatalf("stored policy for %s: %v", r.Uri, err)
		}
		out[r.Uri] = p
	}
	return out
}

// members lists the member list's rows per space.
func (f *simplespaceFixtures) members(t *testing.T) map[string][]models.MemberspaceMember {
	t.Helper()
	var rows []models.MemberspaceMember
	if err := f.db.Order("space asc, member_did asc").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string][]models.MemberspaceMember{}
	for _, r := range rows {
		out[r.Space] = append(out[r.Space], r)
	}
	return out
}

// TestSpaceMigrateSimplespace ports the reference's actor-store migrations 006
// (simplespace_config -> space_policy, simplespace_member ->
// memberspace_member) and 009 (the registerNotify tables dropped): every
// config becomes a baseline policy, the member lists of the spaces that become
// managedspaces are dropped, and the tables that no longer exist go away.
func TestSpaceMigrateSimplespace(t *testing.T) {
	f := openSimplespaceDB(t)
	if err := migrateSpaceTables(f.db, slog.Default()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Each config became the baseline policy the migration names.
	want := map[string]*spacePolicy{
		f.space("managed-read"):            {Type: policyManaged, ManagingApp: f.apps["read"]},
		f.space("managed-write"):           {Type: policyManaged, ManagingApp: f.apps["write"]},
		f.space("members-private"):         {Type: policyMember},
		f.space("members-public"):          {Type: policyMember, PublicRead: true, PublicWrite: true, AllowedApps: []string{"https://app.example", "did:web:app.example"}},
		f.space("members-empty-allowlist"): {Type: policyMember, PublicWrite: true, AllowedApps: []string{}},
	}
	got := f.storedPolicies(t)
	if len(got) != len(want) {
		t.Fatalf("migrated %d policies, want %d: %+v", len(got), len(want), got)
	}
	for uri, expect := range want {
		if !reflect.DeepEqual(got[uri], expect) {
			t.Errorf("policy for %s = %+v, want %+v", uri, got[uri], expect)
		}
	}

	// An open space keeps no allowedApps at all, and a managedspace drops the
	// allow-list it could not enforce.
	var open models.SpacePolicy
	if err := f.db.Where("uri = ?", f.space("members-private")).Take(&open).Error; err != nil {
		t.Fatal(err)
	}
	var lex map[string]any
	if err := json.Unmarshal([]byte(open.PolicyJson), &lex); err != nil {
		t.Fatal(err)
	}
	if _, ok := lex["allowedApps"]; ok {
		t.Fatalf("an open space kept allowedApps: %s", open.PolicyJson)
	}

	// The member lists of the spaces that became managedspaces are gone: a
	// managedspace asks its app, so the list would be silently ignored.
	members := f.members(t)
	for _, skey := range []string{"managed-read", "managed-write"} {
		if len(members[f.space(skey)]) != 0 {
			t.Errorf("member list of the managedspace %s survived: %+v", skey, members[f.space(skey)])
		}
	}
	for _, skey := range []string{"members-private", "members-public", "members-empty-allowlist"} {
		want := []models.MemberspaceMember{
			{Did: "did:plc:authority", Space: f.space(skey), MemberDid: "did:plc:one", Read: true, Write: true},
			{Did: "did:plc:authority", Space: f.space(skey), MemberDid: "did:plc:two", Read: true, Write: false},
		}
		if !reflect.DeepEqual(members[f.space(skey)], want) {
			t.Errorf("member list of %s = %+v, want %+v", skey, members[f.space(skey)], want)
		}
	}

	// The tables of the October 22 alpha are gone, and today's are all there.
	m := f.db.Migrator()
	for _, table := range []string{"simplespace_configs", "simplespace_members", "space_credential_recipients", "space_deleted_notification_retries"} {
		if m.HasTable(table) {
			t.Errorf("%s was not dropped", table)
		}
	}
	for _, model := range models.SpaceModels() {
		if !m.HasTable(model) {
			t.Errorf("table for %T was not created", model)
		}
	}

	// Running again (every startup) changes nothing.
	before := map[string]string{}
	var rows []models.SpacePolicy
	if err := f.db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		before[r.Uri] = r.PolicyJson
	}
	if err := migrateSpaceTables(f.db, slog.Default()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if after := f.storedPolicies(t); !reflect.DeepEqual(after, got) {
		t.Fatalf("a second migration changed the policies:\n%+v\n%+v", after, got)
	}
	var policyRows []models.SpacePolicy
	if err := f.db.Find(&policyRows).Error; err != nil {
		t.Fatal(err)
	}
	for _, r := range policyRows {
		if before[r.Uri] != r.PolicyJson {
			t.Fatalf("a second migration rewrote the policy of %s", r.Uri)
		}
	}
	if after := f.members(t); !reflect.DeepEqual(after, members) {
		t.Fatalf("a second migration changed the member lists:\n%+v\n%+v", after, members)
	}
}

// TestSpaceMigrateSimplespaceBothMemberTables covers a database that already
// has memberspace_members when it still has simplespace_members, as when an
// earlier attempt was interrupted: no member is lost, the legacy rows join the
// current table's, and the current rows win a conflict.
func TestSpaceMigrateSimplespaceBothMemberTables(t *testing.T) {
	f := openSimplespaceDB(t)
	if err := f.db.AutoMigrate(&models.MemberspaceMember{}); err != nil {
		t.Fatal(err)
	}
	current := models.MemberspaceMember{Did: "did:plc:authority", Space: f.space("members-private"), MemberDid: "did:plc:current", Read: true, Write: true}
	if err := f.db.Create(&current).Error; err != nil {
		t.Fatal(err)
	}

	if err := migrateSpaceTables(f.db, slog.Default()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if f.db.Migrator().HasTable("simplespace_members") {
		t.Fatal("simplespace_members was not dropped")
	}
	got := f.members(t)[f.space("members-private")]
	dids := map[string]models.MemberspaceMember{}
	for _, m := range got {
		dids[m.MemberDid] = m
	}
	if len(got) != 3 || dids["did:plc:current"] != current || !dids["did:plc:one"].Write || dids["did:plc:two"].Write {
		t.Fatalf("member list of the member space = %+v, want the current row %+v and both legacy members", got, current)
	}
}

// TestSpaceMigrateSimplespaceWithoutConfigs covers a database from the
// October 22 alpha that kept its member list but lost its config table: the
// rename still happens.
func TestSpaceMigrateSimplespaceWithoutConfigs(t *testing.T) {
	gdb := openSpaceMigrateDB(t)
	if err := gdb.AutoMigrate(&legacySimplespaceMember{}); err != nil {
		t.Fatal(err)
	}
	spaceURI := "at://did:plc:authority/space/com.example.group/no-config"
	if err := gdb.Create(&legacySimplespaceMember{Did: "did:plc:authority", Space: spaceURI, MemberDid: "did:plc:one", Read: true, Write: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err := migrateSpaceTables(gdb, slog.Default()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if gdb.Migrator().HasTable("simplespace_members") {
		t.Fatal("simplespace_members was not renamed")
	}
	var n int64
	if err := gdb.Model(&models.MemberspaceMember{}).Where("space = ?", spaceURI).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("member row did not survive the rename: n=%d err=%v", n, err)
	}
}
