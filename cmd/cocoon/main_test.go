package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/ipfs/go-cid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// setupTestDb creates a pre-migrated temp SQLite DB (the CLI never migrates;
// AutoMigrate runs only in server.New) and returns its path.
func setupTestDb(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "cocoon-cli-test.db")
	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gdb.AutoMigrate(
		&models.Actor{},
		&models.Repo{},
		&models.InviteCode{},
		&models.Token{},
		&models.RefreshToken{},
		&models.Block{},
		&models.Record{},
		&models.Blob{},
		&models.BlobPart{},
		&models.ReservedKey{},
		&provider.OauthToken{},
		&provider.OauthAuthorizationRequest{},
		&models.EventRecord{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	return path
}

// runCli builds the app with a captured writer and runs args (argv without
// argv[0]... actually including the "cocoon" program name).
func runCli(t *testing.T, args ...string) (string, *gorm.DB) {
	t.Helper()

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	app := newApp("test")
	app.Writer = &buf
	app.ErrWriter = &errBuf

	if err := app.Run(append([]string{"cocoon"}, args...)); err != nil {
		t.Fatalf("app.Run(%v): %v", args, err)
	}

	// reopen the db named on the command line for assertions
	dbName := ""
	for i, a := range args {
		if a == "--db-name" && i+1 < len(args) {
			dbName = args[i+1]
		}
	}
	gdb, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return buf.String(), gdb
}

func TestCreateInviteCodeJson(t *testing.T) {
	dbPath := setupTestDb(t)

	out, gdb := runCli(t, "--db-name", dbPath, "create-invite-code", "--json", "--uses", "3")

	var resp struct {
		Code string `json:"code"`
		Uses int    `json:"uses"`
		For  string `json:"for"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decode json output %q: %v", out, err)
	}
	if resp.Code == "" {
		t.Fatalf("expected non-empty code, got %q", out)
	}
	if resp.Uses != 3 {
		t.Fatalf("expected uses 3, got %d", resp.Uses)
	}
	if resp.For != "" {
		t.Fatalf("expected empty for, got %q", resp.For)
	}

	var row models.InviteCode
	if err := gdb.Where("code = ?", resp.Code).First(&row).Error; err != nil {
		t.Fatalf("load invite code row: %v", err)
	}
	if row.RemainingUseCount != 3 {
		t.Fatalf("expected remaining_use_count 3, got %d", row.RemainingUseCount)
	}
}

func TestCreateInviteCodeLegacyOutput(t *testing.T) {
	dbPath := setupTestDb(t)

	out, _ := runCli(t, "--db-name", dbPath, "create-invite-code")

	// byte-identical legacy shape: "New invite code created with N uses: CODE\n"
	if len(out) == 0 || out[:1] != "N" {
		t.Fatalf("expected legacy prose output, got %q", out)
	}
	var in struct {
		Uses int
		Code string
	}
	// proves it is NOT json
	if err := json.Unmarshal([]byte(out), &in); err == nil && in.Code != "" {
		t.Fatalf("expected non-json output, got %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("New invite code created with 1 uses: ")) {
		t.Fatalf("expected legacy sentence, got %q", out)
	}
}

func TestResetPasswordJson(t *testing.T) {
	dbPath := setupTestDb(t)

	did := "did:plc:resetpasstestabcdefg"
	seedRepo(t, dbPath, did, "badrev", nil)

	out, gdb := runCli(t, "--db-name", dbPath, "reset-password", "--json", "--did", did)

	var resp struct {
		Did      string `json:"did"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decode json output %q: %v", out, err)
	}
	if resp.Did != did {
		t.Fatalf("expected did %q, got %q", did, resp.Did)
	}
	if resp.Password == "" {
		t.Fatalf("expected non-empty password, got %q", out)
	}

	var row models.Repo
	if err := gdb.Where("did = ?", did).First(&row).Error; err != nil {
		t.Fatalf("load repo row: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(row.Password), []byte(resp.Password)); err != nil {
		t.Fatalf("stored password does not match reported password: %v", err)
	}
}

func TestResetPasswordLegacyOutput(t *testing.T) {
	dbPath := setupTestDb(t)

	did := "did:plc:resetpasslegacyabcdef"
	seedRepo(t, dbPath, did, "badrev", nil)

	out, _ := runCli(t, "--db-name", dbPath, "reset-password", "--did", did)

	if !bytes.Contains([]byte(out), []byte("Password for "+did+" has been reset to: ")) {
		t.Fatalf("expected legacy sentence, got %q", out)
	}
}

func TestRecommitReposJson(t *testing.T) {
	dbPath := setupTestDb(t)

	did := "did:plc:recommittestabcdefg"
	rootC, err := cid.Decode("bafyreib77klh3jlrqhxnp5g4bgnknpriegseaxa5uq5ktjcvmjn7vwdy4e")
	if err != nil {
		t.Fatalf("decode cid: %v", err)
	}
	seedRepo(t, dbPath, did, "badrev", rootC.Bytes())

	out, _ := runCli(t, "--db-name", dbPath, "recommit-repos", "--json", "--dids", did)

	var results []map[string]any
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("decode json output %q: %v", out, err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (%s)", len(results), out)
	}
	r := results[0]
	if r["did"] != did {
		t.Fatalf("expected did %q, got %v", did, r["did"])
	}
	if r["recommitted"] != true {
		t.Fatalf("expected recommitted true for invalid rev, got %v (result %v)", r["recommitted"], r)
	}
	if r["oldRev"] != "badrev" {
		t.Fatalf("expected oldRev badrev, got %v", r["oldRev"])
	}
	if r["err"] != "" && r["err"] != nil {
		t.Fatalf("expected no error in result, got %v", r["err"])
	}
}

// TestRecommitReposJsonStdoutPureUnderProductionErrWriter reproduces the
// production wiring — newApp sets ErrWriter to os.Stdout — and asserts the
// stdout payload still parses as JSON: banners and the migration logger must
// go to real stderr, never through App.ErrWriter.
func TestRecommitReposJsonStdoutPureUnderProductionErrWriter(t *testing.T) {
	dbPath := setupTestDb(t)

	did := "did:plc:recommitpurityabcdefg"
	rootC, err := cid.Decode("bafyreib77klh3jlrqhxnp5g4bgnknpriegseaxa5uq5ktjcvmjn7vwdy4e")
	if err != nil {
		t.Fatalf("decode cid: %v", err)
	}
	seedRepo(t, dbPath, did, "badrev", rootC.Bytes())

	var buf bytes.Buffer
	app := newApp("test")
	app.Writer = &buf
	// exactly the production mis-direction: ErrWriter == stdout target
	app.ErrWriter = &buf

	if err := app.Run([]string{"cocoon", "--db-name", dbPath, "recommit-repos", "--json", "--dids", did}); err != nil {
		t.Fatalf("app.Run: %v", err)
	}

	var results []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &results); err != nil {
		t.Fatalf("stdout is not pure JSON under production ErrWriter wiring: %q: %v", buf.String(), err)
	}
	if len(results) != 1 || results[0]["did"] != did {
		t.Fatalf("unexpected results: %s", buf.String())
	}
}

func seedRepo(t *testing.T, dbPath, did, rev string, root []byte) {
	t.Helper()

	gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() {
		if sqlDB, err := gdb.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()

	repo := models.Repo{
		Did:        did,
		CreatedAt:  time.Now(),
		Rev:        rev,
		Root:       root,
		SigningKey: []byte("not-a-real-key"),
	}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	actor := models.Actor{Did: did, Handle: did + ".test"}
	if err := gdb.Create(&actor).Error; err != nil {
		t.Fatalf("seed actor: %v", err)
	}
}
