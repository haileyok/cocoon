package server

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/google/uuid"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func localLexiconTestServer(t *testing.T) (*Server, *testAccount) {
	t.Helper()
	s := newTestServer(t)
	s.evtman = s.newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "lexicon.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
	return s, acct
}

func putLocalLexicon(t *testing.T, s *Server, acct *testAccount, nsid, title string) []byte {
	t.Helper()
	record := MarshalableMap{
		"$type": "com.atproto.lexicon.schema", "lexicon": int64(1), "id": nsid,
		"defs": map[string]any{"main": map[string]any{"type": "permission-set", "title": title, "permissions": []any{}}},
	}
	mustApply(t, s, acct.Did, Op{Type: OpTypeCreate, Collection: "com.atproto.lexicon.schema", Rkey: strPtr(nsid), Record: &record})
	raw, err := atdata.MarshalCBOR(record)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadLocalLexiconCommittedAccounts(t *testing.T) {
	s, alice := localLexiconTestServer(t)
	bob := s.createTestAccount(t, "otherlexicon.pds.test")
	s.seedGenesisRepo(t, bob.Did, bob.SigningKey)
	wants := map[string][]byte{}
	for _, acct := range []*testAccount{alice, bob} {
		wants[acct.Did] = putLocalLexicon(t, s, acct, "com.example.lexicon", acct.Handle)
	}
	for _, acct := range []*testAccount{alice, bob} {
		got, hosted, err := s.readLocalLexicon(t.Context(), syntax.DID(acct.Did), "com.example.lexicon")
		if err != nil || !hosted || !bytes.Equal(wants[acct.Did], got) {
			t.Fatalf("%s: hosted=%v err=%v record=%s", acct.Handle, hosted, err, got)
		}
	}
	// Bob must not get Alice's declaration at a different rkey.
	putLocalLexicon(t, s, alice, "com.example.alice", "Alice only")
	if raw, hosted, err := s.readLocalLexicon(t.Context(), syntax.DID(bob.Did), "com.example.alice"); err == nil || !hosted || raw != nil {
		t.Fatalf("cross-account lookup: hosted=%v err=%v record=%s", hosted, err, raw)
	}
	if raw, hosted, err := s.readLocalLexicon(t.Context(), "did:plc:abcdefghijklmnopqrstuvwx", "com.example.lexicon"); err != nil || hosted || raw != nil {
		t.Fatalf("remote account: hosted=%v err=%v record=%s", hosted, err, raw)
	}
}

func TestReadLocalLexiconFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing", "deactivated", "taken down", "bad root", "uncommitted index", "mismatched index", "missing index", "missing block", "tampered block", "database error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			s, acct := localLexiconTestServer(t)
			putLocalLexicon(t, s, acct, "com.example.lexicon", "Original")
			ctx := t.Context()
			nsid := syntax.NSID("com.example.lexicon")
			var record models.Record
			if err := s.db.Client().Where("did = ? AND nsid = ? AND rkey = ?", acct.Did, "com.atproto.lexicon.schema", nsid).First(&record).Error; err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "missing":
				nsid = "com.example.missing"
			case "deactivated":
				err = s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Update("deactivated", true).Error
			case "taken down":
				err = s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Update("takedown_ref", "test").Error
			case "bad root":
				err = s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Update("root", []byte("invalid")).Error
			case "uncommitted index":
				nsid = "com.example.uncommitted"
				record.Rkey = nsid.String()
				err = s.db.Client().Create(&record).Error
			case "mismatched index":
				err = s.db.Client().Model(&record).Update("cid", "different").Error
			case "missing index":
				err = s.db.Client().Delete(&record).Error
			case "missing block":
				err = s.db.Client().Where("did = ?", acct.Did).Delete(&models.Block{}).Error
			case "tampered block":
				err = s.db.Client().Model(&models.Block{}).Where("did = ? AND value = ?", acct.Did, record.Value).Update("value", []byte{0xa0}).Error
			case "database error":
				err = s.db.Client().Migrator().DropTable(&models.Record{})
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, hosted, err := s.readLocalLexicon(ctx, syntax.DID(acct.Did), nsid)
			if err == nil || raw != nil {
				t.Fatalf("%s: hosted=%v err=%v record=%x", mode, hosted, err, raw)
			}
			if mode != "canceled" && !hosted {
				t.Fatalf("local failure reported as remote: %v", err)
			}
		})
	}
}

func TestReadLocalLexiconPostgresConcurrentCommit(t *testing.T) {
	dsn := os.Getenv("COCOON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set COCOON_TEST_POSTGRES_DSN to run the PostgreSQL snapshot regression")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid COCOON_TEST_POSTGRES_DSN") // Do not print credentials.
	}
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = admin.Close() })
	// Never migrate, replace, or drop shared tables. CREATE without IF NOT
	// EXISTS guarantees ownership of a fresh schema, even on a shared test DB.
	schemaName := "cocoon_lexicon_" + uuid.New().String()
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()
	if _, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("remove isolated test schema: %v", err)
		}
	})
	// Apply the isolated search path to every connection, not just the first
	// pooled connection. No public or caller-supplied schema is a fallback.
	cfg.RuntimeParams["search_path"] = quotedSchema
	cfg.RuntimeParams["default_transaction_isolation"] = "read committed"
	pool := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = pool.Close() })
	pg, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	var currentSchema string
	if err := pg.Raw("SELECT current_schema()").Scan(&currentSchema).Error; err != nil || currentSchema != schemaName {
		t.Fatalf("isolated schema not selected: schema=%q err=%v", currentSchema, err)
	}
	if err := pg.AutoMigrate(&models.Repo{}, &models.Record{}, &models.Block{}); err != nil {
		t.Fatal(err)
	}

	source, acct := localLexiconTestServer(t)
	want := putLocalLexicon(t, source, acct, "com.example.lexicon", "Original")
	// Build both committed states through the existing write helpers, then
	// publish each atomically on another PostgreSQL connection. The second
	// state no longer contains the superseded commit/tree blocks.
	copySnapshot := func() error {
		var account models.Repo
		var records []models.Record
		var blocks []models.Block
		for _, dest := range []any{&account, &records, &blocks} {
			if err := source.db.Client().Where("did = ?", acct.Did).Find(dest).Error; err != nil {
				return err
			}
		}
		return pg.Transaction(func(tx *gorm.DB) error {
			for _, model := range []any{&models.Record{}, &models.Block{}} {
				if err := tx.Where("did = ?", acct.Did).Delete(model).Error; err != nil {
					return err
				}
			}
			if err := tx.Save(&account).Error; err != nil {
				return err
			}
			for _, model := range []any{&records, &blocks} {
				if err := tx.Create(model).Error; err != nil {
					return err
				}
			}
			return nil
		})
	}
	if err := copySnapshot(); err != nil {
		t.Fatal(err)
	}
	local := &Server{db: db.NewDB(pg)}
	assertReadable := func(stage string) {
		t.Helper()
		got, hosted, err := local.readLocalLexicon(t.Context(), syntax.DID(acct.Did), "com.example.lexicon")
		if err != nil || !hosted || !bytes.Equal(got, want) {
			t.Errorf("%s: unchanged lexicon unavailable: hosted=%v err=%v record=%x", stage, hosted, err, got)
		}
	}
	assertReadable("before unrelated commit")
	post := MarshalableMap{"$type": "app.bsky.feed.post", "text": "unrelated update"}
	mustApply(t, source, acct.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("unrelated"), Record: &post})
	// Force publication after the reader captures the old root, but before
	// it reads the index or blocks. No timing sleeps or isolation assertions.
	fired := false
	if err := pg.Callback().Query().After("gorm:query").Register("local_lexicon_concurrent_commit", func(tx *gorm.DB) {
		if !fired && tx.Statement.Table == "repos" {
			fired = true
			if err := copySnapshot(); err != nil {
				tx.AddError(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	assertReadable("during unrelated commit")
	if !fired {
		t.Fatal("concurrent commit was not exercised")
	}
	assertReadable("after unrelated commit")
}
