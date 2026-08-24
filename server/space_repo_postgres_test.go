package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/haileyok/cocoon/space"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var postgresSpaceSchemaSequence atomic.Uint64

type postgresSpaceRepoFixture struct {
	server *Server
	db     *gorm.DB
	dsn    string
	schema string
}

// newPostgresSpaceRepoFixture creates an isolated PostgreSQL schema for one
// test. The search_path is part of the connection DSN so every pooled
// connection, including concurrent-write connections, targets the test schema.
func newPostgresSpaceRepoFixture(t *testing.T) *postgresSpaceRepoFixture {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("COCOON_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("COCOON_TEST_POSTGRES_DSN is not set")
	}

	schema := fmt.Sprintf("cocoon_test_%d_%d_%d", os.Getpid(), time.Now().UnixNano(), postgresSpaceSchemaSequence.Add(1))
	admin, err := gorm.Open(postgres.Open(dsn), postgresTestGORMConfig())
	if err != nil {
		t.Fatalf("open postgres admin connection: %v", err)
	}
	adminSQL, err := admin.DB()
	if err != nil {
		t.Fatalf("get postgres admin connection: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + postgresQuoteIdentifier(schema)).Error; err != nil {
		_ = adminSQL.Close()
		t.Fatalf("create postgres schema %q: %v", schema, err)
	}
	if err := adminSQL.Close(); err != nil {
		t.Fatalf("close postgres admin connection: %v", err)
	}

	schemaDSN, err := postgresDSNWithSearchPath(dsn, schema)
	if err != nil {
		t.Fatalf("configure postgres search_path: %v", err)
	}

	var gdb *gorm.DB
	t.Cleanup(func() {
		if gdb != nil {
			if sqlDB, err := gdb.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
		cleanupDB, err := gorm.Open(postgres.Open(dsn), postgresTestGORMConfig())
		if err != nil {
			t.Errorf("open postgres cleanup connection: %v", err)
			return
		}
		if err := cleanupDB.Exec("DROP SCHEMA " + postgresQuoteIdentifier(schema) + " CASCADE").Error; err != nil {
			t.Errorf("drop postgres schema %q: %v", schema, err)
		}
		if sqlDB, err := cleanupDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	gdb, err = gorm.Open(postgres.Open(schemaDSN), postgresTestGORMConfig())
	if err != nil {
		t.Fatalf("open postgres test connection: %v", err)
	}
	if sqlDB, err := gdb.DB(); err != nil {
		t.Fatalf("get postgres test connection: %v", err)
	} else {
		sqlDB.SetMaxOpenConns(32)
		sqlDB.SetMaxIdleConns(32)
	}
	if err := gdb.Exec("SET search_path TO " + postgresQuoteIdentifier(schema)).Error; err != nil {
		t.Fatalf("set postgres search_path: %v", err)
	}

	migrationModels := []any{
		&models.Actor{},
		&models.Repo{},
		&models.InviteCode{},
		&models.Token{},
		&models.RefreshToken{},
		&models.Block{},
		&models.Record{},
		&models.Blob{},
		&models.BlobPart{},
		&models.BlobDeletion{},
		&models.ReservedKey{},
		&provider.OauthToken{},
		&provider.OauthAuthorizationRequest{},
	}
	migrationModels = append(migrationModels, models.SpaceModels()...)
	if err := gdb.AutoMigrate(migrationModels...); err != nil {
		t.Fatalf("migrate postgres test schema: %v", err)
	}

	return &postgresSpaceRepoFixture{
		server: &Server{db: db.NewDB(gdb)},
		db:     gdb,
		dsn:    schemaDSN,
		schema: schema,
	}
}

func postgresTestGORMConfig() *gorm.Config {
	return &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)}
}

func postgresQuoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func postgresDSNWithSearchPath(dsn, schema string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err == nil && parsed.Scheme != "" {
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		return parsed.String(), nil
	}
	if strings.Contains(dsn, "://") {
		return "", fmt.Errorf("parse postgres URL: %w", err)
	}
	if strings.TrimSpace(dsn) == "" {
		return "", errors.New("empty postgres DSN")
	}
	return strings.TrimSpace(dsn) + " search_path=" + schema, nil
}

func postgresSpaceRecord(text string) map[string]any {
	return map[string]any{
		"$type":     "com.example.post",
		"text":      text,
		"createdAt": "2024-01-01T00:00:00Z",
	}
}

const (
	postgresSpaceRef = "at://did:example:authority/space/com.example.space/space"
	postgresAuthor   = "did:example:alice"
)

func TestPostgresSpaceRepoCompositeIdentityIsolation(t *testing.T) {
	fixture := newPostgresSpaceRepoFixture(t)
	manager := NewSpaceRepoMan(fixture.server)
	ctx := context.Background()
	pairs := []struct {
		space  string
		author string
		text   string
	}{
		{postgresSpaceRef, postgresAuthor, "space-author-one"},
		{postgresSpaceRef, "did:example:bob", "space-author-two"},
		{"at://did:example:authority/space/com.example.space/other", postgresAuthor, "space-author-three"},
	}
	wantCID := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		batch, err := manager.Apply(ctx, pair.space, pair.author, []SpaceRepoOperation{{
			Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "same", Record: postgresSpaceRecord(pair.text),
		}})
		if err != nil {
			t.Fatalf("create %s/%s: %v", pair.space, pair.author, err)
		}
		wantCID[pair.space+"\x00"+pair.author] = batch.Changes[0].CID
	}

	for _, pair := range pairs {
		row, err := manager.GetRecord(ctx, pair.space, pair.author, "com.example.post", "same")
		if err != nil {
			t.Fatalf("get %s/%s: %v", pair.space, pair.author, err)
		}
		if row.CID != wantCID[pair.space+"\x00"+pair.author] {
			t.Fatalf("record %s/%s CID = %q, want %q", pair.space, pair.author, row.CID, wantCID[pair.space+"\x00"+pair.author])
		}
	}

	var repoCount int64
	if err := fixture.db.Model(&models.SpaceRepo{}).Count(&repoCount).Error; err != nil {
		t.Fatalf("count isolated repos: %v", err)
	}
	if repoCount != int64(len(pairs)) {
		t.Fatalf("isolated repo count = %d, want %d", repoCount, len(pairs))
	}
	var recordCount int64
	if err := fixture.db.Model(&models.SpaceRecord{}).Count(&recordCount).Error; err != nil {
		t.Fatalf("count isolated records: %v", err)
	}
	if recordCount != int64(len(pairs)) {
		t.Fatalf("isolated record count = %d, want %d", recordCount, len(pairs))
	}
}

func TestPostgresSpaceRepoNullableCIDPrevSemantics(t *testing.T) {
	fixture := newPostgresSpaceRepoFixture(t)
	manager := NewSpaceRepoMan(fixture.server)
	ctx := context.Background()

	created, err := manager.Apply(ctx, postgresSpaceRef, postgresAuthor, []SpaceRepoOperation{{
		Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "first", Record: postgresSpaceRecord("one"),
	}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := manager.Apply(ctx, postgresSpaceRef, postgresAuthor, []SpaceRepoOperation{
		{Type: SpaceRepoOpUpdate, Collection: "com.example.post", Rkey: "first", Record: postgresSpaceRecord("two")},
		{Type: SpaceRepoOpDelete, Collection: "com.example.post", Rkey: "first"},
	})
	if err != nil {
		t.Fatalf("update+delete batch: %v", err)
	}
	if created.Rev == updated.Rev || len(updated.Changes) != 2 {
		t.Fatalf("unexpected revisions/changes: created=%+v updated=%+v", created, updated)
	}

	var ops []models.SpaceRepoOp
	if err := fixture.db.Where("space = ? AND author = ?", postgresSpaceRef, postgresAuthor).Order("rev ASC, idx ASC").Find(&ops).Error; err != nil {
		t.Fatalf("load ops: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("op count = %d, want 3", len(ops))
	}
	if ops[0].CurrentCID == nil || ops[0].PreviousCID != nil {
		t.Fatalf("create CID nullability = current %v previous %v", ops[0].CurrentCID, ops[0].PreviousCID)
	}
	if ops[1].CurrentCID == nil || ops[1].PreviousCID == nil {
		t.Fatalf("update CID nullability = current %v previous %v", ops[1].CurrentCID, ops[1].PreviousCID)
	}
	if ops[2].CurrentCID != nil || ops[2].PreviousCID == nil {
		t.Fatalf("delete CID nullability = current %v previous %v", ops[2].CurrentCID, ops[2].PreviousCID)
	}
	if _, err := manager.GetRecord(ctx, postgresSpaceRef, postgresAuthor, "com.example.post", "first"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("deleted record lookup error = %v, want not found", err)
	}
}

func TestPostgresSpaceRepoAtomicRollback(t *testing.T) {
	stages := []SpaceRepoFailureStage{
		SpaceRepoFailureAfterRepoCreation,
		SpaceRepoFailureAfterRecordMutation,
		SpaceRepoFailureAfterBlobMutation,
		SpaceRepoFailureAfterOplogInsertion,
		SpaceRepoFailureAfterHeadUpdate,
	}
	for _, stage := range stages {
		t.Run(string(stage), func(t *testing.T) {
			fixture := newPostgresSpaceRepoFixture(t)
			manager := NewSpaceRepoMan(fixture.server)
			ctx := context.Background()
			if stage != SpaceRepoFailureAfterRepoCreation {
				if _, err := manager.Apply(ctx, postgresSpaceRef, postgresAuthor, []SpaceRepoOperation{{
					Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "seed", Record: postgresSpaceRecord("seed"),
				}}); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			restore := manager.SetFailureStage(stage)
			defer restore()
			if _, err := manager.Apply(ctx, postgresSpaceRef, postgresAuthor, []SpaceRepoOperation{{
				Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "new", Record: postgresSpaceRecord("new"),
			}}); err == nil {
				t.Fatalf("stage %s did not fail", stage)
			}

			var repos []models.SpaceRepo
			if err := fixture.db.Where("space = ? AND author = ?", postgresSpaceRef, postgresAuthor).Find(&repos).Error; err != nil {
				t.Fatalf("load repos: %v", err)
			}
			var records []models.SpaceRecord
			if err := fixture.db.Where("space = ? AND author = ?", postgresSpaceRef, postgresAuthor).Find(&records).Error; err != nil {
				t.Fatalf("load records: %v", err)
			}
			var opCount int64
			if err := fixture.db.Model(&models.SpaceRepoOp{}).Where("space = ? AND author = ?", postgresSpaceRef, postgresAuthor).Count(&opCount).Error; err != nil {
				t.Fatalf("count ops: %v", err)
			}
			wantRows := int64(0)
			if stage != SpaceRepoFailureAfterRepoCreation {
				wantRows = 1
			}
			if int64(len(repos)) != wantRows || int64(len(records)) != wantRows || opCount != wantRows {
				t.Fatalf("transaction leaked at %s: repos=%d records=%d ops=%d", stage, len(repos), len(records), opCount)
			}
		})
	}
}

func TestPostgresSpaceRepoConcurrentWrites(t *testing.T) {
	fixture := newPostgresSpaceRepoFixture(t)
	manager := NewSpaceRepoMan(fixture.server)
	ctx := context.Background()
	const writers = 16

	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := manager.Apply(ctx, postgresSpaceRef, postgresAuthor, []SpaceRepoOperation{{
				Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: fmt.Sprintf("r%02d", i), Record: postgresSpaceRecord(fmt.Sprintf("parallel-%02d", i)),
			}})
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}

	rows, _, err := manager.ListRecords(ctx, postgresSpaceRef, postgresAuthor, "", 100)
	if err != nil {
		t.Fatalf("list concurrent records: %v", err)
	}
	if len(rows) != writers {
		t.Fatalf("concurrent record count = %d, want %d", len(rows), writers)
	}
	var opCount int64
	if err := fixture.db.Model(&models.SpaceRepoOp{}).Where("space = ? AND author = ?", postgresSpaceRef, postgresAuthor).Count(&opCount).Error; err != nil {
		t.Fatalf("count concurrent ops: %v", err)
	}
	if opCount != writers {
		t.Fatalf("concurrent op count = %d, want %d", opCount, writers)
	}
}

func TestPostgresSpaceRepoDurableReplayConcurrency(t *testing.T) {
	fixture := newPostgresSpaceRepoFixture(t)
	store := space.NewGORMReplayStore(fixture.db)
	ctx := context.Background()
	const attempts = 32
	const jti = "postgres-durable-concurrent-jti"
	deadline := time.Now().Add(time.Hour)

	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- store.Consume(ctx, jti, "delegation", deadline)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, space.ErrReplay):
			replays++
		default:
			t.Fatalf("unexpected replay error: %v", err)
		}
	}
	if successes != 1 || replays != attempts-1 {
		t.Fatalf("replay outcomes success=%d replay=%d, want 1/%d", successes, replays, attempts-1)
	}

	// A separate GORM pool proves that the result is persisted, rather than
	// merely retained by the first store instance or its connection state.
	reopened, err := gorm.Open(postgres.Open(fixture.dsn), postgresTestGORMConfig())
	if err != nil {
		t.Fatalf("reopen postgres schema: %v", err)
	}
	if sqlDB, err := reopened.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	freshStore := space.NewGORMReplayStore(reopened)
	if err := freshStore.Consume(ctx, jti, "delegation", deadline); !errors.Is(err, space.ErrReplay) {
		t.Fatalf("durable replay after reopen error = %v, want ErrReplay", err)
	}
	var rows []models.SpaceReplayJTI
	if err := reopened.Where("token_type = ?", "delegation").Find(&rows).Error; err != nil {
		t.Fatalf("load durable replay rows: %v", err)
	}
	var row models.SpaceReplayJTI
	for _, candidate := range rows {
		if strings.HasSuffix(candidate.JTI, ":"+jti) {
			row = candidate
			break
		}
	}
	if row.JTI == "" {
		t.Fatalf("durable replay row for %q not found in %+v", jti, rows)
	}
	if row.TokenType != "delegation" {
		t.Fatalf("durable replay token type = %q, want delegation", row.TokenType)
	}
}

func TestPostgresSpaceNotificationRevisionOrderingContract(t *testing.T) {
	fixture := newPostgresSpaceRepoFixture(t)
	service := "did:web:syncer.test#space"
	if err := fixture.server.db.Create(context.Background(), &models.SpaceNotifyRegistration{Space: postgresSpaceRef, Service: service, ExpiresAt: time.Now().Add(time.Hour)}, nil).Error; err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	oldRev := spaceRepoClock.Next().String()
	newRev := spaceRepoClock.Next().String()
	oldHash := bytes.Repeat([]byte{0x61}, 32)
	newHash := bytes.Repeat([]byte{0x62}, 32)
	ctx := context.Background()
	if err := fixture.server.RecordSpaceNotifyWrite(ctx, postgresSpaceRef, postgresAuthor, newRev, newHash, "did:web:new.test"); err != nil {
		t.Fatalf("new notifyWrite: %v", err)
	}
	if err := fixture.server.RecordSpaceNotifyWrite(ctx, postgresSpaceRef, postgresAuthor, oldRev, oldHash, "did:web:old.test"); err != nil {
		t.Fatalf("older notifyWrite: %v", err)
	}
	if err := fixture.server.RecordSpaceNotifyWrite(ctx, postgresSpaceRef, postgresAuthor, newRev, oldHash, "did:web:conflict.test"); !errors.Is(err, ErrSpaceNotifyRevisionConflict) {
		t.Fatalf("conflicting notifyWrite error = %v, want ErrSpaceNotifyRevisionConflict", err)
	}
	var writer models.SpaceWriter
	if err := fixture.db.Where("space = ? AND author = ?", postgresSpaceRef, postgresAuthor).First(&writer).Error; err != nil {
		t.Fatal(err)
	}
	if writer.Rev != newRev || !bytes.Equal(writer.Hash, newHash) || writer.Host != "did:web:new.test" {
		t.Fatalf("postgres writer = %+v, want newest snapshot", writer)
	}
	var deliveries []models.SpaceNotifyDelivery
	if err := fixture.db.Where("space = ? AND service = ?", postgresSpaceRef, service).Find(&deliveries).Error; err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].Rev != newRev || !bytes.Equal(deliveries[0].Hash, newHash) {
		t.Fatalf("postgres deliveries = %+v, want only newest snapshot", deliveries)
	}
}
