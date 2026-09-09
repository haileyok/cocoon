package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/go-playground/validator"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const (
	testHostname = "pds.test"
	testDid      = "did:web:pds.test"
)

// newTestServer builds a minimal, white-box *Server backed by a fresh on-disk
// SQLite database (the same driver and migrations as production). Only the
// fields exercised by auth/session/handler code paths are populated. Network
// collaborators (plcClient, passport, oauthProvider, mail) are left nil; a test
// that exercises a path needing one must set it explicitly.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "cocoon-test.db")
	gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	gdb.Exec("PRAGMA journal_mode=WAL")
	gdb.Exec("PRAGMA synchronous=NORMAL")
	gdb.Exec("PRAGMA busy_timeout=5000")

	dbw := db.NewDB(gdb)
	if err := dbw.AutoMigrate(
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
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	pkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}

	publicJwk, publicKid, err := derivePublicJWK(pkey, "")
	if err != nil {
		t.Fatalf("derive public jwk: %v", err)
	}

	return &Server{
		db:         dbw,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		privateKey: pkey,
		publicJwk:  publicJwk,
		publicKid:  publicKid,
		config: &config{
			Version:          "test",
			Did:              testDid,
			Hostname:         testHostname,
			AdminPassword:    "admin-test-password",
			SessionCookieKey: "cocoon-test-session",
			RequireInvite:    false,
		},
	}
}

// newTestValidator mirrors the custom validator registered in New() so that
// handlers calling e.Validate behave identically under test.
func newTestValidator() *CustomValidator {
	vdtor := validator.New()
	vdtor.RegisterValidation("atproto-handle", func(fl validator.FieldLevel) bool {
		_, err := syntax.ParseHandle(fl.Field().String())
		return err == nil
	})
	vdtor.RegisterValidation("atproto-did", func(fl validator.FieldLevel) bool {
		_, err := syntax.ParseDID(fl.Field().String())
		return err == nil
	})
	vdtor.RegisterValidation("atproto-rkey", func(fl validator.FieldLevel) bool {
		_, err := syntax.ParseRecordKey(fl.Field().String())
		return err == nil
	})
	vdtor.RegisterValidation("atproto-nsid", func(fl validator.FieldLevel) bool {
		_, err := syntax.ParseNSID(fl.Field().String())
		return err == nil
	})
	return &CustomValidator{validator: vdtor}
}

// newRequestContext builds an echo.Context for a single request, wiring the
// shared validator. headers are applied to the request; body may be empty.
func newRequestContext(method, target, body string, headers map[string]string) (echo.Context, *httptest.ResponseRecorder) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != "" {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e := echo.New()
	e.Validator = newTestValidator()
	return e.NewContext(req, rec), rec
}

// testAccount describes a Repo+Actor inserted by createTestAccount.
type testAccount struct {
	Did        string
	Handle     string
	Email      string
	Password   string
	SigningKey []byte // raw secp256k1 (k256) private key bytes
}

// createTestAccount inserts a Repo and Actor with a known password and a fresh
// k256 signing key, returning its descriptor for use in token/auth tests.
func (s *Server) createTestAccount(t *testing.T, handle string) *testAccount {
	t.Helper()
	ctx := context.Background()

	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate k256 key: %v", err)
	}

	did := "did:plc:" + strings.ToLower(helpers.RandomVarchar(24))
	if _, err := syntax.ParseDID(did); err != nil {
		t.Fatalf("generated did did not parse: %v", err)
	}

	const password = "correct-horse-battery-staple"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := models.Repo{
		Did:           did,
		CreatedAt:     time.Now(),
		Email:         handle + "@test.invalid",
		Password:      string(hashed),
		SigningKey:    k.Bytes(),
		TwoFactorType: models.TwoFactorTypeNone,
	}
	if err := s.db.Create(ctx, &repo, nil).Error; err != nil {
		t.Fatalf("insert repo: %v", err)
	}

	actor := models.Actor{Did: did, Handle: handle}
	if err := s.db.Create(ctx, &actor, nil).Error; err != nil {
		t.Fatalf("insert actor: %v", err)
	}

	return &testAccount{
		Did:        did,
		Handle:     handle,
		Email:      repo.Email,
		Password:   password,
		SigningKey: k.Bytes(),
	}
}

// TestHarnessSmoke proves the harness wiring: CGO SQLite opens, migrations run,
// and an inserted account round-trips through the production query helper.
func TestHarnessSmoke(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	got, err := s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	if got.Actor.Handle != acct.Handle {
		t.Fatalf("handle = %q, want %q", got.Actor.Handle, acct.Handle)
	}
	if got.Repo.Email != acct.Email {
		t.Fatalf("email = %q, want %q", got.Repo.Email, acct.Email)
	}
}

// TestRequestContextValidatorWired confirms e.Validate runs the custom validator.
func TestRequestContextValidatorWired(t *testing.T) {
	c, _ := newRequestContext(http.MethodPost, "/", `{}`, nil)

	var req ComAtprotoServerCreateSessionRequest
	if err := c.Bind(&req); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := c.Validate(req); err == nil {
		t.Fatal("expected validation error for empty identifier/password")
	}
}
