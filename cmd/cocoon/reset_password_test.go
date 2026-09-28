package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestResetPasswordCommand(t *testing.T) {
	for _, mode := range []string{"success", "missing-account", "revocation-failure"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recovery.db")
			database, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := database.DB()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := database.AutoMigrate(&models.Repo{}, &models.Token{}, &models.RefreshToken{}, &provider.OauthToken{}, &provider.OauthAuthorizationRequest{}); err != nil {
				t.Fatal(err)
			}
			code := "pending-code"
			expires := time.Now().Add(time.Hour)
			hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			for _, did := range []string{"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"} {
				for _, row := range []any{
					&models.Repo{Did: did, Email: did + "@test.invalid", Password: string(hash), SessionVersion: 7, PasswordResetCode: &code, PasswordResetCodeExpiresAt: &expires, TwoFactorCode: &code, TwoFactorCodeExpiresAt: &expires},
					&models.Token{Did: did, Token: did + "-access", RefreshToken: did + "-refresh", SessionVersion: 7},
					&models.RefreshToken{Did: did, Token: did + "-refresh", SessionVersion: 7},
					&provider.OauthToken{Sub: did, Token: did + "-oauth", RefreshToken: did + "-oauth-refresh", SessionVersion: 7},
					&provider.OauthAuthorizationRequest{RequestId: did, Sub: &did, Code: &code, SessionVersion: 7},
				} {
					if err := database.Create(row).Error; err != nil {
						t.Fatal(err)
					}
				}
			}
			var before []models.Repo
			if err := database.Order("did").Find(&before).Error; err != nil {
				t.Fatal(err)
			}
			did := before[0].Did
			if mode == "missing-account" {
				did = "did:plc:cccccccccccccccccccccccc"
			}
			if mode == "revocation-failure" {
				if err := database.Exec("CREATE TRIGGER reject_revocation BEFORE DELETE ON oauth_authorization_requests BEGIN SELECT RAISE(ABORT, 'injected failure'); END").Error; err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			app := &cli.App{Writer: &output, Commands: []*cli.Command{runResetPassword}, Flags: []cli.Flag{&cli.StringFlag{Name: "db-name"}}}
			err = app.Run([]string{"cocoon", "--db-name", path, "reset-password", "--did", did})
			var after []models.Repo
			if e := database.Order("did").Find(&after).Error; e != nil {
				t.Fatal(e)
			}
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				password := strings.TrimPrefix(output.String(), "Password for "+did+" has been reset to: ")
				if bcrypt.CompareHashAndPassword([]byte(after[0].Password), []byte(password)) != nil {
					t.Fatal("printed password does not match stored hash")
				}
				if after[0].SessionVersion != 8 || after[0].PasswordResetCode != nil || after[0].PasswordResetCodeExpiresAt != nil || after[0].TwoFactorCode != nil || after[0].TwoFactorCodeExpiresAt != nil {
					t.Fatal("recovery state not invalidated")
				}
				if !reflect.DeepEqual(before[1], after[1]) {
					t.Fatal("other account changed")
				}
			} else {
				if err == nil || output.Len() != 0 {
					t.Fatal("failed reset reported success")
				}
				if mode == "missing-account" && !errors.Is(err, gorm.ErrRecordNotFound) {
					t.Fatalf("missing account: %v", err)
				}
				if !reflect.DeepEqual(before, after) {
					t.Fatal("failed reset changed accounts")
				}
			}
			for _, table := range []string{"tokens", "refresh_tokens", "oauth_tokens", "oauth_authorization_requests"} {
				column := "did"
				if strings.HasPrefix(table, "oauth_") {
					column = "sub"
				}
				for i, repo := range before {
					var count int64
					if err := database.Table(table).Where(column+" = ?", repo.Did).Count(&count).Error; err != nil {
						t.Fatal(err)
					}
					want := int64(1)
					if mode == "success" && i == 0 {
						want = 0
					}
					if count != want {
						t.Fatalf("%s account %d: %d rows, want %d", table, i, count, want)
					}
				}
			}
		})
	}
}
