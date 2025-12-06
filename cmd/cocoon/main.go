package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/server"
	_ "github.com/joho/godotenv/autoload"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var Version = "dev"

func main() {
	app := &cli.App{
		Name:  "cocoon",
		Usage: "An atproto PDS",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "addr",
				Value:   ":8080",
				EnvVars: []string{"COCOON_ADDR"},
			},
			&cli.StringFlag{
				Name:    "db-name",
				Value:   "cocoon.db",
				EnvVars: []string{"COCOON_DB_NAME"},
			},
			&cli.StringFlag{
				Name:    "db-type",
				Value:   "sqlite",
				Usage:   "Database type: sqlite or postgres",
				EnvVars: []string{"COCOON_DB_TYPE"},
			},
			&cli.StringFlag{
				Name:    "database-url",
				Aliases: []string{"db-url"},
				Usage:   "PostgreSQL connection string (required if db-type is postgres)",
				EnvVars: []string{"COCOON_DATABASE_URL", "DATABASE_URL"},
			},
			&cli.StringFlag{
				Name:    "did",
				EnvVars: []string{"COCOON_DID"},
			},
			&cli.StringFlag{
				Name:    "hostname",
				EnvVars: []string{"COCOON_HOSTNAME"},
			},
			&cli.StringFlag{
				Name:    "rotation-key-path",
				EnvVars: []string{"COCOON_ROTATION_KEY_PATH"},
			},
			&cli.StringFlag{
				Name:    "jwk-path",
				EnvVars: []string{"COCOON_JWK_PATH"},
			},
			&cli.StringFlag{
				Name:    "contact-email",
				EnvVars: []string{"COCOON_CONTACT_EMAIL"},
			},
			&cli.StringSliceFlag{
				Name:    "relays",
				EnvVars: []string{"COCOON_RELAYS"},
			},
			&cli.StringFlag{
				Name:    "admin-password",
				EnvVars: []string{"COCOON_ADMIN_PASSWORD"},
			},
			&cli.StringFlag{
				Name:    "smtp-user",
				EnvVars: []string{"COCOON_SMTP_USER"},
			},
			&cli.StringFlag{
				Name:    "smtp-pass",
				EnvVars: []string{"COCOON_SMTP_PASS"},
			},
			&cli.StringFlag{
				Name:    "smtp-host",
				EnvVars: []string{"COCOON_SMTP_HOST"},
			},
			&cli.StringFlag{
				Name:    "smtp-port",
				EnvVars: []string{"COCOON_SMTP_PORT"},
			},
			&cli.StringFlag{
				Name:    "smtp-email",
				EnvVars: []string{"COCOON_SMTP_EMAIL"},
			},
			&cli.StringFlag{
				Name:    "smtp-name",
				EnvVars: []string{"COCOON_SMTP_NAME"},
			},
			&cli.BoolFlag{
				Name:    "s3-backups-enabled",
				EnvVars: []string{"COCOON_S3_BACKUPS_ENABLED"},
			},
			&cli.BoolFlag{
				Name:    "s3-blobstore-enabled",
				EnvVars: []string{"COCOON_S3_BLOBSTORE_ENABLED"},
			},
			&cli.StringFlag{
				Name:    "s3-region",
				EnvVars: []string{"COCOON_S3_REGION"},
			},
			&cli.StringFlag{
				Name:    "s3-bucket",
				EnvVars: []string{"COCOON_S3_BUCKET"},
			},
			&cli.StringFlag{
				Name:    "s3-endpoint",
				EnvVars: []string{"COCOON_S3_ENDPOINT"},
			},
			&cli.StringFlag{
				Name:    "s3-access-key",
				EnvVars: []string{"COCOON_S3_ACCESS_KEY"},
			},
			&cli.StringFlag{
				Name:    "s3-secret-key",
				EnvVars: []string{"COCOON_S3_SECRET_KEY"},
			},
			&cli.StringFlag{
				Name:    "session-secret",
				EnvVars: []string{"COCOON_SESSION_SECRET"},
			},
			&cli.StringFlag{
				Name:    "blockstore-variant",
				EnvVars: []string{"COCOON_BLOCKSTORE_VARIANT"},
				Value:   "sqlite",
			},
			&cli.StringFlag{
				Name:    "fallback-proxy",
				EnvVars: []string{"COCOON_FALLBACK_PROXY"},
			},
		},
		Commands: []*cli.Command{
			runServe,
			runCreateRotationKey,
			runCreatePrivateJwk,
			runCreateInviteCode,
			runResetPassword,
		},
		ErrWriter: os.Stdout,
		Version:   Version,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

var runServe = &cli.Command{
	Name:  "run",
	Usage: "Start the cocoon PDS",
	Flags: []cli.Flag{},
	Action: func(cmd *cli.Context) error {

		s, err := server.New(&server.Args{
			Addr:            cmd.String("addr"),
			DbName:          cmd.String("db-name"),
			DbType:          cmd.String("db-type"),
			DatabaseURL:     cmd.String("database-url"),
			Did:             cmd.String("did"),
			Hostname:        cmd.String("hostname"),
			RotationKeyPath: cmd.String("rotation-key-path"),
			JwkPath:         cmd.String("jwk-path"),
			ContactEmail:    cmd.String("contact-email"),
			Version:         Version,
			Relays:          cmd.StringSlice("relays"),
			AdminPassword:   cmd.String("admin-password"),
			SmtpUser:        cmd.String("smtp-user"),
			SmtpPass:        cmd.String("smtp-pass"),
			SmtpHost:        cmd.String("smtp-host"),
			SmtpPort:        cmd.String("smtp-port"),
			SmtpEmail:       cmd.String("smtp-email"),
			SmtpName:        cmd.String("smtp-name"),
			S3Config: &server.S3Config{
				BackupsEnabled:   cmd.Bool("s3-backups-enabled"),
				BlobstoreEnabled: cmd.Bool("s3-blobstore-enabled"),
				Region:           cmd.String("s3-region"),
				Bucket:           cmd.String("s3-bucket"),
				Endpoint:         cmd.String("s3-endpoint"),
				AccessKey:        cmd.String("s3-access-key"),
				SecretKey:        cmd.String("s3-secret-key"),
			},
			SessionSecret:     cmd.String("session-secret"),
			BlockstoreVariant: server.MustReturnBlockstoreVariant(cmd.String("blockstore-variant")),
			FallbackProxy:     cmd.String("fallback-proxy"),
		})
		if err != nil {
			fmt.Printf("error creating cocoon: %v", err)
			return err
		}

		if err := s.Serve(cmd.Context); err != nil {
			fmt.Printf("error starting cocoon: %v", err)
			return err
		}

		return nil
	},
}

var runCreateRotationKey = &cli.Command{
	Name:  "create-rotation-key",
	Usage: "creates a rotation key for your pds",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "out",
			Required: true,
			Usage:    "output file for your rotation key",
		},
	},
	Action: func(cmd *cli.Context) error {
		key, err := atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			return err
		}

		bytes := key.Bytes()

		if err := os.WriteFile(cmd.String("out"), bytes, 0644); err != nil {
			return err
		}

		return nil
	},
}

var runCreatePrivateJwk = &cli.Command{
	Name:  "create-private-jwk",
	Usage: "creates a private jwk for your pds",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "out",
			Required: true,
			Usage:    "output file for your jwk",
		},
	},
	Action: func(cmd *cli.Context) error {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		key, err := jwk.FromRaw(privKey)
		if err != nil {
			return err
		}

		kid := fmt.Sprintf("%d", time.Now().Unix())

		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			return err
		}

		b, err := json.Marshal(key)
		if err != nil {
			return err
		}

		if err := os.WriteFile(cmd.String("out"), b, 0644); err != nil {
			return err
		}

		return nil
	},
}

var runCreateInviteCode = &cli.Command{
	Name:  "create-invite-code",
	Usage: "creates an invite code",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "for",
			Usage: "optional did to assign the invite code to",
		},
		&cli.IntFlag{
			Name:  "uses",
			Usage: "number of times the invite code can be used",
			Value: 1,
		},
	},
	Action: func(cmd *cli.Context) error {
		db, err := newDb(cmd)
		if err != nil {
			return err
		}

		forDid := "did:plc:123"
		if cmd.String("for") != "" {
			did, err := syntax.ParseDID(cmd.String("for"))
			if err != nil {
				return err
			}

			forDid = did.String()
		}

		uses := cmd.Int("uses")

		code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(8), helpers.RandomVarchar(8))

		if err := db.Exec("INSERT INTO invite_codes (did, code, remaining_use_count) VALUES (?, ?, ?)", forDid, code, uses).Error; err != nil {
			return err
		}

		fmt.Printf("New invite code created with %d uses: %s\n", uses, code)

		return nil
	},
}

var runResetPassword = &cli.Command{
	Name:  "reset-password",
	Usage: "resets a password",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "did",
			Usage: "did of the user who's password you want to reset",
		},
	},
	Action: func(cmd *cli.Context) error {
		db, err := newDb(cmd)
		if err != nil {
			return err
		}

		didStr := cmd.String("did")
		did, err := syntax.ParseDID(didStr)
		if err != nil {
			return err
		}

		newPass := fmt.Sprintf("%s-%s", helpers.RandomVarchar(12), helpers.RandomVarchar(12))
		hashed, err := bcrypt.GenerateFromPassword([]byte(newPass), 10)
		if err != nil {
			return err
		}

		if err := db.Exec("UPDATE repos SET password = ? WHERE did = ?", hashed, did.String()).Error; err != nil {
			return err
		}

		fmt.Printf("Password for %s has been reset to: %s", did.String(), newPass)

		return nil
	},
}

func newDb(cmd *cli.Context) (*gorm.DB, error) {
	dbType := cmd.String("db-type")
	if dbType == "" {
		dbType = "sqlite"
	}

	switch dbType {
	case "postgres":
		databaseURL := cmd.String("database-url")
		if databaseURL == "" {
			databaseURL = cmd.String("database-url")
		}
		if databaseURL == "" {
			return nil, fmt.Errorf("COCOON_DATABASE_URL or DATABASE_URL must be set when using postgres")
		}
		return gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	default:
		dbName := cmd.String("db-name")
		if dbName == "" {
			dbName = "cocoon.db"
		}
		return gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	}
}
