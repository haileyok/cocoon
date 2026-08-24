package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const password = "interop-pass"

type account struct {
	did    string
	handle string
	email  string
}

var accounts = []account{
	{did: "did:plc:z72i7hdynmk6r22z27h6tvur", handle: "alice.pds.test", email: "alice@pds.test"},
	{did: "did:plc:ewvi7nxzyouno6dufxzhgotq", handle: "bob.pds.test", email: "bob@pds.test"},
}

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	flag.Parse()
	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "-db is required")
		os.Exit(2)
	}

	db, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	if err := db.AutoMigrate(&models.Repo{}, &models.Actor{}); err != nil {
		panic(err)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	for _, account := range accounts {
		key, err := atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			panic(err)
		}
		repo := models.Repo{
			Did:        account.did,
			CreatedAt:  time.Now().UTC(),
			Email:      account.email,
			Password:   string(passwordHash),
			SigningKey: key.Bytes(),
		}
		actor := models.Actor{Did: account.did, Handle: account.handle}
		if err := db.Create(&repo).Error; err != nil {
			panic(err)
		}
		if err := db.Create(&actor).Error; err != nil {
			panic(err)
		}
	}
}
