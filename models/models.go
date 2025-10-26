package models

import (
	"context"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

type Repo struct {
	Did                            string `gorm:"primaryKey"`
	CreatedAt                      time.Time
	Email                          string `gorm:"uniqueIndex"`
	EmailConfirmedAt               *time.Time
	EmailVerificationCode          *string
	EmailVerificationCodeExpiresAt *time.Time
	EmailUpdateCode                *string
	EmailUpdateCodeExpiresAt       *time.Time
	PasswordResetCode              *string
	PasswordResetCodeExpiresAt     *time.Time
	Password                       string
	SigningKey                     []byte
	Rev                            string
	Root                           []byte
	Preferences                    []byte
	Deactivated                    bool
}

func (r *Repo) SignFor(ctx context.Context, did string, msg []byte) ([]byte, error) {
	k, err := atcrypto.ParsePrivateBytesK256(r.SigningKey)
	if err != nil {
		return nil, err
	}

	sig, err := k.HashAndSign(msg)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (r *Repo) Status() *string {
	var status *string
	if r.Deactivated {
		status = to.StringPtr("deactivated")
	}
	return status
}

func (r *Repo) Active() bool {
	return r.Status() == nil
}

type Actor struct {
	Did    string `gorm:"primaryKey"`
	Handle string `gorm:"uniqueIndex"`
}

type RepoActor struct {
	Repo
	Actor
}

type InviteCode struct {
	Code              string `gorm:"primaryKey"`
	Did               string `gorm:"index"`
	RemainingUseCount int
}

type Token struct {
	Token        string `gorm:"primaryKey"`
	Did          string `gorm:"index"`
	RefreshToken string `gorm:"index"`
	CreatedAt    time.Time
	ExpiresAt    time.Time `gorm:"index:,sort:asc"`
}

type RefreshToken struct {
	Token     string `gorm:"primaryKey"`
	Did       string `gorm:"index"`
	CreatedAt time.Time
	ExpiresAt time.Time `gorm:"index:,sort:asc"`
}

type Record struct {
	Did       string `gorm:"primaryKey:idx_record_did_created_at;index:idx_record_did_nsid"`
	CreatedAt string `gorm:"index;index:idx_record_did_created_at,sort:desc"`
	Nsid      string `gorm:"primaryKey;index:idx_record_did_nsid"`
	Rkey      string `gorm:"primaryKey"`
	Cid       string
	Value     []byte
}

type Block struct {
	Did   string `gorm:"primaryKey;index:idx_blocks_by_rev"`
	Cid   []byte `gorm:"primaryKey"`
	Rev   string `gorm:"index:idx_blocks_by_rev,sort:desc"`
	Value []byte
}

type Blob struct {
	ID        uint
	CreatedAt string `gorm:"index"`
	Did       string `gorm:"index;index:idx_blob_did_cid"`
	Cid       []byte `gorm:"index;index:idx_blob_did_cid"`
	RefCount  int
	Storage   string `gorm:"default:sqlite"`
}

type BlobPart struct {
	Blob   Blob
	BlobID uint `gorm:"primaryKey"`
	Idx    int  `gorm:"primaryKey"`
	Data   []byte
}
