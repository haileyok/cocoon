package models

import (
	"context"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

type TwoFactorType string

var (
	TwoFactorTypeNone  = TwoFactorType("none")
	TwoFactorTypeEmail = TwoFactorType("email")
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
	PlcOperationCode               *string
	PlcOperationCodeExpiresAt      *time.Time
	AccountDeleteCode              *string
	AccountDeleteCodeExpiresAt     *time.Time
	Password                       string
	SigningKey                     []byte
	Rev                            string
	Root                           []byte
	Preferences                    []byte
	Deactivated                    bool
	Suspended                      bool
	Takendown                      bool
	TwoFactorCode                  *string
	TwoFactorCodeExpiresAt         *time.Time
	TwoFactorType                  TwoFactorType `gorm:"default:none"`
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
	// Moderation states take precedence over user-controlled deactivation so
	// callers return the strongest authoritative availability restriction.
	if r.Takendown {
		return to.StringPtr("takendown")
	}
	if r.Suspended {
		return to.StringPtr("suspended")
	}
	if r.Deactivated {
		return to.StringPtr("deactivated")
	}
	return nil
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
	MimeType  string
	Size      int64
	RefCount  int
	Storage   string `gorm:"default:sqlite"`
	// Bucket and ObjectKey are immutable S3 identity for this blob generation.
	// Empty ObjectKey is retained for legacy rows, which resolve to the original
	// blobs/{did}/{cid} location at read/deletion time.
	Bucket    string
	ObjectKey string
}

type BlobPart struct {
	Blob   Blob
	BlobID uint `gorm:"primaryKey"`
	Idx    int  `gorm:"primaryKey"`
	Data   []byte
}

// BlobDeletion is durable work for removing an S3-backed blob after its
// account metadata has been deleted. ObjectKey and Bucket are snapshotted at
// enqueue time so retries do not depend on mutable server configuration.
type BlobDeletion struct {
	ID             uint   `gorm:"primaryKey"`
	IdempotencyKey string `gorm:"uniqueIndex"`
	Bucket         string
	ObjectKey      string
	Status         string `gorm:"index:idx_blob_deletions_status"`
	AttemptCount   int
	NextAttemptAt  *time.Time `gorm:"index"`
	LastError      string
	DeletedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ReservedKey struct {
	KeyDid     string  `gorm:"primaryKey"`
	Did        *string `gorm:"index"`
	PrivateKey []byte
	CreatedAt  time.Time `gorm:"index"`
}

type EventRecord struct {
	Seq       int64 `gorm:"primaryKey;autoIncrement:false"`
	CreatedAt time.Time
	Did       string `gorm:"index"`
	Type      string
	Data      []byte
}
