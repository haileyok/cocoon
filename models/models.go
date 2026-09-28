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
	PasswordResetCode              *string `gorm:"index"`
	PasswordResetCodeExpiresAt     *time.Time
	PlcOperationCode               *string
	PlcOperationCodeExpiresAt      *time.Time
	AccountDeleteCode              *string
	AccountDeleteCodeExpiresAt     *time.Time
	Password                       string
	SessionVersion                 int64 `gorm:"not null;default:0"`
	SigningKey                     []byte
	Rev                            string
	Root                           []byte
	Preferences                    []byte
	Deactivated                    bool
	TwoFactorCode                  *string
	TwoFactorCodeExpiresAt         *time.Time
	TwoFactorType                  TwoFactorType `gorm:"default:none"`
	// Failed second-factor attempts since the last success, and the time
	// until which further attempts are refused once too many have failed.
	TwoFactorFailedAttempts int `gorm:"not null;default:0"`
	TwoFactorLockedUntil    *time.Time
}

type TwoFactorCredentialType string

var (
	TwoFactorCredentialTOTP      = TwoFactorCredentialType("totp")
	TwoFactorCredentialYubicoOTP = TwoFactorCredentialType("yubico_otp")
)

// TwoFactorCredential is an authenticator app (TOTP) or a YubiKey slot
// programmed for Yubico OTP. When an account has any of these, they replace
// emailed sign-in codes entirely.
type TwoFactorCredential struct {
	ID        uint   `gorm:"primaryKey"`
	Did       string `gorm:"index;not null"`
	Type      TwoFactorCredentialType
	Name      string
	CreatedAt time.Time
	// TOTP shared secret, or the YubiKey slot's AES-128 key.
	Secret []byte
	// Yubico OTP only: the modhex public identity typed before each OTP, and
	// the 6-byte private identity found inside the encrypted block.
	PublicID  string `gorm:"index"`
	PrivateID []byte
	// Replay protection. TOTP stores the last accepted time step; Yubico OTP
	// stores the last accepted (session counter, session use) pair.
	LastStep    int64 `gorm:"not null;default:0"`
	LastCounter int   `gorm:"not null;default:0"`
	LastUse     int   `gorm:"not null;default:0"`
	LastUsedAt  *time.Time
}

// TwoFactorBackupCode is a single-use recovery code, stored as a SHA-256
// hash. Backup codes are only accepted when the account has at least one
// TwoFactorCredential.
type TwoFactorBackupCode struct {
	ID        uint   `gorm:"primaryKey"`
	Did       string `gorm:"index;not null"`
	CodeHash  []byte
	CreatedAt time.Time
	UsedAt    *time.Time
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
	Token          string `gorm:"primaryKey"`
	Did            string `gorm:"index"`
	SessionVersion int64  `gorm:"not null;default:0"`
	RefreshToken   string `gorm:"index"`
	CreatedAt      time.Time
	ExpiresAt      time.Time `gorm:"index:,sort:asc"`
}

type RefreshToken struct {
	Token          string `gorm:"primaryKey"`
	Did            string `gorm:"index"`
	SessionVersion int64  `gorm:"not null;default:0"`
	CreatedAt      time.Time
	ExpiresAt      time.Time `gorm:"index:,sort:asc"`
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
