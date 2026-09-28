package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/internal/totp"
	"github.com/haileyok/cocoon/internal/yubiotp"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

const (
	// maxSecondFactorAttempts failed codes in a row lock second-factor
	// attempts for secondFactorLockout. The counter is only reachable after
	// a correct password, so it can't be used to lock out arbitrary users.
	maxSecondFactorAttempts = 10
	secondFactorLockout     = 15 * time.Minute

	backupCodeCount = 10
)

type secondFactorResult int

const (
	secondFactorOK secondFactorResult = iota
	// secondFactorRequired: no code was given (an email code has been sent
	// if the account uses email 2FA).
	secondFactorRequired
	secondFactorInvalid
	secondFactorExpired
	secondFactorLocked
)

func (s *Server) getTwoFactorCredentials(ctx context.Context, did string) ([]models.TwoFactorCredential, error) {
	var creds []models.TwoFactorCredential
	if err := s.db.Raw(ctx, "SELECT * FROM two_factor_credentials WHERE did = ? ORDER BY id", nil, did).Scan(&creds).Error; err != nil {
		return nil, err
	}
	return creds, nil
}

// hasSecondFactor reports whether signing in needs a code of any kind.
func (s *Server) hasSecondFactor(ctx context.Context, repo *models.Repo) (bool, error) {
	if repo.TwoFactorType != models.TwoFactorTypeNone {
		return true, nil
	}
	var n int64
	if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM two_factor_credentials WHERE did = ?", nil, repo.Did).Scan(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// checkSecondFactor is the single second-factor check behind both
// com.atproto.server.createSession and the browser signin page (which the
// OAuth flow uses). Call it only after the password has been verified.
//
// If the account has an authenticator app or YubiKey registered, only those
// (or a backup code) are accepted and no email is sent. Otherwise, when
// email 2FA is on, the emailed code is used as before.
func (s *Server) checkSecondFactor(ctx context.Context, repo *models.RepoActor, token string) (secondFactorResult, error) {
	creds, err := s.getTwoFactorCredentials(ctx, repo.Repo.Did)
	if err != nil {
		return 0, err
	}
	if len(creds) == 0 && repo.TwoFactorType == models.TwoFactorTypeNone {
		return secondFactorOK, nil
	}

	now := time.Now().UTC()
	if repo.TwoFactorLockedUntil != nil && now.Before(*repo.TwoFactorLockedUntil) {
		return secondFactorLocked, nil
	}

	token = strings.TrimSpace(token)
	if token == "" {
		if len(creds) == 0 {
			if err := s.createAndSendTwoFactorCode(ctx, *repo); err != nil {
				return 0, err
			}
		}
		return secondFactorRequired, nil
	}

	var ok bool
	if len(creds) > 0 {
		ok, err = s.verifyStrongSecondFactor(ctx, repo.Repo.Did, creds, token, now)
		if err != nil {
			return 0, err
		}
	} else {
		if repo.TwoFactorCode == nil || repo.TwoFactorCodeExpiresAt == nil {
			if err := s.createAndSendTwoFactorCode(ctx, *repo); err != nil {
				return 0, err
			}
			return secondFactorRequired, nil
		}
		ok = subtle.ConstantTimeCompare([]byte(*repo.TwoFactorCode), []byte(token)) == 1
		if ok && now.After(*repo.TwoFactorCodeExpiresAt) {
			return secondFactorExpired, nil
		}
		if ok {
			if err := s.clearTwoFactorCode(ctx, repo.Repo.Did); err != nil {
				return 0, err
			}
		}
	}

	if !ok {
		if err := s.recordSecondFactorFailure(ctx, repo.Repo.Did, now); err != nil {
			return 0, err
		}
		return secondFactorInvalid, nil
	}

	if repo.TwoFactorFailedAttempts != 0 || repo.TwoFactorLockedUntil != nil {
		if err := s.db.Exec(ctx, "UPDATE repos SET two_factor_failed_attempts = 0, two_factor_locked_until = NULL WHERE did = ?", nil, repo.Repo.Did).Error; err != nil {
			return 0, err
		}
	}
	return secondFactorOK, nil
}

func (s *Server) recordSecondFactorFailure(ctx context.Context, did string, now time.Time) error {
	if err := s.db.Exec(ctx, "UPDATE repos SET two_factor_failed_attempts = two_factor_failed_attempts + 1 WHERE did = ?", nil, did).Error; err != nil {
		return err
	}
	return s.db.Exec(ctx,
		"UPDATE repos SET two_factor_failed_attempts = 0, two_factor_locked_until = ? WHERE did = ? AND two_factor_failed_attempts >= ?",
		nil, now.Add(secondFactorLockout), did, maxSecondFactorAttempts,
	).Error
}

// verifyStrongSecondFactor checks token against the account's authenticator
// apps, YubiKeys, and backup codes. Each accepted code is claimed with a
// conditional UPDATE, so concurrent requests can't both use the same one.
func (s *Server) verifyStrongSecondFactor(ctx context.Context, did string, creds []models.TwoFactorCredential, token string, now time.Time) (bool, error) {
	switch {
	case yubiotp.LooksLikeOTP(token):
		for _, c := range creds {
			if c.Type != models.TwoFactorCredentialYubicoOTP {
				continue
			}
			ok, err := s.claimYubicoOTP(ctx, c, token, now)
			if err != nil || ok {
				return ok, err
			}
		}
		return false, nil

	case isTOTPShaped(token):
		for _, c := range creds {
			if c.Type != models.TwoFactorCredentialTOTP {
				continue
			}
			step, ok := totp.Validate(c.Secret, token, now, c.LastStep)
			if !ok {
				continue
			}
			res := s.db.Exec(ctx, "UPDATE two_factor_credentials SET last_step = ?, last_used_at = ? WHERE id = ? AND last_step < ?", nil, step, now, c.ID, step)
			if res.Error != nil {
				return false, res.Error
			}
			if res.RowsAffected == 1 {
				return true, nil
			}
		}
		return false, nil

	default:
		return s.claimBackupCode(ctx, did, token, now)
	}
}

func isTOTPShaped(token string) bool {
	token = strings.ReplaceAll(token, " ", "")
	if len(token) != totp.Digits {
		return false
	}
	for _, c := range token {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (s *Server) claimYubicoOTP(ctx context.Context, c models.TwoFactorCredential, token string, now time.Time) (bool, error) {
	// A key programmed with a public identity always types it first; skip
	// keys whose identity doesn't match without spending an AES decrypt.
	if c.PublicID != "" && subtle.ConstantTimeCompare([]byte(yubiotp.PublicID(token)), []byte(c.PublicID)) != 1 {
		return false, nil
	}
	otp, err := yubiotp.Parse(token, c.Secret)
	if err != nil {
		return false, nil
	}
	if !otp.MatchesPrivateID(c.PrivateID) {
		return false, nil
	}
	if !yubiotp.IsNewer(otp, uint16(c.LastCounter), uint8(c.LastUse)) {
		return false, nil
	}
	ctr, use := int(otp.Counter), int(otp.SessionUse)
	res := s.db.Exec(ctx,
		`UPDATE two_factor_credentials SET last_counter = ?, last_use = ?, last_used_at = ?
		 WHERE id = ? AND (last_counter < ? OR (last_counter = ? AND last_use < ?))`,
		nil, ctr, use, now, c.ID, ctr, ctr, use,
	)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func normalizeBackupCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
}

func hashBackupCode(code string) []byte {
	sum := sha256.Sum256([]byte(normalizeBackupCode(code)))
	return sum[:]
}

func (s *Server) claimBackupCode(ctx context.Context, did, token string, now time.Time) (bool, error) {
	res := s.db.Exec(ctx,
		"UPDATE two_factor_backup_codes SET used_at = ? WHERE did = ? AND code_hash = ? AND used_at IS NULL",
		nil, now, did, hashBackupCode(token),
	)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// regenerateBackupCodes replaces all of an account's backup codes and
// returns the new ones in plaintext. They are shown to the user once.
func (s *Server) regenerateBackupCodes(ctx context.Context, did string) ([]string, error) {
	codes := make([]string, backupCodeCount)
	rows := make([]models.TwoFactorBackupCode, backupCodeCount)
	now := time.Now().UTC()
	for i := range codes {
		codes[i] = fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
		rows[i] = models.TwoFactorBackupCode{Did: did, CodeHash: hashBackupCode(codes[i]), CreatedAt: now}
	}
	if err := s.db.Exec(ctx, "DELETE FROM two_factor_backup_codes WHERE did = ?", nil, did).Error; err != nil {
		return nil, err
	}
	if err := s.db.Create(ctx, &rows, nil).Error; err != nil {
		return nil, err
	}
	return codes, nil
}

// secondFactorXrpcError maps a non-OK result to the XRPC response the
// Bluesky app understands. AuthFactorTokenRequired makes it show its code
// box; "Token is invalid" makes it highlight that box as wrong.
func secondFactorXrpcError(e echo.Context, res secondFactorResult) error {
	switch res {
	case secondFactorRequired:
		return helpers.InputError(e, to.StringPtr("AuthFactorTokenRequired"))
	case secondFactorExpired:
		return helpers.ExpiredTokenError(e)
	case secondFactorLocked:
		return e.JSON(429, map[string]string{
			"error":   "RateLimitExceeded",
			"message": "Too many incorrect codes. Try again in a few minutes.",
		})
	default:
		return helpers.InvalidTokenError(e)
	}
}
