package db

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// ResetPassword revokes sessions atomically with the password change. A nil
// resetCode is reserved for administrative recovery without an email challenge.
func (db *DB) ResetPassword(ctx context.Context, did, hash string, resetCode *string) error {
	return db.Transaction(ctx, func(tx *DB) error {
		where := "did = ?"
		args := []any{hash, did}
		if resetCode != nil {
			where += " AND password_reset_code = ? AND password_reset_code_expires_at > ?"
			args = append(args, *resetCode, time.Now().UTC())
		}
		result := tx.Exec(ctx, `UPDATE repos SET password_reset_code = NULL, password_reset_code_expires_at = NULL,
			password = ?, session_version = session_version + 1,
			two_factor_code = NULL, two_factor_code_expires_at = NULL WHERE `+where, nil, args...)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		for _, query := range []string{
			"DELETE FROM tokens WHERE did = ?",
			"DELETE FROM refresh_tokens WHERE did = ?",
			"DELETE FROM oauth_tokens WHERE sub = ?",
			"DELETE FROM oauth_authorization_requests WHERE sub = ?",
		} {
			if err := tx.Exec(ctx, query, nil, did).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
