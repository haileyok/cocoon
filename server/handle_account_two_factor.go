package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/internal/totp"
	"github.com/haileyok/cocoon/internal/yubiotp"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// Pages under /account/2fa for adding and removing authenticator apps,
// YubiKeys, and backup codes. Every change needs the account password and,
// once any of these methods exists, a current code from one of them. That
// keeps a stolen browser session from adding its own authenticator, which
// would lock the owner out now that email codes are no longer a fallback.

const maxCredentialNameLength = 64

type twoFactorManageInput struct {
	ID          uint   `form:"id"`
	Name        string `form:"name"`
	Password    string `form:"password"`
	CurrentCode string `form:"current_code"`
	Secret      string `form:"secret"`
	Code        string `form:"code"`
	AesKey      string `form:"aes_key"`
	OTP         string `form:"otp"`
}

func credentialName(name, fallback string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return fallback
	}
	if r := []rune(name); len(r) > maxCredentialNameLength {
		name = string(r[:maxCredentialNameLength])
	}
	return name
}

// authorizeTwoFactorChange checks the password and, if the account already
// has an authenticator or YubiKey, a current code from one of them. It
// returns a message for the user when the check fails.
func (s *Server) authorizeTwoFactorChange(ctx context.Context, repo *models.RepoActor, creds []models.TwoFactorCredential, password, currentCode string) (string, error) {
	if bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(password)) != nil {
		return "Password is incorrect.", nil
	}
	emailOnly := len(creds) == 0 && repo.TwoFactorType != models.TwoFactorTypeNone
	if len(creds) == 0 && !emailOnly {
		return "", nil
	}

	now := time.Now().UTC()
	if repo.TwoFactorLockedUntil != nil && now.Before(*repo.TwoFactorLockedUntil) {
		return "Too many incorrect codes. Try again in a few minutes.", nil
	}
	currentCode = strings.TrimSpace(currentCode)
	if currentCode == "" {
		if emailOnly {
			return "Enter the code we emailed you. Use \"Email me a code\" to get one.", nil
		}
		return "Enter a code from one of your current sign-in methods.", nil
	}

	var ok bool
	var err error
	if emailOnly {
		// Adding the first authenticator replaces email codes, so prove
		// control of the email address first.
		if repo.TwoFactorCode == nil || repo.TwoFactorCodeExpiresAt == nil {
			return "Use \"Email me a code\" to get a code first.", nil
		}
		ok = subtle.ConstantTimeCompare([]byte(*repo.TwoFactorCode), []byte(currentCode)) == 1
		if ok && now.After(*repo.TwoFactorCodeExpiresAt) {
			return "That code has expired. Use \"Email me a code\" to get a new one.", nil
		}
		if ok {
			if err := s.clearTwoFactorCode(ctx, repo.Repo.Did); err != nil {
				return "", err
			}
		}
	} else {
		ok, err = s.verifyStrongSecondFactor(ctx, repo.Repo.Did, creds, currentCode, now)
		if err != nil {
			return "", err
		}
	}
	if !ok {
		if err := s.recordSecondFactorFailure(ctx, repo.Repo.Did, now); err != nil {
			return "", err
		}
		return "That code is incorrect.", nil
	}
	if err := s.db.Exec(ctx, "UPDATE repos SET two_factor_failed_attempts = 0, two_factor_locked_until = NULL WHERE did = ?", nil, repo.Repo.Did).Error; err != nil {
		return "", err
	}
	return "", nil
}

// twoFactorSession loads the signed-in account and its methods, or reports
// that the caller should be sent to the signin page.
func (s *Server) twoFactorSession(e echo.Context) (*models.RepoActor, *sessions.Session, []models.TwoFactorCredential, error) {
	repo, sess, err := s.getSessionRepoOrErr(e)
	if err != nil {
		return nil, nil, nil, err
	}
	creds, err := s.getTwoFactorCredentials(e.Request().Context(), repo.Repo.Did)
	if err != nil {
		return nil, nil, nil, err
	}
	return repo, sess, creds, nil
}

func (s *Server) twoFactorSessionError(e echo.Context, err error) error {
	if errors.Is(err, ErrSessionUnauthenticated) {
		return e.Redirect(303, "/account/signin")
	}
	s.logger.Error("loading two factor settings", "error", err)
	return helpers.ServerError(e, nil)
}

func credentialTypeLabel(t models.TwoFactorCredentialType) string {
	switch t {
	case models.TwoFactorCredentialTOTP:
		return "Authenticator app"
	case models.TwoFactorCredentialYubicoOTP:
		return "YubiKey"
	}
	return string(t)
}

func (s *Server) handleAccountTwoFactor(e echo.Context) error {
	ctx := e.Request().Context()
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}

	var remaining int64
	if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM two_factor_backup_codes WHERE did = ? AND used_at IS NULL", nil, repo.Repo.Did).Scan(&remaining).Error; err != nil {
		return s.twoFactorSessionError(e, err)
	}

	type row struct {
		ID         uint
		Name       string
		Type       string
		CreatedAt  string
		LastUsedAt string
	}
	rows := make([]row, 0, len(creds))
	for _, c := range creds {
		r := row{ID: c.ID, Name: c.Name, Type: credentialTypeLabel(c.Type), CreatedAt: c.CreatedAt.Format("2006-01-02"), LastUsedAt: "never"}
		if c.LastUsedAt != nil {
			r.LastUsedAt = c.LastUsedAt.Format("2006-01-02 15:04 MST")
		}
		rows = append(rows, r)
	}

	return e.Render(200, "two_factor.html", map[string]any{
		"Repo":                 repo,
		"Credentials":          rows,
		"HasCredentials":       len(creds) > 0,
		"EmailTwoFactor":       repo.TwoFactorType != models.TwoFactorTypeNone,
		"BackupCodesRemaining": remaining,
		"flashes":              getFlashesFromSession(e, sess),
	})
}

// finishAddingCredential stores a new method. The first one also gets a
// fresh set of backup codes, which are shown once.
func (s *Server) finishAddingCredential(e echo.Context, sess *sessions.Session, repo *models.RepoActor, hadCredentials bool, cred *models.TwoFactorCredential) error {
	ctx := e.Request().Context()
	if err := s.db.Create(ctx, cred, nil).Error; err != nil {
		s.logger.Error("adding two factor credential", "error", err)
		return helpers.ServerError(e, nil)
	}
	if hadCredentials {
		sess.AddFlash(credentialTypeLabel(cred.Type)+" added.", "success")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/2fa")
	}
	codes, err := s.regenerateBackupCodes(ctx, repo.Repo.Did)
	if err != nil {
		s.logger.Error("creating backup codes", "error", err)
		return helpers.ServerError(e, nil)
	}
	return e.Render(200, "two_factor_backup_codes.html", map[string]any{
		"Repo":    repo,
		"Codes":   codes,
		"Message": credentialTypeLabel(cred.Type) + " added. Signing in now needs a code from it instead of an emailed code.",
	})
}

// setupPageData is shared by the authenticator app and YubiKey setup pages.
func setupPageData(repo *models.RepoActor, hasCredentials bool, errMsg string, flashes map[string]any) map[string]any {
	return map[string]any{
		"Repo":           repo,
		"HasCredentials": hasCredentials,
		"EmailOnly":      !hasCredentials && repo.TwoFactorType != models.TwoFactorTypeNone,
		"Error":          errMsg,
		"flashes":        flashes,
	}
}

func (s *Server) renderTOTPSetup(e echo.Context, status int, repo *models.RepoActor, hasCredentials bool, secret []byte, errMsg string, flashes map[string]any) error {
	uri := totp.URI(s.config.Hostname, repo.Handle, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		s.logger.Error("rendering qr code", "error", err)
		return helpers.ServerError(e, nil)
	}
	data := setupPageData(repo, hasCredentials, errMsg, flashes)
	data["Secret"] = totp.EncodeSecret(secret)
	data["QR"] = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	return e.Render(status, "two_factor_totp.html", data)
}

func (s *Server) handleAccountTwoFactorTOTPGet(e echo.Context) error {
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return helpers.ServerError(e, nil)
	}
	return s.renderTOTPSetup(e, 200, repo, len(creds) > 0, secret, "", getFlashesFromSession(e, sess))
}

func (s *Server) handleAccountTwoFactorTOTPPost(e echo.Context) error {
	ctx := e.Request().Context()
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}
	var req twoFactorManageInput
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, nil)
	}

	secret, err := totp.DecodeSecret(req.Secret)
	if err != nil || len(secret) != totp.SecretSize {
		// Not something the setup page produces; start over with a new secret.
		return e.Redirect(303, "/account/2fa/totp")
	}

	// Check the new code before the account checks, which consume a code.
	now := time.Now().UTC()
	step, ok := totp.Validate(secret, req.Code, now, 0)
	if !ok {
		return s.renderTOTPSetup(e, http.StatusBadRequest, repo, len(creds) > 0, secret, "That code doesn't match. Check your authenticator app and try again.", nil)
	}
	msg, err := s.authorizeTwoFactorChange(ctx, repo, creds, req.Password, req.CurrentCode)
	if err != nil {
		s.logger.Error("authorizing two factor change", "error", err)
		return helpers.ServerError(e, nil)
	}
	if msg != "" {
		return s.renderTOTPSetup(e, http.StatusBadRequest, repo, len(creds) > 0, secret, msg, nil)
	}

	return s.finishAddingCredential(e, sess, repo, len(creds) > 0, &models.TwoFactorCredential{
		Did:        repo.Repo.Did,
		Type:       models.TwoFactorCredentialTOTP,
		Name:       credentialName(req.Name, "Authenticator app"),
		CreatedAt:  now,
		Secret:     secret,
		LastStep:   step,
		LastUsedAt: &now,
	})
}

func (s *Server) renderYubiKeySetup(e echo.Context, status int, repo *models.RepoActor, hasCredentials bool, errMsg string, flashes map[string]any) error {
	return e.Render(status, "two_factor_yubikey.html", setupPageData(repo, hasCredentials, errMsg, flashes))
}

func (s *Server) handleAccountTwoFactorYubiKeyGet(e echo.Context) error {
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}
	return s.renderYubiKeySetup(e, 200, repo, len(creds) > 0, "", getFlashesFromSession(e, sess))
}

func (s *Server) handleAccountTwoFactorYubiKeyPost(e echo.Context) error {
	ctx := e.Request().Context()
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}
	var req twoFactorManageInput
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, nil)
	}

	key, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(req.AesKey), " ", ""))
	if err != nil || len(key) != yubiotp.KeySize {
		return s.renderYubiKeySetup(e, http.StatusBadRequest, repo, len(creds) > 0, "The secret key should be 32 hexadecimal characters.", nil)
	}
	otp, err := yubiotp.Parse(req.OTP, key)
	if err != nil {
		return s.renderYubiKeySetup(e, http.StatusBadRequest, repo, len(creds) > 0, "That YubiKey code doesn't match the secret key. Check you touched the slot you programmed.", nil)
	}

	msg, err := s.authorizeTwoFactorChange(ctx, repo, creds, req.Password, req.CurrentCode)
	if err != nil {
		s.logger.Error("authorizing two factor change", "error", err)
		return helpers.ServerError(e, nil)
	}
	if msg != "" {
		return s.renderYubiKeySetup(e, http.StatusBadRequest, repo, len(creds) > 0, msg, nil)
	}

	now := time.Now().UTC()
	return s.finishAddingCredential(e, sess, repo, len(creds) > 0, &models.TwoFactorCredential{
		Did:         repo.Repo.Did,
		Type:        models.TwoFactorCredentialYubicoOTP,
		Name:        credentialName(req.Name, "YubiKey"),
		CreatedAt:   now,
		Secret:      key,
		PublicID:    otp.PublicID,
		PrivateID:   otp.PrivateID[:],
		LastCounter: int(otp.Counter),
		LastUse:     int(otp.SessionUse),
		LastUsedAt:  &now,
	})
}

// handleAccountTwoFactorEmailCode emails a sign-in code to an account that
// uses email 2FA, so it can confirm adding its first authenticator.
func (s *Server) handleAccountTwoFactorEmailCode(e echo.Context) error {
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}
	next := e.FormValue("next")
	if next != "/account/2fa/totp" && next != "/account/2fa/yubikey" {
		next = "/account/2fa"
	}
	if len(creds) == 0 && repo.TwoFactorType != models.TwoFactorTypeNone {
		if err := s.createAndSendTwoFactorCode(e.Request().Context(), *repo); err != nil {
			s.logger.Error("sending two factor code", "error", err)
			sess.AddFlash("Couldn't send the email. Try again later.", "error")
		} else {
			sess.AddFlash("We've emailed you a code. It expires in ten minutes.", "success")
		}
		sess.Save(e.Request(), e.Response())
	}
	return e.Redirect(303, next)
}

func (s *Server) handleAccountTwoFactorRemove(e echo.Context) error {
	ctx := e.Request().Context()
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}
	var req twoFactorManageInput
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, nil)
	}

	msg, err := s.authorizeTwoFactorChange(ctx, repo, creds, req.Password, req.CurrentCode)
	if err != nil {
		s.logger.Error("authorizing two factor change", "error", err)
		return helpers.ServerError(e, nil)
	}
	if msg != "" {
		sess.AddFlash(msg, "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/2fa")
	}

	res := s.db.Exec(ctx, "DELETE FROM two_factor_credentials WHERE id = ? AND did = ?", nil, req.ID, repo.Repo.Did)
	if res.Error != nil {
		s.logger.Error("removing two factor credential", "error", res.Error)
		return helpers.ServerError(e, nil)
	}
	if res.RowsAffected == 0 {
		sess.AddFlash("That sign-in method was not found.", "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/2fa")
	}

	remaining, err := s.getTwoFactorCredentials(ctx, repo.Repo.Did)
	if err != nil {
		return helpers.ServerError(e, nil)
	}
	if len(remaining) == 0 {
		if err := s.db.Exec(ctx, "DELETE FROM two_factor_backup_codes WHERE did = ?", nil, repo.Repo.Did).Error; err != nil {
			return helpers.ServerError(e, nil)
		}
	}

	sess.AddFlash("Sign-in method removed.", "success")
	sess.Save(e.Request(), e.Response())
	return e.Redirect(303, "/account/2fa")
}

func (s *Server) handleAccountTwoFactorBackupCodes(e echo.Context) error {
	ctx := e.Request().Context()
	repo, sess, creds, err := s.twoFactorSession(e)
	if err != nil {
		return s.twoFactorSessionError(e, err)
	}
	var req twoFactorManageInput
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, nil)
	}
	if len(creds) == 0 {
		sess.AddFlash("Add an authenticator app or YubiKey first.", "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/2fa")
	}

	msg, err := s.authorizeTwoFactorChange(ctx, repo, creds, req.Password, req.CurrentCode)
	if err != nil {
		s.logger.Error("authorizing two factor change", "error", err)
		return helpers.ServerError(e, nil)
	}
	if msg != "" {
		sess.AddFlash(msg, "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/2fa")
	}

	codes, err := s.regenerateBackupCodes(ctx, repo.Repo.Did)
	if err != nil {
		s.logger.Error("creating backup codes", "error", err)
		return helpers.ServerError(e, nil)
	}
	return e.Render(200, "two_factor_backup_codes.html", map[string]any{
		"Repo":    repo,
		"Codes":   codes,
		"Message": "New backup codes created. Your old ones no longer work.",
	})
}
