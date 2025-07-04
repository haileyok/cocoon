package server

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

func (s *Server) handleAccountTotpEnrollGet(e echo.Context) error {
	urepo, sess, err := s.getSessionRepoOrErr(e)
	if err != nil {
		return e.Redirect(303, "/account/signin")
	}

	if urepo.TwoFactorType == models.TwoFactorTypeTotp {
		sess.AddFlash("You have already enabled TOTP", "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account")
	} else if urepo.TwoFactorType != models.TwoFactorTypeNone {
		sess.AddFlash("You have already have another 2FA method enabled", "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account")
	}

	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.Hostname,
		AccountName: urepo.Repo.Did,
	})
	if err != nil {
		s.logger.Error("error generating totp secret", "error", err)
		return helpers.ServerError(e, nil)
	}

	sess.Values["totp-secret"] = secret
	if err := sess.Save(e.Request(), e.Response()); err != nil {
		s.logger.Error("error saving session", "error", err)

		return helpers.ServerError(e, nil)
	}

	var buf bytes.Buffer
	img, err := secret.Image(200, 200)
	if err != nil {
		s.logger.Error("error generating image from secret", "error", err)
		return helpers.ServerError(e, nil)
	}
	png.Encode(&buf, img)

	b64img := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(buf.Bytes()))

	return e.Render(200, "totp_enroll.html", map[string]any{
		"flashes": getFlashesFromSession(e, sess),
		"Image":   b64img,
	})
}

type TotpEnrollRequest struct {
	Code string `form:"code"`
}

func (s *Server) handleAccountTotpEnrollPost(e echo.Context) error {
	urepo, sess, err := s.getSessionRepoOrErr(e)
	if err != nil {
		return e.Redirect(303, "/account/signin")
	}

	var req TotpEnrollRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding request for enroll totp", "error", err)
		return helpers.ServerError(e, nil)
	}

	secret, ok := sess.Values["totp-secret"].(string)
	if !ok {
		return helpers.InputError(e, nil)
	}

	if !totp.Validate(req.Code, secret) {
		sess.AddFlash("The provided code was not valid.", "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/totp-enroll")
	}

	if err := s.db.Exec("UPDATE repos SET two_factor_type = ?, totp_secret = ? WHERE did = ?", nil, models.TwoFactorTypeTotp, secret, urepo.Repo.Did).Error; err != nil {
		s.logger.Error("error updating database with totp token", "error", err)
		return helpers.ServerError(e, nil)
	}

	sess.AddFlash("You have successfully enrolled in TOTP!", "success")
	delete(sess.Values, "totp-secret")
	sess.Save(e.Request(), e.Response())

	return e.Redirect(303, "/account")
}
