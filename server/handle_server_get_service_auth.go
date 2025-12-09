package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	secp256k1secec "gitlab.com/yawning/secp256k1-voi/secec"
)

type ServerGetServiceAuthRequest struct {
	Aud string `query:"aud" validate:"required,atproto-did"`
	// exp should be a float, as some clients will send a non-integer expiration
	Exp float64 `query:"exp"`
	Lxm string  `query:"lxm"`
}

func (s *Server) handleServerGetServiceAuth(e echo.Context) error {
	var req ServerGetServiceAuthRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("could not bind service auth request", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	exp := int64(req.Exp)
	now := time.Now().Unix()
	if exp == 0 {
		exp = now + 60 // default
	}

	if req.Lxm == "com.atproto.server.getServiceAuth" {
		return helpers.InputError(e, to.StringPtr("may not generate auth tokens recursively"))
	}

	var maxExp int64
	if req.Lxm != "" {
		maxExp = now + (60 * 60)
	} else {
		maxExp = now + 60
	}
	if exp > maxExp {
		return helpers.InputError(e, to.StringPtr("expiration too big. smoller please"))
	}

	repo := e.Get("repo").(*models.RepoActor)

	header := map[string]string{
		"alg": "ES256K",
		"crv": "secp256k1",
		"typ": "JWT",
	}
	hj, err := json.Marshal(header)
	if err != nil {
		s.logger.Error("error marshaling header", "error", err)
		return helpers.ServerError(e, nil)
	}

	encheader := strings.TrimRight(base64.RawURLEncoding.EncodeToString(hj), "=")

	payload := map[string]any{
		"iss": repo.Repo.Did,
		"aud": req.Aud,
		"jti": uuid.NewString(),
		"exp": exp,
		"iat": now,
	}
	if req.Lxm != "" {
		payload["lxm"] = req.Lxm
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("error marashaling payload", "error", err)
		return helpers.ServerError(e, nil)
	}

	encpayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

	input := fmt.Sprintf("%s.%s", encheader, encpayload)
	hash := sha256.Sum256([]byte(input))

	sk, err := secp256k1secec.NewPrivateKey(repo.SigningKey)
	if err != nil {
		s.logger.Error("can't load private key", "error", err)
		return err
	}

	R, S, _, err := sk.SignRaw(rand.Reader, hash[:])
	if err != nil {
		s.logger.Error("error signing", "error", err)
		return helpers.ServerError(e, nil)
	}

	rBytes := R.Bytes()
	sBytes := S.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	rawsig := append(rPadded, sPadded...)
	encsig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(rawsig), "=")
	token := fmt.Sprintf("%s.%s", input, encsig)

	return e.JSON(200, map[string]string{
		"token": token,
	})
}
