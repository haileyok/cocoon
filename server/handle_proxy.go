package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	secp256k1secec "gitlab.com/yawning/secp256k1-voi/secec"
)

func (s *Server) getAtprotoProxyEndpointFromRequest(e echo.Context) (string, string, error) {
	svc := e.Request().Header.Get("atproto-proxy")
	if svc == "" && s.config.FallbackProxy != "" {
		svc = s.config.FallbackProxy
	}

	svcPts := strings.Split(svc, "#")
	if len(svcPts) != 2 {
		return "", "", fmt.Errorf("invalid service header")
	}

	svcDid := svcPts[0]
	svcId := "#" + svcPts[1]

	doc, err := s.passport.FetchDoc(e.Request().Context(), svcDid)
	if err != nil {
		return "", "", err
	}

	var endpoint string
	for _, s := range doc.Service {
		if s.Id == svcId {
			endpoint = s.ServiceEndpoint
		}
	}

	return endpoint, svcDid, nil
}

func (s *Server) handleProxy(e echo.Context) error {
	lgr := s.logger.With("handler", "handleProxy")

	repo, isAuthed := e.Get("repo").(*models.RepoActor)

	pts := strings.Split(e.Request().URL.Path, "/")
	if len(pts) != 3 {
		return fmt.Errorf("incorrect number of parts")
	}

	endpoint, svcDid, err := s.getAtprotoProxyEndpointFromRequest(e)
	if err != nil {
		lgr.Error("could not get atproto proxy", "error", err)
		return helpers.ServerError(e, nil)
	}

	requrl := e.Request().URL
	requrl.Host = strings.TrimPrefix(endpoint, "https://")
	requrl.Scheme = "https"

	body := e.Request().Body
	if e.Request().Method == "GET" {
		body = nil
	}

	req, err := http.NewRequest(e.Request().Method, requrl.String(), body)
	if err != nil {
		return err
	}

	req.Header = e.Request().Header.Clone()

	if isAuthed {
		// this is a little dumb. i should probably figure out a better way to do this, and use
		// a single way of creating/signing jwts throughout the pds. kinda limited here because
		// im using the atproto crypto lib for this though. will come back to it

		header := map[string]string{
			"alg": "ES256K",
			"crv": "secp256k1",
			"typ": "JWT",
		}
		hj, err := json.Marshal(header)
		if err != nil {
			lgr.Error("error marshaling header", "error", err)
			return helpers.ServerError(e, nil)
		}

		encheader := strings.TrimRight(base64.RawURLEncoding.EncodeToString(hj), "=")

		// When proxying app.bsky.feed.getFeed the token is actually issued for the
		// underlying feed generator and the app view passes it on. This allows the
		// getFeed implementation to pass in the desired lxm and aud for the token
		// and then just delegate to the general proxying logic
		lxm, proxyTokenLxmExists := e.Get("proxyTokenLxm").(string)
		if !proxyTokenLxmExists || lxm == "" {
			lxm = pts[2]
		}
		aud, proxyTokenAudExists := e.Get("proxyTokenAud").(string)
		if !proxyTokenAudExists || aud == "" {
			aud = svcDid
		}

		payload := map[string]any{
			"iss": repo.Repo.Did,
			"aud": svcDid,
			"lxm": lxm,
			"jti": uuid.NewString(),
			"exp": time.Now().Add(1 * time.Minute).UTC().Unix(),
		}
		pj, err := json.Marshal(payload)
		if err != nil {
			lgr.Error("error marashaling payload", "error", err)
			return helpers.ServerError(e, nil)
		}

		encpayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

		input := fmt.Sprintf("%s.%s", encheader, encpayload)
		hash := sha256.Sum256([]byte(input))

		sk, err := secp256k1secec.NewPrivateKey(repo.SigningKey)
		if err != nil {
			lgr.Error("can't load private key", "error", err)
			return err
		}

		R, S, _, err := sk.SignRaw(rand.Reader, hash[:])
		if err != nil {
			lgr.Error("error signing", "error", err)
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

		req.Header.Set("authorization", "Bearer "+token)
	} else {
		req.Header.Del("authorization")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		e.Response().Header().Set(k, strings.Join(v, ","))
	}

	return e.Stream(resp.StatusCode, e.Response().Header().Get("content-type"), resp.Body)
}
