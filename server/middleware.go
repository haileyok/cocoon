package server

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
	"gitlab.com/yawning/secp256k1-voi"
	secp256k1secec "gitlab.com/yawning/secp256k1-voi/secec"
	"gorm.io/gorm"
)

func (s *Server) handleAdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		username, password, ok := e.Request().BasicAuth()
		if !ok || username != "admin" || password != s.config.AdminPassword {
			return helpers.InputError(e, to.StringPtr("Unauthorized"))
		}

		if err := next(e); err != nil {
			e.Error(err)
		}

		return nil
	}
}

func (s *Server) handleLegacySessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		authheader := e.Request().Header.Get("authorization")
		if authheader == "" {
			return e.JSON(401, map[string]string{"error": "Unauthorized"})
		}

		pts := strings.Split(authheader, " ")
		if len(pts) != 2 {
			return helpers.ServerError(e, nil)
		}

		// move on to oauth session middleware if this is a dpop token
		if pts[0] == "DPoP" {
			return next(e)
		}

		tokenstr := pts[1]
		token, _, err := new(jwt.Parser).ParseUnverified(tokenstr, jwt.MapClaims{})
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return helpers.InvalidTokenError(e)
		}

		var did string
		var repo *models.RepoActor

		// service auth tokens
		lxm, hasLxm := claims["lxm"]
		if hasLxm {
			pts := strings.Split(e.Request().URL.String(), "/")
			if lxm != pts[len(pts)-1] {
				s.logger.Error("service auth lxm incorrect", "lxm", lxm, "expected", pts[len(pts)-1], "error", err)
				return helpers.InputError(e, nil)
			}

			maybeDid, ok := claims["iss"].(string)
			if !ok {
				s.logger.Error("no iss in service auth token", "error", err)
				return helpers.InputError(e, nil)
			}
			did = maybeDid

			maybeRepo, err := s.getRepoActorByDid(did)
			if err != nil {
				s.logger.Error("error fetching repo", "error", err)
				return helpers.ServerError(e, nil)
			}
			repo = maybeRepo
		}

		if token.Header["alg"] != "ES256K" {
			token, err = new(jwt.Parser).Parse(tokenstr, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unsupported signing method: %v", t.Header["alg"])
				}
				return s.privateKey.Public(), nil
			})
			if err != nil {
				s.logger.Error("error parsing jwt", "error", err)
				return helpers.ExpiredTokenError(e)
			}

			if !token.Valid {
				return helpers.InvalidTokenError(e)
			}
		} else {
			kpts := strings.Split(tokenstr, ".")
			signingInput := kpts[0] + "." + kpts[1]
			hash := sha256.Sum256([]byte(signingInput))
			sigBytes, err := base64.RawURLEncoding.DecodeString(kpts[2])
			if err != nil {
				s.logger.Error("error decoding signature bytes", "error", err)
				return helpers.ServerError(e, nil)
			}

			if len(sigBytes) != 64 {
				s.logger.Error("incorrect sigbytes length", "length", len(sigBytes))
				return helpers.ServerError(e, nil)
			}

			rBytes := sigBytes[:32]
			sBytes := sigBytes[32:]
			rr, _ := secp256k1.NewScalarFromBytes((*[32]byte)(rBytes))
			ss, _ := secp256k1.NewScalarFromBytes((*[32]byte)(sBytes))

			sk, err := secp256k1secec.NewPrivateKey(repo.SigningKey)
			if err != nil {
				s.logger.Error("can't load private key", "error", err)
				return err
			}

			pubKey, ok := sk.Public().(*secp256k1secec.PublicKey)
			if !ok {
				s.logger.Error("error getting public key from sk")
				return helpers.ServerError(e, nil)
			}

			verified := pubKey.VerifyRaw(hash[:], rr, ss)
			if !verified {
				s.logger.Error("error verifying", "error", err)
				return helpers.ServerError(e, nil)
			}
		}

		isRefresh := e.Request().URL.Path == "/xrpc/com.atproto.server.refreshSession"
		scope, _ := claims["scope"].(string)

		if isRefresh && scope != "com.atproto.refresh" {
			return helpers.InvalidTokenError(e)
		} else if !hasLxm && !isRefresh && scope != "com.atproto.access" {
			return helpers.InvalidTokenError(e)
		}

		table := "tokens"
		if isRefresh {
			table = "refresh_tokens"
		}

		if isRefresh {
			type Result struct {
				Found bool
			}
			var result Result
			if err := s.db.Raw("SELECT EXISTS(SELECT 1 FROM "+table+" WHERE token = ?) AS found", nil, tokenstr).Scan(&result).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					return helpers.InvalidTokenError(e)
				}

				s.logger.Error("error getting token from db", "error", err)
				return helpers.ServerError(e, nil)
			}

			if !result.Found {
				return helpers.InvalidTokenError(e)
			}
		}

		exp, ok := claims["exp"].(float64)
		if !ok {
			s.logger.Error("error getting iat from token")
			return helpers.ServerError(e, nil)
		}

		if exp < float64(time.Now().UTC().Unix()) {
			return helpers.ExpiredTokenError(e)
		}

		if repo == nil {
			maybeRepo, err := s.getRepoActorByDid(claims["sub"].(string))
			if err != nil {
				s.logger.Error("error fetching repo", "error", err)
				return helpers.ServerError(e, nil)
			}
			repo = maybeRepo
			did = repo.Repo.Did
		}

		e.Set("repo", repo)
		e.Set("did", did)
		e.Set("token", tokenstr)

		if err := next(e); err != nil {
			return helpers.InvalidTokenError(e)
		}

		return nil
	}
}

func (s *Server) handleOauthSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		authheader := e.Request().Header.Get("authorization")
		if authheader == "" {
			return e.JSON(401, map[string]string{"error": "Unauthorized"})
		}

		pts := strings.Split(authheader, " ")
		if len(pts) != 2 {
			return helpers.ServerError(e, nil)
		}

		if pts[0] != "DPoP" {
			return next(e)
		}

		accessToken := pts[1]

		nonce := s.oauthProvider.NextNonce()
		if nonce != "" {
			e.Response().Header().Set("DPoP-Nonce", nonce)
			e.Response().Header().Add("access-control-expose-headers", "DPoP-Nonce")
		}

		proof, err := s.oauthProvider.DpopManager.CheckProof(e.Request().Method, "https://"+s.config.Hostname+e.Request().URL.String(), e.Request().Header, to.StringPtr(accessToken))
		if err != nil {
			if errors.Is(err, dpop.ErrUseDpopNonce) {
				return e.JSON(401, map[string]string{
					"error": "use_dpop_nonce",
				})
			}
			s.logger.Error("invalid dpop proof", "error", err)
			return helpers.InputError(e, nil)
		}

		var oauthToken provider.OauthToken
		if err := s.db.Raw("SELECT * FROM oauth_tokens WHERE token = ?", nil, accessToken).Scan(&oauthToken).Error; err != nil {
			s.logger.Error("error finding access token in db", "error", err)
			return helpers.InputError(e, nil)
		}

		if oauthToken.Token == "" {
			return helpers.InvalidTokenError(e)
		}

		if *oauthToken.Parameters.DpopJkt != proof.JKT {
			s.logger.Error("jkt mismatch", "token", oauthToken.Parameters.DpopJkt, "proof", proof.JKT)
			return helpers.InputError(e, to.StringPtr("dpop jkt mismatch"))
		}

		if time.Now().After(oauthToken.ExpiresAt) {
			return helpers.ExpiredTokenError(e)
		}

		repo, err := s.getRepoActorByDid(oauthToken.Sub)
		if err != nil {
			s.logger.Error("could not find actor in db", "error", err)
			return helpers.ServerError(e, nil)
		}

		e.Set("repo", repo)
		e.Set("did", repo.Repo.Did)
		e.Set("token", accessToken)
		e.Set("scopes", strings.Split(oauthToken.Parameters.Scope, " "))

		return next(e)
	}
}
