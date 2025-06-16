package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type OauthTokenRequest struct {
	models.OauthAuthenticateClientRequestBase
	GrantType    string  `form:"grant_type" json:"grant_type"`
	Code         *string `form:"code" json:"code,omitempty"`
	CodeVerifier *string `form:"code_verifier" json:"code_verifier,omitempty"`
	RedirectURI  *string `form:"redirect_uri" json:"redirect_uri,omitempty"`
	RefreshToken *string `form:"refresh_token" json:"refresh_token,omitempty"`
}

type OauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	Sub          string `json:"sub"`
}

func (s *Server) handleOauthToken(e echo.Context) error {
	var req OauthTokenRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding token request", "error", err)
		return helpers.ServerError(e, nil)
	}

	dpopProof, err := s.oauthDpopMan.CheckProof(e.Request().Method, "https://"+s.config.Hostname+e.Request().URL.String(), e.Request().Header, nil)
	if err != nil {
		s.logger.Error("error getting dpop proof", "error", err)
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	client, clientAuth, err := s.oauthAuthenticateClient(e.Request().Context(), req.OauthAuthenticateClientRequestBase, dpopProof, &OauthAuthenticateClientOptions{
		AllowMissingDpopProof: true,
	})
	if err != nil {
		s.logger.Error("error authenticating client", "error", err)
		return helpers.InputError(e, to.StringPtr(err.Error()))
	}

	// TODO: this should come from an oauth provier config
	if !slices.Contains([]string{"authorization_code", "refresh_token"}, req.GrantType) {
		return helpers.InputError(e, to.StringPtr(fmt.Sprintf(`"%s" grant type is not supported by the server`, req.GrantType)))
	}

	if !slices.Contains(client.Metadata.GrantTypes, req.GrantType) {
		return helpers.InputError(e, to.StringPtr(fmt.Sprintf(`"%s" grant type is not supported by the client`, req.GrantType)))
	}

	if req.GrantType == "authorization_code" {
		if req.Code == nil {
			return helpers.InputError(e, to.StringPtr(`"code" is required"`))
		}

		var authReq models.OauthAuthorizationRequest
		// get the lil guy and delete him
		if err := s.db.Raw("DELETE FROM oauth_authorization_requests WHERE code = ? RETURNING *", nil, *req.Code).Scan(&authReq).Error; err != nil {
			s.logger.Error("error finding authorization request", "error", err)
			return helpers.ServerError(e, nil)
		}

		if req.RedirectURI == nil || *req.RedirectURI != authReq.Parameters.RedirectURI {
			return helpers.InputError(e, to.StringPtr(`"redirect_uri" mismatch`))
		}

		if authReq.Parameters.CodeChallenge != nil {
			if req.CodeVerifier == nil {
				return helpers.InputError(e, to.StringPtr(`"code_verifier" is required`))
			}

			if len(*req.CodeVerifier) < 43 {
				return helpers.InputError(e, to.StringPtr(`"code_verifier" is too short`))
			}

			switch *&authReq.Parameters.CodeChallengeMethod {
			case "", "plain":
				if authReq.Parameters.CodeChallenge != req.CodeVerifier {
					return helpers.InputError(e, to.StringPtr("invalid code_verifier"))
				}
			case "S256":
				inputChal, err := base64.StdEncoding.DecodeString(*authReq.Parameters.CodeChallenge)
				if err != nil {
					s.logger.Error("error decoding code challenge", "error", err)
					return helpers.ServerError(e, nil)
				}

				h := sha256.New()
				h.Write([]byte(*req.CodeVerifier))
				compdChal := h.Sum(nil)

				if !bytes.Equal(inputChal, compdChal) {
					return helpers.InputError(e, to.StringPtr("invalid code_verifier"))
				}
			default:
				return helpers.InputError(e, to.StringPtr("unsupported code_challenge_method "+*&authReq.Parameters.CodeChallengeMethod))
			}
		} else if req.CodeVerifier != nil {
			return helpers.InputError(e, to.StringPtr("code_challenge parameter wasn't provided"))
		}

		repo, err := s.getRepoActorByDid(*authReq.Sub)
		if err != nil {
			helpers.InputError(e, to.StringPtr("unable to find actor"))
		}

		now := time.Now()
		eat := now.Add(OauthTokenMaxAge)
		id := generateTokenId()

		refreshToken := generateRefreshToken()

		accessClaims := jwt.MapClaims{
			"scope":     authReq.Parameters.Scope,
			"aud":       s.config.Did,
			"sub":       repo.Repo.Did,
			"iat":       now.Unix(),
			"exp":       eat.Unix(),
			"jti":       id,
			"client_id": authReq.ClientId,
		}

		if authReq.Parameters.DpopJkt != nil {
			accessClaims["cnf"] = *authReq.Parameters.DpopJkt
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
		accessString, err := accessToken.SignedString(s.privateKey)
		if err != nil {
			return err
		}

		if err := s.db.Create(&models.OauthToken{
			ClientId:     authReq.ClientId,
			ClientAuth:   *clientAuth,
			Parameters:   authReq.Parameters,
			ExpiresAt:    eat,
			DeviceId:     "",
			Sub:          repo.Repo.Did,
			Code:         *authReq.Code,
			Token:        accessString,
			RefreshToken: refreshToken,
		}, nil).Error; err != nil {
			s.logger.Error("error creating token in db", "error", err)
			return helpers.ServerError(e, nil)
		}

		// prob not needed
		tokenType := "Bearer"
		if authReq.Parameters.DpopJkt != nil {
			tokenType = "DPoP"
		}

		return e.JSON(200, OauthTokenResponse{
			AccessToken:  accessString,
			RefreshToken: refreshToken,
			TokenType:    tokenType,
			Scope:        authReq.Parameters.Scope,
			ExpiresIn:    int64(eat.Sub(time.Now()).Seconds()),
			Sub:          repo.Repo.Did,
		})
	}

	if req.GrantType == "refresh_token" {
		if req.RefreshToken == nil {
			return helpers.InputError(e, to.StringPtr(`"refresh_token" is required`))
		}

		var oauthToken models.OauthToken
		if err := s.db.Raw("SELECT * FROM oauth_tokens WHERE refresh_token = ?", nil, req.RefreshToken).Scan(&oauthToken).Error; err != nil {
			s.logger.Error("error finding oauth token by refresh token", "error", err, "refresh_token", req.RefreshToken)
			return helpers.ServerError(e, nil)
		}

		if client.Metadata.ClientID != oauthToken.ClientId {
			return helpers.InputError(e, to.StringPtr(`"client_id" mismatch`))
		}

		if clientAuth.Method != oauthToken.ClientAuth.Method {
			return helpers.InputError(e, to.StringPtr(`"client authentication method mismatch`))
		}

		if *oauthToken.Parameters.DpopJkt != dpopProof.JKT {
			return helpers.InputError(e, to.StringPtr("dpop proof does not match expected jkt"))
		}

		sessionLifetime := OauthPublicClientSessionLifetime
		refreshLifetime := OauthPublicClientRefreshLifetime
		if clientAuth.Method != "none" {
			sessionLifetime = OauthConfidentialClientSessionLifetime
			refreshLifetime = OauthConfidentialClientRefreshLifetime
		}

		sessionAge := time.Since(oauthToken.CreatedAt)
		if sessionAge > sessionLifetime {
			return helpers.InputError(e, to.StringPtr("Session expired"))
		}

		refreshAge := time.Since(oauthToken.UpdatedAt)
		if refreshAge > refreshLifetime {
			return helpers.InputError(e, to.StringPtr("Refresh token expired"))
		}

		if client.Metadata.DpopBoundAccessTokens && oauthToken.Parameters.DpopJkt == nil {
			// why? ref impl
			return helpers.InputError(e, to.StringPtr("dpop jkt is required for dpop bound access tokens"))
		}

		nextTokenId := generateTokenId()
		nextRefreshToken := generateRefreshToken()

		now := time.Now()
		eat := now.Add(OauthTokenMaxAge)

		refreshToken := generateRefreshToken()

		accessClaims := jwt.MapClaims{
			"scope":     oauthToken.Parameters.Scope,
			"aud":       s.config.Did,
			"sub":       oauthToken.Sub,
			"iat":       now.Unix(),
			"exp":       eat.Unix(),
			"jti":       nextTokenId,
			"client_id": oauthToken.ClientId,
		}

		if oauthToken.Parameters.DpopJkt != nil {
			accessClaims["cnf"] = *&oauthToken.Parameters.DpopJkt
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
		accessString, err := accessToken.SignedString(s.privateKey)
		if err != nil {
			return err
		}

		if err := s.db.Exec("UPDATE oauth_tokens SET token = ?, refresh_token = ?, expires_at = ?, updated_at = ? WHERE refresh_token = ?", nil, accessString, nextRefreshToken, eat, now, *req.RefreshToken).Error; err != nil {
			s.logger.Error("error updating token", "error", err)
			return helpers.ServerError(e, nil)
		}

		// prob not needed
		tokenType := "Bearer"
		if oauthToken.Parameters.DpopJkt != nil {
			tokenType = "DPoP"
		}

		return e.JSON(200, OauthTokenResponse{
			AccessToken:  accessString,
			RefreshToken: refreshToken,
			TokenType:    tokenType,
			Scope:        oauthToken.Parameters.Scope,
			ExpiresIn:    int64(eat.Sub(time.Now()).Seconds()),
			Sub:          oauthToken.Sub,
		})
	}

	return helpers.InputError(e, to.StringPtr(fmt.Sprintf(`grant type "%s" is not supported`, req.GrantType)))
}
