package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

const (
	OauthClientAssertionTypeJwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	OauthParExpiresIn                 = 5 * time.Minute

	OauthClientAssertionMaxAge = 1 * time.Minute

	OauthDeviceIdPrefix      = "dev-"
	OauthDeviceIdBytesLength = 16

	OauthSessionIdPrefix      = "ses-"
	OauthSessionIdBytesLength = 16

	OauthRefreshTokenPrefix      = "ref-"
	OauthRefreshTokenBytesLength = 32

	OauthRequestIdPrefix      = "req-"
	OauthRequestIdBytesLength = 16
	OauthRequestUriPrefix     = "urn:ietf:params:oauth:request_uri:"

	OauthCodePrefix      = "cod-"
	OauthCodeBytesLength = 32

	OauthTokenIdPrefix      = "tok-"
	OauthTokenIdBytesLength = 16

	OauthTokenMaxAge = 60 * time.Minute

	OauthAuthorizationInactivityTimeout = 5 * time.Minute

	OauthDpopNonceMaxAge = 3 * time.Minute

	OauthConfidentialClientSessionLifetime = 2 * 365 * 24 * time.Hour // 2 years
	OauthConfidentialClientRefreshLifetime = 3 * 30 * 24 * time.Hour  // 3 months

	OauthPublicClientSessionLifetime = 2 * 7 * 24 * time.Hour // 2 weeks
	OauthPublicClientRefreshLifetime = OauthPublicClientSessionLifetime
)

type DpopProof struct {
	JTI string
	JKT string
	HTM string
	HTU string
}

func (s *Server) handleOauthBaseMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		e.Response().Header().Set("cache-control", "no-store")
		e.Response().Header().Set("pragma", "no-cache")

		nonce := s.oauthDpopMan.nonce.Next()
		if nonce != "" {
			e.Response().Header().Set("DPoP-Nonce", nonce)
			e.Response().Header().Add("access-control-expose-headers", "DPoP-Nonce")
		}

		return next(e)
	}
}

type OauthAuthenticateClientOptions struct {
	AllowMissingDpopProof bool
}

type OauthAuthenticateClientRequestBase struct {
	ClientID            string  `form:"client_id" json:"client_id" validate:"required"`
	ClientAssertionType *string `form:"client_assertion_type" json:"client_assertion_type,omitempty"`
	ClientAssertion     *string `form:"client_assertion" json:"client_assertion,omitempty"`
}

func (s *Server) oauthAuthenticateClient(ctx context.Context, req models.OauthAuthenticateClientRequestBase, dpopProof *DpopProof, opts *OauthAuthenticateClientOptions) (*OauthClient, *models.OauthClientAuth, error) {
	client, err := s.oauthClientMan.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get client: %w", err)
	}

	if client.Metadata.DpopBoundAccessTokens && dpopProof == nil && (opts == nil || !opts.AllowMissingDpopProof) {
		return nil, nil, errors.New("dpop proof required")
	}

	if dpopProof != nil && !client.Metadata.DpopBoundAccessTokens {
		return nil, nil, errors.New("dpop proof not allowed for this client")
	}

	clientAuth, err := s.oauthAuthenticate(ctx, req, client)
	if err != nil {
		return nil, nil, err
	}

	return client, clientAuth, nil
}

func (s *Server) oauthAuthenticate(_ context.Context, req models.OauthAuthenticateClientRequestBase, client *OauthClient) (*models.OauthClientAuth, error) {
	metadata := client.Metadata

	if metadata.TokenEndpointAuthMethod == "none" {
		return &models.OauthClientAuth{
			Method: "none",
		}, nil
	}

	if metadata.TokenEndpointAuthMethod == "private_key_jwt" {
		if req.ClientAssertion == nil {
			return nil, errors.New(`client authentication method "private_key_jwt" requires a "client_assertion`)
		}

		if req.ClientAssertionType == nil || *req.ClientAssertionType != OauthClientAssertionTypeJwtBearer {
			return nil, fmt.Errorf("unsupported client_assertion_type %s", *req.ClientAssertionType)
		}

		token, _, err := jwt.NewParser().ParseUnverified(*req.ClientAssertion, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("error parsing client assertion: %w", err)
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New(`"kid" required in client_assertion`)
		}

		var rawKey any
		if err := client.JWKS.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to extract raw key: %w", err)
		}

		token, err = jwt.Parse(*req.ClientAssertion, func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return rawKey, nil
		})
		if err != nil {
			return nil, fmt.Errorf(`unable to verify "client_assertion" jwt: %w`, err)
		}

		if !token.Valid {
			return nil, errors.New("client_assertion jwt is invalid")
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("no claims in client_assertion jwt")
		}

		sub, _ := claims["sub"].(string)
		if sub != metadata.ClientID {
			return nil, errors.New("subject must be client_id")
		}

		aud, _ := claims["aud"].(string)
		if aud != "" && aud != "https://"+s.config.Hostname {
			return nil, fmt.Errorf("audience must be %s, got %s", "https://"+s.config.Hostname, aud)
		}

		iat, iatOk := claims["iat"].(float64)
		if !iatOk {
			return nil, errors.New(`invalid client_assertion jwt: "iat" is missing`)
		}

		iatTime := time.Unix(int64(iat), 0)
		if time.Since(iatTime) > OauthClientAssertionMaxAge {
			return nil, errors.New("client_assertion jwt too old")
		}

		jti, _ := claims["jti"].(string)
		if jti == "" {
			return nil, errors.New(`invalid client_assertion jwt: "jti" is missing`)
		}

		var exp *float64
		if maybeExp, ok := claims["exp"].(float64); ok {
			exp = &maybeExp
		}

		alg := token.Header["alg"].(string)

		thumbBytes, err := client.JWKS.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate thumbprint: %w", err)
		}

		thumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

		return &models.OauthClientAuth{
			Method: "private_key_jwt",
			Jti:    jti,
			Exp:    exp,
			Jkt:    thumb,
			Alg:    alg,
			Kid:    kid,
		}, nil
	}

	return nil, fmt.Errorf("auth method %s is not implemented in this pds", metadata.TokenEndpointAuthMethod)
}

func generateRequestId() string {
	h, _ := helpers.RandomHex(OauthRequestIdBytesLength)
	return OauthRequestIdPrefix + h
}

func encodeRequestUri(reqId string) string {
	return OauthRequestUriPrefix + url.QueryEscape(reqId)
}

func decodeRequestUri(reqUri string) (string, error) {
	if len(reqUri) < len(OauthRequestUriPrefix) {
		return "", errors.New("invalid request uri")
	}

	reqIdEnc := reqUri[len(OauthRequestUriPrefix):]
	reqId, err := url.QueryUnescape(reqIdEnc)
	if err != nil {
		return "", fmt.Errorf("could not unescape request id: %w", err)
	}

	return reqId, nil
}

func generateCode() string {
	h, _ := helpers.RandomHex(OauthCodeBytesLength)
	return OauthCodePrefix + h
}

func generateTokenId() string {
	h, _ := helpers.RandomHex(OauthTokenIdBytesLength)
	return OauthTokenIdPrefix + h
}

func generateRefreshToken() string {
	h, _ := helpers.RandomHex(OauthRefreshTokenBytesLength)
	return OauthRefreshTokenPrefix + h
}
