package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/provider"
)

func GenerateCode() string {
	h, _ := helpers.RandomHex(constants.CodeBytesLength)
	return constants.CodePrefix + h
}

func GenerateTokenId() string {
	h, _ := helpers.RandomHex(constants.TokenIdBytesLength)
	return constants.TokenIdPrefix + h
}

func GenerateRefreshToken() string {
	h, _ := helpers.RandomHex(constants.RefreshTokenBytesLength)
	return constants.RefreshTokenPrefix + h
}

func GenerateRequestId() string {
	h, _ := helpers.RandomHex(constants.RequestIdBytesLength)
	return constants.RequestIdPrefix + h
}

func EncodeRequestUri(reqId string) string {
	return constants.RequestUriPrefix + url.QueryEscape(reqId)
}

func DecodeRequestUri(reqUri string) (string, error) {
	if len(reqUri) < len(constants.RequestUriPrefix) {
		return "", errors.New("invalid request uri")
	}

	reqIdEnc := reqUri[len(constants.RequestUriPrefix):]
	reqId, err := url.QueryUnescape(reqIdEnc)
	if err != nil {
		return "", fmt.Errorf("could not unescape request id: %w", err)
	}

	return reqId, nil
}

type SessionAgeResult struct {
	SessionAge     time.Duration
	RefreshAge     time.Duration
	SessionExpired bool
	RefreshExpired bool
}

func GetSessionLifetimes(t provider.OauthToken) (session, refresh time.Duration) {
	if t.ClientAuth.Method != "none" {
		return constants.ConfidentialClientSessionLifetime, constants.ConfidentialClientRefreshLifetime
	}
	return constants.PublicClientSessionLifetime, constants.PublicClientRefreshLifetime
}

func GetSessionAgeFromToken(t provider.OauthToken) SessionAgeResult {
	sessionLifetime, refreshLifetime := GetSessionLifetimes(t)
	res := SessionAgeResult{}

	res.SessionAge = time.Since(t.CreatedAt)
	if res.SessionAge > sessionLifetime {
		res.SessionExpired = true
	}

	refreshAge := time.Since(t.UpdatedAt)
	if refreshAge > refreshLifetime {
		res.RefreshExpired = true
	}

	return res
}
