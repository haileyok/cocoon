package oauth

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/constants"
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
