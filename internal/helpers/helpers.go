package helpers

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"math/rand"
	"net/url"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// This will confirm to the regex in the application if 5 chars are used for each side of the -
// /^[A-Z2-7]{5}-[A-Z2-7]{5}$/
var letters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

func InputError(e echo.Context, custom *string) error {
	msg := "InvalidRequest"
	if custom != nil {
		msg = *custom
	}
	return genericError(e, 400, msg)
}

func ServerError(e echo.Context, suffix *string) error {
	msg := "Internal server error"
	if suffix != nil {
		msg += ". " + *suffix
	}
	return genericError(e, 500, msg)
}

func UnauthorizedError(e echo.Context, suffix *string) error {
	msg := "Unauthorized"
	if suffix != nil {
		msg += ". " + *suffix
	}
	return genericError(e, 401, msg)
}

func ForbiddenError(e echo.Context, suffix *string) error {
	msg := "Forbidden"
	if suffix != nil {
		msg += ". " + *suffix
	}
	return genericError(e, 403, msg)
}

func InvalidTokenError(e echo.Context) error {
	return InputError(e, to.StringPtr("InvalidToken"))
}

func ExpiredTokenError(e echo.Context) error {
	// WARN: See https://github.com/bluesky-social/atproto/discussions/3319
	return e.JSON(400, map[string]string{
		"error":   "ExpiredToken",
		"message": "*",
	})
}

func genericError(e echo.Context, code int, msg string) error {
	return e.JSON(code, map[string]string{
		"error": msg,
	})
}

// OauthError responds with a standard OAuth 2.0 error response (RFC 6749 5.2):
// a JSON body with an "error" code and an optional "error_description".
func OauthError(e echo.Context, status int, code, desc string) error {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	return e.JSON(status, body)
}

// InvalidRequestOauthError responds with a 400 "invalid_request" OAuth error.
func InvalidRequestOauthError(e echo.Context, desc string) error {
	return OauthError(e, 400, "invalid_request", desc)
}

// OauthInvalidTokenError responds with a 401 "invalid_token" error plus the
// DPoP WWW-Authenticate challenge required by RFC 6750 / RFC 9449. Used by the
// resource server when a presented access token is unknown or has been revoked.
func OauthInvalidTokenError(e echo.Context) error {
	e.Response().Header().Set("WWW-Authenticate", "DPoP error=\"invalid_token\"")
	e.Response().Header().Add("access-control-expose-headers", "WWW-Authenticate")
	return e.JSON(401, map[string]string{
		"error": "invalid_token",
	})
}

// InvalidClientOauthError responds with a 401 "invalid_client" OAuth error,
// used when client authentication fails (RFC 6749 5.2 / RFC 7009).
func InvalidClientOauthError(e echo.Context, desc string) error {
	return OauthError(e, 401, "invalid_client", desc)
}

func RandomVarchar(length int) string {
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := crand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func RandomBytes(n int) []byte {
	bs := make([]byte, n)
	crand.Read(bs)
	return bs
}

func ParseJWKFromBytes(b []byte) (jwk.Key, error) {
	return jwk.ParseKey(b)
}

func OauthParseHtu(htu string) (string, error) {
	u, err := url.Parse(htu)
	if err != nil {
		return "", errors.New("`htu` is not a valid URL")
	}

	if u.User != nil {
		_, containsPass := u.User.Password()
		if u.User.Username() != "" || containsPass {
			return "", errors.New("`htu` must not contain credentials")
		}
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("`htu` must be http or https")
	}

	return OauthNormalizeHtu(u), nil
}

func OauthNormalizeHtu(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.RawPath
}
