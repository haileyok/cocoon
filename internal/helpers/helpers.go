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
	return genericError(e, 400, msg)
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
