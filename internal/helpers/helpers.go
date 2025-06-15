package helpers

import (
	"math/rand"

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

func ParseJWKFromBytes(b []byte) (jwk.Key, error) {
	return jwk.ParseKey(b)
}
