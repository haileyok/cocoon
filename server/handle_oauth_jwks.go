package server

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type OauthJwksResponse struct {
	Keys []any `json:"keys"`
}

func (s *Server) handleOauthJwks(e echo.Context) error {
	keys := []any{}
	if s.publicJwk != nil {
		keys = append(keys, s.publicJwk)
	}
	return e.JSON(200, OauthJwksResponse{Keys: keys})
}

// derivePublicJWK builds the public JWK for the server's signing key. If kid is
// empty, the key's RFC 7638 thumbprint is used so external resource servers can
// select the key. It returns the public JWK and the resolved kid.
func derivePublicJWK(priv *ecdsa.PrivateKey, kid string) (jwk.Key, string, error) {
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		return nil, "", err
	}

	if kid == "" {
		thumb, err := pub.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, "", err
		}
		kid = base64.RawURLEncoding.EncodeToString(thumb)
	}

	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, "", err
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, "", err
	}
	if err := pub.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, "", err
	}

	return pub, kid, nil
}
