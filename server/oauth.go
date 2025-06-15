package server

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
)

type DpopProof struct {
	JTI string
	JKT string
	HTM string
	HTU string
}

func (s *Server) oauthCheckDpopProof(reqMethod, reqUrl string, headers http.Header, accessToken *string) (*DpopProof, error) {
	if reqMethod == "" {
		return nil, errors.New("HTTP method is required")
	}

	proof, err := oauthExtractProof(headers)
	if err != nil {
		return nil, err
	}

	if proof == "" {
		return nil, nil
	}

	token, err := new(jwt.Parser).Parse(proof, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unsupported signing method: %v", t.Header["alg"])
		}

		return s.privateKey.Public(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not parse dpop proof jwt: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("dpop proof jwt as invalid")
	}

	typ, _ := token.Header["typ"].(string)
	if typ == "" {
		return nil, errors.New("invalid dpop proof jwt: `typ` is missing in header")
	}

	if typ != "dpop+jwt" {
		return nil, errors.New("invalid dpop proof jwt: `typ` must be 'dpop+jwt'")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("no claims in dpop proof jwt")
	}

	if _, iatOk := claims["iat"].(float64); !iatOk {

		return nil, errors.New("invalid dpop proof jwt: `iat` is missing")
	}

	if !claims.VerifyIssuedAt(10, true) {
		return nil, errors.New("dpop proof too old")
	}

	// nonce does not have to be included

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("invalid dpop proof jwt: `jti` is missing")
	}

	htm, _ := claims["htm"].(string)
	if htm == "" {
		return nil, errors.New("invalid dpop proof jwt: `htm` is missing")
	}

	if htm != reqMethod {
		return nil, errors.New("invalid dpop proof jwt: `htm` mismatch")
	}

	htu := claims["htu"].(string)
	if htu == "" {
		return nil, errors.New("invalid dpop proof jwt: `htu` is missing")
	}

	parsedHtu, err := oauthParseHtu(htu)
	if err != nil {
		return nil, errors.New("invalid dpop proof jwt: `htu` could not be parsed")
	}

	u, _ := url.Parse(reqUrl)

	if parsedHtu != oauthNormalizeHtu(u) {
		return nil, errors.New("invalid dpop proof jwt: `htu` mismatch")
	}

	ath, _ := claims["ath"].(string)

	if accessToken != nil && *accessToken != "" {
		if ath == "" {
			return nil, errors.New("invalid dpop proof jwt: `ath` is required with access token")
		}

		hash := sha256.Sum256([]byte(*accessToken))
		if ath != base64.RawURLEncoding.EncodeToString(hash[:]) {
			return nil, errors.New("invalid dpop proof jwt: `ath` mismatch")
		}
	} else if ath != "" {
		return nil, errors.New("invalid dpop proof jwt: `ath` claim not allowed")
	}

	dpopJwk, jwkOk := token.Header["jwk"].(map[string]any)
	if !jwkOk {
		return nil, errors.New("invalid dpop proof jwt: `jwk` is missing")
	}

	jwkb, err := json.Marshal(dpopJwk)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jwk: %w", err)
	}

	key, err := helpers.ParseJWKFromBytes(jwkb)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwk: %w", err)
	}

	thumbb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate thumbprint: %w", err)
	}

	thumb := base64.RawURLEncoding.EncodeToString(thumbb)

	return &DpopProof{
		JTI: jti,
		JKT: thumb,
		HTM: htm,
		HTU: htu,
	}, nil
}

// gsnot quite sure if this is required. refrence impl (js) sees if the header is a string or an array (?)
// if it's an array it will return the first item, and if the length is more than one will return an error
// (header must contain one proof). im not certain what the purpose of this is right now, so might be
// able to get rid of this little helper later
func oauthExtractProof(headers http.Header) (string, error) {
	dpopHeader := headers.Get("dpop")
	return dpopHeader, nil
}

func oauthParseHtu(htu string) (string, error) {
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

	return oauthNormalizeHtu(u), nil
}

func oauthNormalizeHtu(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.RawPath
}
