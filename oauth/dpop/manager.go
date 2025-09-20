package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Manager struct {
	nonce    *Nonce
	jtiCache *jtiCache
	logger   *slog.Logger
	hostname string
}

type ManagerArgs struct {
	NonceSecret           []byte
	NonceRotationInterval time.Duration
	OnNonceSecretCreated  func([]byte)
	JTICacheSize          int
	Logger                *slog.Logger
	Hostname              string
}

var (
	ErrUseDpopNonce = errors.New("use_dpop_nonce")
)

func NewManager(args ManagerArgs) *Manager {
	if args.Logger == nil {
		args.Logger = slog.Default()
	}

	if args.JTICacheSize == 0 {
		args.JTICacheSize = 100_000
	}

	if args.NonceSecret == nil {
		args.Logger.Warn("nonce secret passed to dpop manager was nil. existing sessions may break. consider saving and restoring your nonce.")
	}

	return &Manager{
		nonce: NewNonce(NonceArgs{
			RotationInterval: args.NonceRotationInterval,
			Secret:           args.NonceSecret,
			OnSecretCreated:  args.OnNonceSecretCreated,
		}),
		jtiCache: newJTICache(args.JTICacheSize),
		logger:   args.Logger,
		hostname: args.Hostname,
	}
}

func (dm *Manager) CheckProof(reqMethod, reqUrl string, headers http.Header, accessToken *string) (*Proof, error) {
	if reqMethod == "" {
		return nil, errors.New("HTTP method is required")
	}

	if !strings.HasPrefix(reqUrl, "https://") {
		reqUrl = "https://" + dm.hostname + reqUrl
	}

	proof := extractProof(headers)

	if proof == "" {
		return nil, nil
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	var token *jwt.Token

	token, _, err := parser.ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("could not parse dpop proof jwt: %w", err)
	}

	typ, _ := token.Header["typ"].(string)
	if typ != "dpop+jwt" {
		return nil, errors.New(`invalid dpop proof jwt: "typ" must be 'dpop+jwt'`)
	}

	dpopJwk, jwkOk := token.Header["jwk"].(map[string]any)
	if !jwkOk {
		return nil, errors.New(`invalid dpop proof jwt: "jwk" is missing in header`)
	}

	jwkb, err := json.Marshal(dpopJwk)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jwk: %w", err)
	}

	key, err := jwk.ParseKey(jwkb)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwk: %w", err)
	}

	var pubKey any
	if err := key.Raw(&pubKey); err != nil {
		return nil, fmt.Errorf("failed to get raw public key: %w", err)
	}

	token, err = jwt.Parse(proof, func(t *jwt.Token) (any, error) {
		alg := t.Header["alg"].(string)

		switch key.KeyType() {
		case jwa.EC:
			if !strings.HasPrefix(alg, "ES") {
				return nil, fmt.Errorf("algorithm %s doesn't match EC key type", alg)
			}
		case jwa.RSA:
			if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
				return nil, fmt.Errorf("algorithm %s doesn't match RSA key type", alg)
			}
		case jwa.OKP:
			if alg != "EdDSA" {
				return nil, fmt.Errorf("algorithm %s doesn't match OKP key type", alg)
			}
		}

		return pubKey, nil
	}, jwt.WithValidMethods([]string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}))
	if err != nil {
		return nil, fmt.Errorf("could not verify dpop proof jwt: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("dpop proof jwt is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("no claims in dpop proof jwt")
	}

	iat, iatOk := claims["iat"].(float64)
	if !iatOk {
		return nil, errors.New(`invalid dpop proof jwt: "iat" is missing`)
	}

	iatTime := time.Unix(int64(iat), 0)
	now := time.Now()

	if now.Sub(iatTime) > constants.DpopNonceMaxAge+constants.DpopCheckTolerance {
		return nil, errors.New("dpop proof too old")
	}

	if iatTime.Sub(now) > constants.DpopCheckTolerance {
		return nil, errors.New("dpop proof iat is in the future")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New(`invalid dpop proof jwt: "jti" is missing`)
	}

	if dm.jtiCache.add(jti) {
		return nil, errors.New("dpop proof replay detected")
	}

	htm, _ := claims["htm"].(string)
	if htm == "" {
		return nil, errors.New(`invalid dpop proof jwt: "htm" is missing`)
	}

	if htm != reqMethod {
		return nil, errors.New(`invalid dpop proof jwt: "htm" mismatch`)
	}

	htu, _ := claims["htu"].(string)
	if htu == "" {
		return nil, errors.New(`invalid dpop proof jwt: "htu" is missing`)
	}

	parsedHtu, err := helpers.OauthParseHtu(htu)
	if err != nil {
		return nil, errors.New(`invalid dpop proof jwt: "htu" could not be parsed`)
	}

	u, _ := url.Parse(reqUrl)
	if parsedHtu != helpers.OauthNormalizeHtu(u) {
		return nil, fmt.Errorf(`invalid dpop proof jwt: "htu" mismatch. reqUrl: %s, parsed: %s, normalized: %s`, reqUrl, parsedHtu, helpers.OauthNormalizeHtu(u))
	}

	nonce, _ := claims["nonce"].(string)
	if nonce == "" {
		// WARN: this _must_ be `use_dpop_nonce` for clients know they should make another request
		return nil, ErrUseDpopNonce
	}

	if nonce != "" && !dm.nonce.Check(nonce) {
		// WARN: this _must_ be `use_dpop_nonce` so that clients will fetch a new nonce
		return nil, ErrUseDpopNonce
	}

	ath, _ := claims["ath"].(string)

	if accessToken != nil && *accessToken != "" {
		if ath == "" {
			return nil, errors.New(`invalid dpop proof jwt: "ath" is required with access token`)
		}

		hash := sha256.Sum256([]byte(*accessToken))
		if ath != base64.RawURLEncoding.EncodeToString(hash[:]) {
			return nil, errors.New(`invalid dpop proof jwt: "ath" mismatch`)
		}
	} else if ath != "" {
		return nil, errors.New(`invalid dpop proof jwt: "ath" claim not allowed`)
	}

	thumbBytes, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate thumbprint: %w", err)
	}

	thumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

	return &Proof{
		JTI: jti,
		JKT: thumb,
		HTM: htm,
		HTU: htu,
	}, nil
}

func extractProof(headers http.Header) string {
	dpopHeaders := headers["Dpop"]
	switch len(dpopHeaders) {
	case 0:
		return ""
	case 1:
		return dpopHeaders[0]
	default:
		return ""
	}
}

func (dm *Manager) NextNonce() string {
	return dm.nonce.NextNonce()
}
