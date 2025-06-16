package server

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	MaxRotationInterval = OauthDpopNonceMaxAge / 3
	MinRotationInterval = 1 * time.Second
	SecretByteLength    = 32
)

type OauthNonce struct {
	rotationInterval time.Duration
	secret           []byte

	mu sync.RWMutex

	counter int64
	prev    string
	curr    string
	next    string
}

func NewOauthNonce(secret []byte, rotationInterval time.Duration) *OauthNonce {
	if secret == nil {
		secret = helpers.RandomBytes(SecretByteLength)
	}

	if rotationInterval <= 0 || rotationInterval > MaxRotationInterval {
		rotationInterval = MaxRotationInterval
	}

	on := &OauthNonce{
		rotationInterval: MaxRotationInterval,
		secret:           secret,
	}

	on.counter = on.currentCounter()
	on.prev = on.compute(on.counter - 1)
	on.curr = on.compute(on.counter)
	on.next = on.compute(on.counter + 1)

	return on
}

func (on *OauthNonce) currentCounter() int64 {
	return time.Now().UnixNano() / int64(on.rotationInterval)
}

func (on *OauthNonce) rotate() {
	counter := on.currentCounter()
	diff := counter - on.counter

	switch diff {
	case 0:
	// counter == on.counter, do nothing
	case 1:
		on.prev = on.curr
		on.curr = on.next
		on.next = on.compute(counter + 1)
	case 2:
		on.prev = on.next
		on.curr = on.compute(counter)
		on.next = on.compute(counter + 1)
	default:
		on.prev = on.compute(counter - 1)
		on.curr = on.compute(counter)
		on.next = on.compute(counter + 1)
	}
}

func (on *OauthNonce) compute(counter int64) string {
	h := hmac.New(sha256.New, on.secret)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))
	h.Write(counterBytes)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (on *OauthNonce) Next() string {
	on.mu.Lock()
	defer on.mu.Unlock()
	on.rotate()
	return on.next
}

func (on *OauthNonce) Check(nonce string) bool {
	on.mu.RLock()
	defer on.mu.RUnlock()
	on.rotate()
	return nonce == on.prev || nonce == on.curr || nonce == on.next
}

type OauthDpopManager struct {
	nonce OauthNonce
}

func NewOauthDpopManager() *OauthDpopManager {
	return &OauthDpopManager{
		nonce: *NewOauthNonce(nil, 0), // use the default values in that guy for now
	}
}

func (odm *OauthDpopManager) CheckProof(reqMethod, reqUrl string, headers http.Header, accessToken *string) (*DpopProof, error) {
	if reqMethod == "" {
		return nil, errors.New("HTTP method is required")
	}

	proof, err := helpers.OauthExtractProof(headers)
	if err != nil {
		return nil, err
	}

	if proof == "" {
		return nil, nil
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	var token *jwt.Token

	token, _, err = parser.ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("could not parse dpop proof jwt: %w", err)
	}

	typ, _ := token.Header["typ"].(string)
	if typ == "" {
		return nil, errors.New(`invalid dpop proof jwt: "typ" is missing in header`)
	}

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

	// Now verify the JWT with the embedded public key
	token, err = jwt.Parse(proof, func(t *jwt.Token) (any, error) {
		// Verify the signing method matches what's in the JWK
		alg := t.Header["alg"].(string)

		// Check that the algorithm matches the key type
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

	// Validate iat with max age of 10 seconds
	iat, iatOk := claims["iat"].(float64)
	if !iatOk {
		return nil, errors.New(`invalid dpop proof jwt: "iat" is missing`)
	}

	iatTime := time.Unix(int64(iat), 0)
	if time.Since(iatTime) > 10*time.Second {
		return nil, errors.New("dpop proof too old")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New(`invalid dpop proof jwt: "jti" is missing`)
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
		return nil, errors.New("use_dpop_nonce")
	}

	if nonce != "" && !odm.nonce.Check(nonce) {
		return nil, errors.New(`dpop "nonce" mismatch`)
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

	return &DpopProof{
		JTI: jti,
		JKT: thumb,
		HTM: htm,
		HTU: htu,
	}, nil
}
