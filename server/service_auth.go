package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/space"
)

type ES256KSigningMethod struct {
	alg string
}

func (m *ES256KSigningMethod) Alg() string {
	return m.alg
}

func (m *ES256KSigningMethod) Verify(signingString string, signature string, key interface{}) error {
	signatureBytes, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}
	switch verifier := key.(type) {
	case atcrypto.PublicKey:
		return verifier.HashAndVerifyLenient([]byte(signingString), signatureBytes)
	case space.Verifier:
		return verifier.Verify([]byte(signingString), signatureBytes)
	default:
		return errors.New("invalid ES256K verification key")
	}
}

func (m *ES256KSigningMethod) Sign(signingString string, key interface{}) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

func init() {
	ES256K := ES256KSigningMethod{alg: "ES256K"}
	jwt.RegisterSigningMethod(ES256K.Alg(), func() jwt.SigningMethod {
		return &ES256K
	})
}

func (s *Server) validateServiceAuth(ctx context.Context, rawToken string, nsid string) (string, error) {
	token := strings.TrimSpace(rawToken)
	if token == "" || s == nil || s.passport == nil {
		return "", errors.New("service-auth verifier is unavailable")
	}
	parsedToken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("service-auth claims are invalid")
		}
		issuer, ok := claims["iss"].(string)
		if !ok || issuer == "" {
			return nil, errors.New("service-auth issuer is required")
		}
		if token.Method != jwt.GetSigningMethod("ES256K") || token.Header["typ"] != "JWT" {
			return nil, errors.New("service-auth token must use ES256K/JWT")
		}
		kid, _ := token.Header["kid"].(string)
		return didDocumentVerifier(ctx, s.passport, space.KeyResolutionRequest{
			Issuer: issuer, Kid: kid, Algorithm: token.Method.Alg(),
		})
	})
	if err != nil || parsedToken == nil || !parsedToken.Valid {
		if err == nil {
			err = errors.New("token signature is invalid")
		}
		return "", fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid service-auth claims")
	}
	if err := validateServiceAuthClaims(claims, s.config.Did, nsid); err != nil {
		return "", err
	}
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return "", errors.New("service-auth issuer is required")
	}
	return issuer, nil
}

const (
	serviceAuthClockSkew   = 5 * time.Second
	serviceAuthMaxLifetime = time.Hour
)

// validateServiceAuthClaims enforces that a service-auth JWT is addressed to
// this PDS (aud), scoped to the expected lexicon method (lxm), and has the
// claims required by the pinned ATProto service-auth producer. Without the aud
// check a token a user minted for another service could be replayed here.
func validateServiceAuthClaims(claims jwt.MapClaims, expectedAud, expectedLxm string) error {
	if lxm, _ := claims["lxm"].(string); lxm != expectedLxm {
		return fmt.Errorf("bad jwt lexicon method (\"lxm\"). must match: %s", expectedLxm)
	}
	if aud, _ := claims["aud"].(string); aud != expectedAud {
		return fmt.Errorf("bad jwt audience (\"aud\"). must match: %s", expectedAud)
	}
	jti, ok := claims["jti"].(string)
	if !ok || strings.TrimSpace(jti) == "" {
		return errors.New("service-auth jti is required")
	}
	iat, err := serviceAuthNumericClaim(claims, "iat")
	if err != nil {
		return err
	}
	exp, err := serviceAuthNumericClaim(claims, "exp")
	if err != nil {
		return err
	}
	if exp <= iat {
		return errors.New("service-auth expiration must be after issuance")
	}
	now := time.Now()
	if time.Unix(iat, 0).After(now.Add(serviceAuthClockSkew)) {
		return errors.New("service-auth iat is in the future")
	}
	if !time.Unix(exp, 0).After(now) {
		return errors.New("service-auth token is expired")
	}
	if exp-iat > int64(serviceAuthMaxLifetime/time.Second) {
		return errors.New("service-auth token lifetime is too long")
	}
	return nil
}

func serviceAuthNumericClaim(claims jwt.MapClaims, name string) (int64, error) {
	value, ok := claims[name]
	if !ok {
		return 0, fmt.Errorf("service-auth %s is required", name)
	}
	var number float64
	switch typed := value.(type) {
	case float64:
		number = typed
	case float32:
		number = float64(typed)
	case int64:
		number = float64(typed)
	case int:
		number = float64(typed)
	default:
		return 0, fmt.Errorf("service-auth %s must be numeric", name)
	}
	if number <= 0 || number != float64(int64(number)) {
		return 0, fmt.Errorf("service-auth %s must be a positive integer", name)
	}
	return int64(number), nil
}
