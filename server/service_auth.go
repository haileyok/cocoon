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

const serviceAuthReplayTokenType = "service-auth"

type validatedServiceAuth struct {
	Issuer   string
	Audience string
	LXM      string
	JTI      string
	Exp      int64
}

func (s *Server) validateServiceAuthToken(ctx context.Context, rawToken string, nsid string) (validatedServiceAuth, error) {
	token := strings.TrimSpace(rawToken)
	if token == "" || s == nil || s.passport == nil || s.config == nil {
		return validatedServiceAuth{}, errors.New("service-auth verifier is unavailable")
	}

	// ParseUnverified is used only to select the issuer/key. The signature is
	// checked below using the DID-resolved verifier before any claims are
	// trusted or replay state is consumed.
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil || parsedToken == nil {
		if err == nil {
			err = errors.New("invalid token")
		}
		return validatedServiceAuth{}, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return validatedServiceAuth{}, errors.New("invalid service-auth claims")
	}
	alg, ok := parsedToken.Header["alg"].(string)
	if !ok || (alg != "ES256K" && alg != "ES256") || parsedToken.Method == nil || parsedToken.Method.Alg() != alg {
		return validatedServiceAuth{}, errors.New("service-auth token must use ES256K or ES256")
	}
	if typ, ok := parsedToken.Header["typ"].(string); !ok || typ != "JWT" {
		return validatedServiceAuth{}, errors.New("service-auth token must use JWT typ")
	}
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return validatedServiceAuth{}, errors.New("service-auth issuer is required")
	}
	kid := ""
	if rawKid, present := parsedToken.Header["kid"]; present {
		var ok bool
		kid, ok = rawKid.(string)
		if !ok || kid == "" {
			return validatedServiceAuth{}, errors.New("service-auth kid must be a non-empty string")
		}
	}
	keyRequest := space.KeyResolutionRequest{Issuer: issuer, Kid: kid, Algorithm: alg}
	verifier, err := didDocumentVerifier(ctx, s.passport, keyRequest)
	if err != nil {
		return validatedServiceAuth{}, fmt.Errorf("resolve service-auth DID key: %w", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return validatedServiceAuth{}, errors.New("invalid service-auth token structure")
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := jwt.DecodeSegment(parts[2])
	if err != nil {
		return validatedServiceAuth{}, fmt.Errorf("invalid service-auth signature encoding: %w", err)
	}
	if verifyErr := verifier.Verify(signingInput, signature); verifyErr != nil {
		// Passport-backed DID documents may be cached. Match Space token
		// verification by refreshing exactly once after a signature failure;
		// replay state is still untouched until this retry succeeds.
		keyRequest.ForceRefresh = true
		freshVerifier, refreshErr := didDocumentVerifier(ctx, s.passport, keyRequest)
		if refreshErr != nil {
			return validatedServiceAuth{}, fmt.Errorf("invalid service-auth signature: %w", verifyErr)
		}
		if freshErr := freshVerifier.Verify(signingInput, signature); freshErr != nil {
			return validatedServiceAuth{}, fmt.Errorf("invalid service-auth signature: %w", freshErr)
		}
	}
	if err := validateServiceAuthClaims(claims, s.config.Did, nsid); err != nil {
		return validatedServiceAuth{}, err
	}
	audience, _ := claims["aud"].(string)
	lxm, _ := claims["lxm"].(string)
	jti, _ := claims["jti"].(string)
	exp, err := serviceAuthNumericClaim(claims, "exp")
	if err != nil {
		return validatedServiceAuth{}, err
	}

	// A token is single-use only after signature and every semantic claim has
	// passed. This ordering ensures malformed, misaddressed, or bad-signature
	// retries do not burn a valid JTI.
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.spaceReplayStore().Consume(ctx, jti, serviceAuthReplayTokenType, time.Unix(exp, 0).Add(serviceAuthClockSkew)); err != nil {
		return validatedServiceAuth{}, fmt.Errorf("service-auth replay: %w", err)
	}
	return validatedServiceAuth{Issuer: issuer, Audience: audience, LXM: lxm, JTI: jti, Exp: exp}, nil
}

// validateServiceAuth retains the historical issuer-only helper contract for
// handlers that only need the authenticated DID. The native auth dispatcher
// uses validateServiceAuthToken so it can install the complete validated result.
func (s *Server) validateServiceAuth(ctx context.Context, rawToken string, nsid string) (string, error) {
	validated, err := s.validateServiceAuthToken(ctx, rawToken, nsid)
	if err != nil {
		return "", err
	}
	return validated.Issuer, nil
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
