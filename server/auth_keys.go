package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/client"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
)

// jwtBearerGrantType is the OAuth JWT bearer grant type (RFC 7523 §4.1):
// an account signs in by presenting a short JWT assertion signed with one
// of its sign-in keys.
const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

const (
	// assertionMaxIatSkew bounds how far an assertion's iat may lie in the
	// future: a small allowance for clock drift, nothing more.
	assertionMaxIatSkew = 60 * time.Second
	// assertionMaxLifetime bounds exp - iat, so an assertion can never be
	// replayable for long.
	assertionMaxLifetime = 300 * time.Second
)

// authKeyDevicePrefix marks an oauth_tokens row issued through the jwt-bearer
// grant, in DeviceId, with the did:key that signed the assertion: revoking a
// key finds the sessions issued through it.
const authKeyDevicePrefix = "auth-key:"

func authKeyDeviceId(didKey string) string {
	return authKeyDevicePrefix + didKey
}

// handleOauthTokenJwtBearer serves the jwt-bearer grant: it verifies the
// assertion against one of the account's active sign-in keys (structure,
// claims, timing, single-use jti, signature), checks the account is active,
// and issues an ordinary DPoP-bound OAuth session.
func (s *Server) handleOauthTokenJwtBearer(e echo.Context, client *client.Client, clientAuth *provider.ClientAuth, proof *dpop.Proof, req OauthTokenRequest) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleOauthTokenJwtBearer")

	if req.Assertion == nil || *req.Assertion == "" {
		return helpers.InvalidGrantError(e, `"assertion" is required`)
	}

	// The grant is DPoP-bound like every other: no proof, no session.
	if proof == nil {
		return helpers.InputError(e, to.StringPtr("dpop proof is required"))
	}

	assertion, err := s.verifyAuthKeyAssertion(ctx, *req.Assertion, time.Now())
	if err != nil {
		logger.Info("refusing jwt-bearer assertion", "error", err)
		return helpers.InvalidGrantError(e, "Invalid assertion")
	}

	repo, err := s.getRepoActorByDid(ctx, assertion.Token.Payload.Sub)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return helpers.InvalidGrantError(e, "Account not found")
		}
		logger.Error("error finding actor for assertion", "error", err)
		return helpers.ServerError(e, nil)
	}
	if repo.Repo.TakenDown() {
		return helpers.InvalidGrantError(e, "Account is taken down")
	}
	if !repo.Repo.Active() {
		return helpers.InvalidGrantError(e, "Account is deactivated")
	}

	scope := ""
	if req.Scope != nil {
		scope = *req.Scope
	}
	if scope == "" {
		scope = client.Metadata.Scope
	}
	if err := s.validateRequestedScopes(ctx, scope); err != nil {
		return invalidScopeError(e, err)
	}

	now := time.Now()
	eat := now.Add(constants.TokenMaxAge)
	id := oauth.GenerateTokenId()

	refreshToken := oauth.GenerateRefreshToken()

	expandedScope, err := s.issueScope(ctx, scope, repo.Repo.Did)
	if err != nil {
		s.logger.Error("refusing to issue token: space type declaration unavailable", "client_id", client.Metadata.ClientID, "scope", scope, "error", err)
		return invalidScopeError(e, err)
	}

	accessClaims := jwt.MapClaims{
		"scope":     expandedScope,
		"aud":       s.config.Did,
		"sub":       repo.Repo.Did,
		"iat":       now.Unix(),
		"exp":       eat.Unix(),
		"jti":       id,
		"client_id": client.Metadata.ClientID,
	}
	if proof.JKT != "" {
		accessClaims["cnf"] = proof.JKT
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	accessToken.Header["kid"] = s.publicKid
	accessString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		return err
	}

	params := provider.ParRequest{
		AuthenticateClientRequestBase: provider.AuthenticateClientRequestBase{ClientID: client.Metadata.ClientID},
		Scope:                         expandedScope,
	}
	params.DpopJkt = to.StringPtr(proof.JKT)

	if err := s.db.Create(ctx, &provider.OauthToken{
		ClientId:       client.Metadata.ClientID,
		ClientAuth:     *clientAuth,
		Parameters:     params,
		ExpiresAt:      eat,
		DeviceId:       authKeyDeviceId(assertion.signer.DidKey),
		Sub:            repo.Repo.Did,
		SessionVersion: repo.SessionVersion,
		Token:          accessString,
		RefreshToken:   refreshToken,
		Ip:             e.Request().Header.Get("X-Forwarded-For"),
	}, nil).Error; err != nil {
		logger.Error("error creating token in db", "error", err)
		return helpers.ServerError(e, nil)
	}

	tokenType := "Bearer"
	if params.DpopJkt != nil {
		tokenType = "DPoP"
	}

	e.Response().Header().Set("content-type", "application/json")

	return e.JSON(200, OauthTokenResponse{
		AccessToken:  accessString,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		Scope:        expandedScope,
		ExpiresIn:    int64(eat.Sub(time.Now()).Seconds()),
		Sub:          repo.Repo.Did,
	})
}

// verifiedAssertion is a fully verified assertion, plus the active key that
// signed it.
type verifiedAssertion struct {
	Token  assertionToken
	signer models.AuthKey
}

// assertionToken is the parsed assertion JWT.
type assertionToken struct {
	Header  assertionHeader
	Payload assertionPayload
}

type assertionHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type assertionPayload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

// errRecordNotFound aliases gorm's not-found sentinel for this file's checks.
var errRecordNotFound = errors.New("record not found")

// verifyAuthKeyAssertion checks a jwt-bearer assertion end to end and marks
// its jti single-use. It returns the parsed token and the signing key.
func (s *Server) verifyAuthKeyAssertion(ctx context.Context, assertion string, now time.Time) (*verifiedAssertion, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed assertion: expected 3 parts")
	}
	hb, err := decodeJSONPart(parts[0], "header")
	if err != nil {
		return nil, err
	}
	pm, err := decodeJSONPart(parts[1], "payload")
	if err != nil {
		return nil, err
	}

	alg, _ := strField(hb, "alg")
	if alg == "" {
		return nil, errors.New(`missing assertion "alg"`)
	}

	var tok assertionToken
	tok.Header.Alg = alg
	tok.Payload.Iss, _ = strField(pm, "iss")
	tok.Payload.Sub, _ = strField(pm, "sub")
	tok.Payload.Aud, _ = strField(pm, "aud")
	tok.Payload.Jti, _ = strField(pm, "jti")
	iat, hasIat := numField(pm, "iat")
	exp, hasExp := numField(pm, "exp")
	tok.Payload.Iat = int64(iat)
	tok.Payload.Exp = int64(exp)

	if tok.Payload.Iss == "" || tok.Payload.Sub == "" {
		return nil, errors.New(`assertion requires "iss" and "sub"`)
	}
	if tok.Payload.Iss != tok.Payload.Sub {
		return nil, errors.New(`assertion "iss" and "sub" must both be the account's did`)
	}
	if _, err := syntax.ParseDID(tok.Payload.Iss); err != nil {
		return nil, errors.New(`assertion "iss" is not a did`)
	}
	if tok.Payload.Aud != "https://"+s.config.Hostname {
		return nil, errors.New(`assertion "aud" does not match this server's issuer`)
	}
	if tok.Payload.Jti == "" {
		return nil, errors.New(`assertion requires a "jti"`)
	}
	if !hasIat || !hasExp {
		return nil, errors.New(`assertion requires "iat" and "exp"`)
	}
	if tok.Payload.Iat > now.Add(assertionMaxIatSkew).Unix() {
		return nil, errors.New("assertion issued too far in the future")
	}
	if now.Unix() >= tok.Payload.Exp {
		return nil, errors.New("assertion expired")
	}
	if tok.Payload.Exp > tok.Payload.Iat {
		if time.Duration(tok.Payload.Exp-tok.Payload.Iat)*time.Second > assertionMaxLifetime {
			return nil, errors.New("assertion lifetime is too long")
		}
	} else {
		return nil, errors.New("assertion exp must be after iat")
	}

	// The account and its active keys.
	repo, err := s.getRepoByDid(ctx, tok.Payload.Sub)
	if err != nil {
		return nil, err
	}
	var keys []models.AuthKey
	if err := s.db.Raw(ctx, "SELECT * FROM auth_keys WHERE did = ?", nil, repo.Did).Scan(&keys).Error; err != nil {
		return nil, err
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := decodeB64(parts[2])
	if err != nil {
		return nil, errors.New("could not parse assertion signature")
	}

	var signer *models.AuthKey
	for i := range keys {
		if !keys[i].Active() {
			continue
		}
		pub, err := atcrypto.ParsePublicDIDKey(keys[i].DidKey)
		if err != nil {
			continue
		}
		ok, err := space.VerifyJWTSignature(pub, alg, []byte(signingInput), sig)
		if err != nil || !ok {
			continue
		}
		signer = &keys[i]
		break
	}
	if signer == nil {
		return nil, errors.New("assertion is not signed by an active sign-in key of this account")
	}

	// Single-use jti: a unique row per assertion, kept until the assertion
	// could still be valid. A second insert of the same jti fails, so a
	// replay loses the race even between concurrent requests.
	expAt := time.Unix(tok.Payload.Exp, 0)
	if err := s.db.Create(ctx, &models.AuthKeyAssertion{
		Jti:       tok.Payload.Jti,
		CreatedAt: now,
		ExpiresAt: expAt,
	}, nil).Error; err != nil {
		return nil, fmt.Errorf("assertion jti was already used: %w", err)
	}

	return &verifiedAssertion{Token: tok, signer: *signer}, nil
}

// getRepoByDid finds the Repo row for did, distinguishing not-found.
func (s *Server) getRepoByDid(ctx context.Context, did string) (*models.Repo, error) {
	var repo models.Repo
	if err := s.db.Raw(ctx, "SELECT * FROM repos WHERE did = ?", nil, did).Scan(&repo).Error; err != nil {
		return nil, err
	}
	if repo.Did == "" {
		return nil, errRecordNotFound
	}
	return &repo, nil
}

// ListAuthKeys returns the account's sign-in keys, newest first.
func (s *Server) ListAuthKeys(ctx context.Context, did string) ([]models.AuthKey, error) {
	var keys []models.AuthKey
	if err := s.db.Raw(ctx, "SELECT * FROM auth_keys WHERE did = ? ORDER BY created_at DESC", nil, did).Scan(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

// RevokeAuthKey revokes the account's sign-in key matching didKey. An empty
// didKey revokes all of the account's keys. Revocation stops future grants
// and revokes the OAuth sessions issued through the key. It reports whether
// any key was revoked.
func (s *Server) RevokeAuthKey(ctx context.Context, did, didKey string) (bool, error) {
	logger := s.logger.With("name", "RevokeAuthKey")

	q := "UPDATE auth_keys SET revoked_at = ? WHERE did = ?"
	args := []any{time.Now(), did}
	if didKey != "" {
		q += " AND did_key = ?"
		args = append(args, didKey)
	}
	res := s.db.Exec(ctx, q, nil, args...)
	if res.Error != nil {
		logger.Error("error revoking sign-in key", "did", did, "error", res.Error)
		return false, res.Error
	}

	// Revoke the OAuth sessions issued through the revoked keys, like a
	// password reset does: bump the session version so every token row and
	// access token from before stops validating, and delete the token rows.
	var revoked []models.AuthKey
	if err := s.db.Raw(ctx, "SELECT * FROM auth_keys WHERE did = ?"+func() string {
		if didKey != "" {
			return " AND did_key = ?"
		}
		return ""
	}(), nil, argsFrom(did, didKey)...).Scan(&revoked).Error; err != nil {
		logger.Error("error finding revoked keys", "did", did, "error", err)
		return res.RowsAffected > 0, nil
	}

	sessionBump := s.db.Exec(ctx, "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, did)
	if sessionBump.Error != nil {
		logger.Error("error bumping session version", "did", did, "error", sessionBump.Error)
		return res.RowsAffected > 0, sessionBump.Error
	}

	for _, k := range revoked {
		if del := s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE sub = ? AND device_id = ?", nil, did, authKeyDeviceId(k.DidKey)); del.Error != nil {
			logger.Error("error deleting sessions for revoked key", "did", did, "key", k.DidKey, "error", del.Error)
		}
	}

	return res.RowsAffected > 0, nil
}

func argsFrom(did, didKey string) []any {
	if didKey != "" {
		return []any{did, didKey}
	}
	return []any{did}
}

// decodeB64 accepts base64url with or without padding.
func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// decodeJSONPart decodes a base64url JWT part as a JSON object.
func decodeJSONPart(s, part string) (map[string]json.RawMessage, error) {
	b, err := decodeB64(s)
	if err != nil {
		return nil, fmt.Errorf("could not parse assertion %s: %v", part, err)
	}
	var m map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&m); err != nil || m == nil {
		return nil, fmt.Errorf("could not parse assertion %s: not a JSON object", part)
	}
	return m, nil
}

func strField(m map[string]json.RawMessage, k string) (string, bool) {
	raw, ok := m[k]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func numField(m map[string]json.RawMessage, k string) (float64, bool) {
	raw, ok := m[k]
	if !ok {
		return 0, false
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
