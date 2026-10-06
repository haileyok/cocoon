package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/space"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm/clause"
)

// Space token, request signature and service auth verification, following
// the reference PDS's auth-verifier.ts at bluesky-social/atproto 5b95b2f2.

// fetchDidDoc resolves a DID document, bypassing any cache when fresh is set.
func (s *Server) fetchDidDoc(ctx context.Context, did string, fresh bool) (*identity.DidDoc, error) {
	if fresh {
		ctx = context.WithValue(ctx, "skip-cache", true)
	}
	return s.passport.FetchDoc(ctx, did)
}

// didDocKey returns the did:key of a DID document's verification method
// (keyID without '#', e.g. "atproto").
func didDocKey(doc *identity.DidDoc, keyID string) (string, bool) {
	for _, vm := range doc.VerificationMethods {
		if vm.Id == "#"+keyID || vm.Id == doc.Id+"#"+keyID {
			pub, err := atcrypto.ParsePublicMultibase(vm.PublicKeyMultibase)
			if err != nil {
				return "", false
			}
			return pub.DIDKey(), true
		}
	}
	return "", false
}

// didDocService returns a DID document's service endpoint by id (without '#').
func didDocService(doc *identity.DidDoc, id string) (string, bool) {
	for _, svc := range doc.Service {
		if svc.Id == "#"+id || svc.Id == doc.Id+"#"+id {
			return svc.ServiceEndpoint, true
		}
	}
	return "", false
}

// resolveSpaceKey resolves the key a space token's issuer signs with. A token
// names the account key (#atproto) or a dedicated space key (#atproto_space).
func (s *Server) resolveSpaceKey(ctx context.Context) space.SigningKeyFunc {
	return func(iss, kid string, fresh bool) (string, error) {
		if kid == "" {
			return "", errAuthRequired("BadJwt", `missing token "kid"`)
		}
		keyID := strings.TrimPrefix(kid, "#")
		if keyID != "atproto" && keyID != "atproto_space" {
			return "", errAuthRequired("BadJwt", "unsupported space token \"kid\": %s", kid)
		}
		doc, err := s.fetchDidDoc(ctx, iss, fresh)
		if err != nil {
			return "", errAuthRequired("BadJwtIss", "could not resolve DID: %s", iss)
		}
		didKey, ok := didDocKey(doc, keyID)
		if !ok {
			return "", errAuthRequired("BadJwtIss", "missing or bad key (#%s) in did doc: %s", keyID, iss)
		}
		return didKey, nil
	}
}

// verifySpaceToken verifies a space token, mapping every failure to a 401.
func (s *Server) verifySpaceToken(ctx context.Context, typ space.TokenType, jwt string) (*space.Token, error) {
	tok, err := space.VerifySpaceToken(typ, jwt, space.VerifyTokenOpts{GetSigningKey: s.resolveSpaceKey(ctx)})
	if err != nil {
		var xe *xrpcError
		if errors.As(err, &xe) {
			return nil, xe
		}
		var te *space.TokenError
		if errors.As(err, &te) {
			return nil, errAuthRequired(te.Code, "%s", te.Message)
		}
		return nil, errAuthRequired("BadJwt", "Invalid %s token: %v", typ, err)
	}
	return tok, nil
}

// verifyRequestSignature checks a space request signature. keyID is a
// credential's bound key; empty for a delegation exchange. It returns the
// did:key that signed.
func verifyRequestSignature(e echo.Context, keyID string) (string, error) {
	h := e.Request().Header
	names := []string{"Authorization"}
	if keyID != "" {
		names = append(names, space.HeaderSpaceAudience)
	}
	for _, n := range names {
		if len(h.Values(n)) != 1 {
			return "", errAuthRequired("BadSpaceSignature", "request requires exactly one %q field", strings.ToLower(n))
		}
	}
	did, err := space.VerifySpaceSignature(h, keyID)
	if err != nil {
		return "", errAuthRequired("BadSpaceSignature", "%s", err.Error())
	}
	return did, nil
}

// authorizationToken splits an Authorization header into scheme and token.
func authorizationToken(e echo.Context) (string, string, error) {
	v := e.Request().Header.Get("Authorization")
	if v == "" {
		return "", "", nil
	}
	parts := strings.Split(v, " ")
	if len(parts) != 2 {
		return "", "", errInvalid("InvalidToken", "Malformed authorization header")
	}
	return parts[0], parts[1], nil
}

// verifySpaceCredentialRequest verifies a request presenting a space
// credential: the credential, the request signature by its bound key, and
// that it has not been revoked. Handlers check the space and audience.
func (s *Server) verifySpaceCredentialRequest(e echo.Context) (*spaceCredentialAuth, error) {
	ctx := e.Request().Context()
	scheme, jwt, err := authorizationToken(e)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(scheme, spaceCredentialScheme) || jwt == "" {
		return nil, errAuthRequired("MissingJwt", "missing space credential")
	}
	tok, err := s.verifySpaceToken(ctx, space.TokenCredential, jwt)
	if err != nil {
		return nil, err
	}
	ref, err := space.ParseRef(tok.Payload.Sub)
	if err != nil {
		return nil, errAuthRequired("BadJwtSub", "space token subject is not a space URI: %s", tok.Payload.Sub)
	}
	if tok.Payload.Iss != ref.Authority {
		return nil, errAuthRequired("BadJwtIss", "space credential issuer is not the space authority")
	}
	audience := e.Request().Header.Get(space.HeaderSpaceAudience)
	if _, err := syntax.ParseDID(audience); err != nil {
		return nil, errAuthRequired("BadSpaceSignature", "missing or invalid space audience DID")
	}
	if _, err := verifyRequestSignature(e, tok.Payload.Cnf.Kid); err != nil {
		return nil, err
	}
	revoked, err := s.isSpaceCredentialRevoked(ctx, ref.String(), tok.Payload.Jti)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, errAuthRequired("CredentialRevoked", "space credential has been revoked")
	}
	return &spaceCredentialAuth{Space: ref.String(), Audience: audience, Issuer: ref.Authority, Jti: tok.Payload.Jti, Exp: tok.Payload.Exp, KeyID: tok.Payload.Cnf.Kid}, nil
}

type delegationAuth struct {
	userDid string
	space   string
	keyID   string
}

// verifyDelegationRequest verifies a delegation token exchange: the token,
// the signature supplying the credential's key binding, and single use.
func (s *Server) verifyDelegationRequest(e echo.Context) (*delegationAuth, error) {
	ctx := e.Request().Context()
	scheme, jwt, err := authorizationToken(e)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(scheme, "Bearer") || jwt == "" {
		return nil, errAuthRequired("MissingJwt", "missing delegation token")
	}
	tok, err := s.verifySpaceToken(ctx, space.TokenDelegation, jwt)
	if err != nil {
		return nil, err
	}
	ref, err := space.ParseRef(tok.Payload.Sub)
	if err != nil {
		return nil, errAuthRequired("BadJwtSub", "space token subject is not a space URI: %s", tok.Payload.Sub)
	}
	// This host answers for many authorities, so the audience is derived from
	// the subject: a token minted for one authority can't be used at another.
	if tok.Payload.Aud != ref.HostAud() {
		return nil, errAuthRequired("BadJwtAudience", "delegation token audience does not match the space authority")
	}
	if _, err := syntax.ParseDID(tok.Payload.Iss); err != nil {
		return nil, errAuthRequired("BadJwtIss", "delegation token issuer is not a DID")
	}
	keyID, err := verifyRequestSignature(e, "")
	if err != nil {
		return nil, err
	}
	unique, err := s.useSpaceTokenOnce(ctx, "delegation", tok.Payload.Iss, tok.Payload.Jti, tok.Payload.Exp)
	if err != nil {
		return nil, err
	}
	if !unique {
		return nil, errAuthRequired("JwtReplayed", "delegation token has already been used")
	}
	return &delegationAuth{userDid: tok.Payload.Iss, space: ref.String(), keyID: keyID}, nil
}

// useSpaceTokenOnce records a single-use token's jti until it expires,
// reporting false if it was already used.
func (s *Server) useSpaceTokenOnce(ctx context.Context, kind, iss, jti string, exp int64) (bool, error) {
	db := s.db.Client().WithContext(ctx)
	now := time.Now().Unix()
	if err := db.Where("expires_at < ?", now-space.ClockSkewSec).Delete(&models.SpaceUsedJti{}).Error; err != nil {
		return false, err
	}
	res := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SpaceUsedJti{Namespace: kind + ":" + iss, Jti: jti, ExpiresAt: exp})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// Revocations, kept for a credential's maximum lifetime plus clock skew at
// both ends.
func (s *Server) addRevokedSpaceCredentials(ctx context.Context, spaceURI string, jtis []string) error {
	exp := time.Now().Add(time.Duration(space.CredentialMaxAgeSec+2*space.ClockSkewSec) * time.Second).UTC().Format(time.RFC3339Nano)
	db := s.db.Client().WithContext(ctx)
	for _, jti := range jtis {
		if err := db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&models.RevokedSpaceCredential{Space: spaceURI, Jti: jti, ExpiresAt: exp}).Error; err != nil {
			return err
		}
	}
	return db.Where("expires_at <= ?", time.Now().UTC().Format(time.RFC3339Nano)).Delete(&models.RevokedSpaceCredential{}).Error
}

func (s *Server) isSpaceCredentialRevoked(ctx context.Context, spaceURI, jti string) (bool, error) {
	var n int64
	err := s.db.Client().WithContext(ctx).Model(&models.RevokedSpaceCredential{}).
		Where("space = ? AND jti = ? AND expires_at > ?", spaceURI, jti, time.Now().UTC().Format(time.RFC3339Nano)).Count(&n).Error
	return n > 0, err
}

// mintServiceAuth signs a service auth JWT as iss.
func mintServiceAuth(key atcrypto.PrivateKey, iss, aud, lxm string, ttl time.Duration) (string, error) {
	alg, err := space.JWTAlg(key)
	if err != nil {
		return "", err
	}
	now := time.Now()
	hb, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": alg})
	pb, _ := json.Marshal(map[string]any{"iat": now.Unix(), "iss": iss, "aud": aud, "exp": now.Add(ttl).Unix(), "lxm": lxm, "jti": nextTID("")})
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := key.HashAndSign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

type serviceAuthClaims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Lxm string `json:"lxm"`
}

// verifyServiceAuth verifies a service auth JWT for a method, leaving the
// audience to the caller. The issuer may carry a service fragment.
func (s *Server) verifyServiceAuth(e echo.Context, lxm string) (*serviceAuthClaims, error) {
	ctx := e.Request().Context()
	scheme, jwt, err := authorizationToken(e)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(scheme, "Bearer") || jwt == "" {
		return nil, errAuthRequired("MissingJwt", "missing jwt")
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errAuthRequired("BadJwt", "poorly formatted jwt")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errAuthRequired("BadJwt", "poorly formatted jwt")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	var claims serviceAuthClaims
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(pb, &claims) != nil {
		return nil, errAuthRequired("BadJwt", "poorly formatted jwt")
	}
	switch header.Typ {
	case "at+jwt", "refresh+jwt", "dpop+jwt":
		return nil, errAuthRequired("BadJwtType", "Invalid jwt type %q", header.Typ)
	}
	if time.Now().Unix() > claims.Exp {
		return nil, errAuthRequired("JwtExpired", "jwt expired")
	}
	if claims.Lxm != lxm {
		return nil, errAuthRequired("BadJwtLexiconMethod", "bad jwt lexicon method (\"lxm\"). must match: %s", lxm)
	}
	did, frag, _ := strings.Cut(claims.Iss, "#")
	keyID := "atproto"
	if frag == "atproto_labeler" {
		keyID = "atproto_label"
	}
	input := []byte(parts[0] + "." + parts[1])
	for _, fresh := range []bool{false, true} {
		doc, err := s.fetchDidDoc(ctx, did, fresh)
		if err != nil {
			return nil, errAuthRequired("", "could not resolve iss did")
		}
		didKey, ok := didDocKey(doc, keyID)
		if !ok {
			return nil, errAuthRequired("", "missing or bad key in did doc")
		}
		pub, err := atcrypto.ParsePublicDIDKey(didKey)
		if err != nil {
			return nil, errAuthRequired("", "missing or bad key in did doc")
		}
		if alg, _ := space.JWTAlg(pub); alg != header.Alg {
			return nil, errAuthRequired("BadJwtSignature", "jwt signature does not match jwt issuer")
		}
		if pub.HashAndVerifyLenient(input, sig) == nil {
			return &claims, nil
		}
	}
	return nil, errAuthRequired("BadJwtSignature", "jwt signature does not match jwt issuer")
}

// resolveServiceEndpoint resolves a service identifier (a DID with an
// optional fragment) to its endpoint. A bare DID names an account, served by
// its PDS. A #atproto_space_host target falls back to the PDS when the DID
// publishes no dedicated space host.
func (s *Server) resolveServiceEndpoint(ctx context.Context, service string) (string, bool) {
	did, frag, _ := strings.Cut(service, "#")
	doc, err := s.fetchDidDoc(ctx, did, false)
	if err != nil {
		s.logger.Warn("could not resolve service did", "service", service, "err", err)
		return "", false
	}
	if frag == "atproto_space_host" {
		if ep, ok := didDocService(doc, "atproto_space_host"); ok {
			return ep, true
		}
		return didDocService(doc, "atproto_pds")
	}
	if frag != "" {
		return didDocService(doc, frag)
	}
	return didDocService(doc, "atproto_pds")
}

// notifyTarget is a resolved endpoint with service auth headers to reach it.
type notifyTarget struct {
	endpoint string
	headers  map[string]string
}

// resolveNotifyTarget resolves a target and mints service auth from iss (a
// local account) to it, addressed to the service identifier as published.
func (s *Server) resolveNotifyTarget(ctx context.Context, iss, service, lxm string) (*notifyTarget, error) {
	ep, ok := s.resolveServiceEndpoint(ctx, service)
	if !ok {
		return nil, nil
	}
	repo, err := s.getRepoActorByDid(ctx, iss)
	if err != nil {
		return nil, err
	}
	key, err := s.accountSigner(repo.Repo)
	if err != nil {
		return nil, err
	}
	tok, err := mintServiceAuth(key, iss, service, lxm, time.Minute)
	if err != nil {
		return nil, err
	}
	return &notifyTarget{endpoint: strings.TrimRight(ep, "/"), headers: map[string]string{"Authorization": "Bearer " + tok}}, nil
}

var errNoTarget = fmt.Errorf("could not resolve target")
