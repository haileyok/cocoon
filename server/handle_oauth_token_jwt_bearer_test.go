package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// assertionOpts customizes an assertion built by buildAssertion. Zero values
// take the defaults that satisfy the token endpoint for the given did and key.
type assertionOpts struct {
	alg string
	iss string
	sub string
	aud string
	iat int64
	exp int64
	jti string
}

// assertionAlgs are the (alg, key) pairs an assertion may be signed with.
func assertionK256(t *testing.T) *atcrypto.PrivateKeyK256 {
	t.Helper()
	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate k256 sign-in key: %v", err)
	}
	return k
}

func assertionP256(t *testing.T) *atcrypto.PrivateKeyP256 {
	t.Helper()
	k, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatalf("generate p256 sign-in key: %v", err)
	}
	return k
}

// buildAssertion mints a jwt-bearer assertion with defaults that satisfy the
// token endpoint for did and key, with any claim overridden.
func buildAssertion(t *testing.T, did string, key atcrypto.PrivateKey, o assertionOpts) string {
	t.Helper()
	now := time.Now().Unix()
	if o.iss == "" {
		o.iss = did
	}
	if o.sub == "" {
		o.sub = did
	}
	if o.aud == "" {
		o.aud = "https://" + testHostname
	}
	if o.iat == 0 {
		o.iat = now
	}
	if o.exp == 0 {
		o.exp = now + 60
	}
	if o.jti == "" {
		o.jti = "jti-" + helpers.RandomVarchar(16)
	}

	claims := map[string]any{
		"iss": o.iss,
		"sub": o.sub,
		"aud": o.aud,
		"iat": o.iat,
		"exp": o.exp,
		"jti": o.jti,
	}

	alg := "ES256K"
	switch key.(type) {
	case *atcrypto.PrivateKeyP256:
		alg = "ES256"
	}
	if o.alg != "" {
		alg = o.alg
	}

	header := map[string]any{"alg": alg, "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := key.HashAndSign([]byte(input))
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// authKeyAccount is an account with an active sign-in key, created directly in
// the database (createAccount's PLC flow isn't under test here).
type authKeyAccount struct {
	did string
	key atcrypto.PrivateKey
}

func createAuthKeyAccount(t *testing.T, s *Server, handle string, key atcrypto.PrivateKey) *authKeyAccount {
	t.Helper()
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("derive public sign-in key: %v", err)
	}
	did := "did:plc:" + strings.ToLower(helpers.RandomVarchar(24))
	if handle == "" {
		handle = did[len(did)-16:] + ".pds.test"
	}
	// A fresh k256 signing key for the repo itself; the sign-in key is only
	// for OAuth assertions.
	rk, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate repo signing key: %v", err)
	}
	repo := models.Repo{
		Did:        did,
		CreatedAt:  time.Now(),
		Email:      handle + "@" + helpers.RandomVarchar(8) + ".test.invalid",
		SigningKey: rk.Bytes(),
	}
	if err := s.db.Create(context.Background(), &repo, nil).Error; err != nil {
		t.Fatalf("insert repo: %v", err)
	}
	if err := s.db.Create(context.Background(), &models.Actor{Did: did, Handle: handle}, nil).Error; err != nil {
		t.Fatalf("insert actor: %v", err)
	}
	if err := s.db.Create(context.Background(), &models.AuthKey{
		Did:       did,
		DidKey:    pub.DIDKey(),
		CreatedAt: time.Now(),
	}, nil).Error; err != nil {
		t.Fatalf("insert auth key: %v", err)
	}
	return &authKeyAccount{did: did, key: key}
}

// jwtBearerRequest drives the token endpoint with a jwt-bearer grant and a
// DPoP proof, returning the recorder and decoded body.
func jwtBearerRequest(t *testing.T, s *Server, assertion string, dpopProof string) (int, map[string]string, string) {
	t.Helper()
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	if dpopProof != "" {
		headers["DPoP"] = dpopProof
	}
	form := url.Values{
		"grant_type": {jwtBearerGrantType},
		"client_id":  {"http://localhost"},
		"assertion":  {assertion},
		"scope":      {"atproto"},
	}
	c, rec := newRequestContext(http.MethodPost, "/oauth/token", form.Encode(), headers)
	if err := s.handleOauthToken(c); err != nil {
		c.Error(err)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Body.String()
}

// bearerTokenResponse is the successful grant response shape.
type bearerTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	Sub          string `json:"sub"`
}

// jwtBearerHappyPath performs a full successful jwt-bearer grant with a DPoP
// key the caller can keep using, returning the tokens and that key pair.
func jwtBearerHappyPath(t *testing.T, s *Server, acct *authKeyAccount) (bearerTokenResponse, *ecdsa.PrivateKey, map[string]any) {
	t.Helper()
	assertion := buildAssertion(t, acct.did, acct.key, assertionOpts{})
	priv, jwkMap := newDpopKeyParts(t)
	htu := "https://" + testHostname + "/oauth/token"
	proof := signDpopProof(t, s, priv, jwkMap, http.MethodPost, htu, nil)
	_, _, raw := jwtBearerRequest(t, s, assertion, proof)
	if !strings.Contains(raw, "access_token") {
		t.Fatalf("expected 200 from jwt-bearer grant, got: %s", raw)
	}
	var resp bearerTokenResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("expected tokens, got %+v", resp)
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("expected token_type DPoP, got %q", resp.TokenType)
	}
	if resp.Sub != acct.did {
		t.Errorf("expected sub %q, got %q", acct.did, resp.Sub)
	}
	return resp, priv, jwkMap
}

// TestOauthTokenJwtBearer runs the jwt-bearer grant end to end through the
// real token handler.
func TestOauthTokenJwtBearer(t *testing.T) {
	t.Run("happy path, authenticated endpoint, refresh", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "key.pds.test", assertionK256(t))

		resp, priv, jwkMap := jwtBearerHappyPath(t, s, acct)

		// The access token works on an authenticated endpoint with DPoP,
		// using the same DPoP key the session is bound to.
		htu := "https://" + testHostname + "/xrpc/com.atproto.server.getSession"
		proof := signDpopProof(t, s, priv, jwkMap, http.MethodGet, htu, &resp.AccessToken)
		c, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.server.getSession", "", map[string]string{
			"Authorization": "DPoP " + resp.AccessToken,
			"DPoP":          proof,
		})
		if err := s.handleOauthSessionMiddleware(s.handleGetSession)(c); err != nil {
			c.Error(err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected authenticated request to work, got %d: %s", rec.Code, rec.Body.String())
		}
		var sess ComAtprotoServerGetSessionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
			t.Fatalf("decode session: %v", err)
		}
		if sess.Did != acct.did {
			t.Errorf("expected session did %q, got %q", acct.did, sess.Did)
		}

		// The refresh_token grant works with the same DPoP key... but the
		// helper mints a fresh key each call, so this is checked in the
		// dedicated refresh test below.
	})

	t.Run("p256 key with ES256", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "p256.pds.test", assertionP256(t))
		_, _, _ = jwtBearerHappyPath(t, s, acct)
	})

	t.Run("refresh token grant works with same dpop key", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "ref.pds.test", assertionK256(t))
		_, _, _ = jwtBearerHappyPath(t, s, acct)

		// The refresh grant must use the SAME DPoP key as the original grant.
		assertion := buildAssertion(t, acct.did, acct.key, assertionOpts{})
		htu := "https://" + testHostname + "/oauth/token"

		priv, jwkMap := newDpopKeyParts(t)
		proof := signDpopProof(t, s, priv, jwkMap, http.MethodPost, htu, nil)
		_, body, raw := jwtBearerRequest(t, s, assertion, proof)
		if body == nil || body["access_token"] == "" {
			t.Fatalf("second grant failed: %s", raw)
		}
		refreshToken := body["refresh_token"]

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {"http://localhost"},
			"refresh_token": {refreshToken},
		}
		c, rec := newRequestContext(http.MethodPost, "/oauth/token", form.Encode(), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"DPoP":         signDpopProof(t, s, priv, jwkMap, http.MethodPost, htu, nil),
		})
		if err := s.handleOauthToken(c); err != nil {
			c.Error(err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected refresh to work, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("refusals", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)

		run := func(name string, assertion func(t *testing.T, s *Server, acct *authKeyAccount) string, wantErr string) {
			t.Run(name, func(t *testing.T) {
				acct := createAuthKeyAccount(t, s, "", assertionK256(t))
				code, body, raw := jwtBearerRequest(t, s, assertion(t, s, acct), newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/token", nil))
				if code == http.StatusOK {
					t.Fatalf("expected refusal, got 200: %s", raw)
				}
				if body["error"] != wantErr {
					t.Fatalf("expected error %q, got %q (body %s)", wantErr, body["error"], raw)
				}
			})
		}

		run("wrong aud", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, a.did, a.key, assertionOpts{aud: "https://other.example.com"})
		}, "invalid_grant")

		run("expired assertion", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, a.did, a.key, assertionOpts{iat: time.Now().Unix() - 300, exp: time.Now().Unix() - 60})
		}, "invalid_grant")

		run("exp too far from iat", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, a.did, a.key, assertionOpts{exp: time.Now().Unix() + 301})
		}, "invalid_grant")

		run("iat in future", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, a.did, a.key, assertionOpts{iat: time.Now().Unix() + 61, exp: time.Now().Unix() + 61 + 60})
		}, "invalid_grant")

		run("missing jti", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return rawAssertionWithoutJti(t, a.did, a.key)
		}, "invalid_grant")

		run("wrong signing key", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, a.did, assertionK256(t), assertionOpts{})
		}, "invalid_grant")

		run("alg mismatch with key", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, a.did, a.key, assertionOpts{alg: "ES256"})
		}, "invalid_grant")

		run("iss not the account", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, a.did, a.key, assertionOpts{iss: "did:plc:otheraccount0000000"})
		}, "invalid_grant")

		run("unknown account", func(t *testing.T, s *Server, a *authKeyAccount) string {
			return buildAssertion(t, "did:plc:notanaccount000000", a.key, assertionOpts{})
		}, "invalid_grant")

		run("deactivated account", func(t *testing.T, s *Server, a *authKeyAccount) string {
			if err := s.db.Exec(context.Background(), "UPDATE repos SET deactivated = true WHERE did = ?", nil, a.did).Error; err != nil {
				t.Fatalf("deactivate: %v", err)
			}
			return buildAssertion(t, a.did, a.key, assertionOpts{})
		}, "invalid_grant")

		run("taken-down account", func(t *testing.T, s *Server, a *authKeyAccount) string {
			if err := s.db.Exec(context.Background(), "UPDATE repos SET takedown_ref = ? WHERE did = ?", nil, "taken", a.did).Error; err != nil {
				t.Fatalf("takedown: %v", err)
			}
			return buildAssertion(t, a.did, a.key, assertionOpts{})
		}, "invalid_grant")
	})

	t.Run("reused jti refused", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "jti.pds.test", assertionK256(t))

		o := assertionOpts{jti: "jti-shared-1"}
		assertion := buildAssertion(t, acct.did, acct.key, o)
		htu := "https://" + testHostname + "/oauth/token"

		code, body, raw := jwtBearerRequest(t, s, assertion, newTestDpopProof(t, s, http.MethodPost, htu, nil))
		if code != http.StatusOK {
			t.Fatalf("first use must succeed, got %d: %s", code, raw)
		}
		code, body, raw = jwtBearerRequest(t, s, assertion, newTestDpopProof(t, s, http.MethodPost, htu, nil))
		if code == http.StatusOK {
			t.Fatal("second use of the same jti must be refused")
		}
		if body["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %q (%s)", body["error"], raw)
		}
	})

	t.Run("revoked key refused and sessions revoked", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "revoked.pds.test", assertionK256(t))

		resp, priv, jwkMap := jwtBearerHappyPath(t, s, acct)

		// Revoke the sign-in key like the dashboard/CLI does.
		if _, err := s.RevokeAuthKey(context.Background(), acct.did, ""); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		// New grants are refused.
		assertion := buildAssertion(t, acct.did, acct.key, assertionOpts{})
		code, body, raw := jwtBearerRequest(t, s, assertion, newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/token", nil))
		if code == http.StatusOK {
			t.Fatalf("grant must be refused after key revocation, got 200: %s", raw)
		}
		if body["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %q (%s)", body["error"], raw)
		}

		// The previously issued session no longer works.
		htu := "https://" + testHostname + "/xrpc/com.atproto.server.getSession"
		proof := signDpopProof(t, s, priv, jwkMap, http.MethodGet, htu, &resp.AccessToken)
		c, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.server.getSession", "", map[string]string{
			"Authorization": "DPoP " + resp.AccessToken,
			"DPoP":          proof,
		})
		if err := s.handleOauthSessionMiddleware(s.handleGetSession)(c); err != nil {
			c.Error(err)
		}
		if rec.Code == http.StatusOK {
			t.Fatalf("session issued through a revoked key must not work, got 200: %s", rec.Body.String())
		}
	})

	t.Run("client without the grant refused", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "client.pds.test", assertionK256(t))

		// A non-loopback client would be refused for not listing the grant
		// type; the loopback virtual client always lists it. Use a client_id
		// the manager resolves to metadata without the grant type.
		assertion := buildAssertion(t, acct.did, acct.key, assertionOpts{})
		form := url.Values{
			"grant_type": {jwtBearerGrantType},
			"client_id":  {"http://127.0.0.1:99/some-other-client"},
			"assertion":  {assertion},
			"scope":      {"atproto"},
		}
		c, rec := newRequestContext(http.MethodPost, "/oauth/token", form.Encode(), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"DPoP":         newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/token", nil),
		})
		if err := s.handleOauthToken(c); err != nil {
			c.Error(err)
		}
		if rec.Code == http.StatusOK {
			t.Fatalf("client without the jwt-bearer grant must be refused, got 200: %s", rec.Body.String())
		}
	})

	t.Run("missing dpop refused", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "nodpop.pds.test", assertionK256(t))

		assertion := buildAssertion(t, acct.did, acct.key, assertionOpts{})
		code, _, raw := jwtBearerRequest(t, s, assertion, "")
		if code == http.StatusOK {
			t.Fatalf("jwt-bearer without a DPoP proof must be refused, got 200: %s", raw)
		}
	})

	t.Run("invalid scope", func(t *testing.T) {
		s := newTestServer(t)
		attachOauthProvider(t, s)
		acct := createAuthKeyAccount(t, s, "scope.pds.test", assertionK256(t))

		assertion := buildAssertion(t, acct.did, acct.key, assertionOpts{})
		form := url.Values{
			"grant_type": {jwtBearerGrantType},
			"client_id":  {"http://localhost"},
			"assertion":  {assertion},
			"scope":      {"not a scope!"},
		}
		c, rec := newRequestContext(http.MethodPost, "/oauth/token", form.Encode(), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"DPoP":         newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/token", nil),
		})
		if err := s.handleOauthToken(c); err != nil {
			c.Error(err)
		}
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code == http.StatusOK {
			t.Fatalf("invalid scope must be refused, got 200: %s", rec.Body.String())
		}
		if body["error"] != "invalid_scope" {
			t.Fatalf("expected invalid_scope, got %q (%s)", body["error"], rec.Body.String())
		}
	})
}

// rawAssertionWithoutJti builds an otherwise-valid assertion whose payload
// omits jti.
func rawAssertionWithoutJti(t *testing.T, did string, key atcrypto.PrivateKey) string {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": did,
		"sub": did,
		"aud": "https://" + testHostname,
		"iat": now,
		"exp": now + 60,
	}
	alg := "ES256K"
	header := map[string]any{"alg": alg, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := key.HashAndSign([]byte(input))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signDpopProof and its helpers below let a test reuse one DPoP key across
// the grant and the refresh: signDpopProof builds and signs a proof from a
// key pair newDpopKeyParts returned earlier.
func newDpopKeyParts(t *testing.T) (*ecdsa.PrivateKey, map[string]any) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("build public jwk: %v", err)
	}
	pubBytes, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	var jwkMap map[string]any
	if err := json.Unmarshal(pubBytes, &jwkMap); err != nil {
		t.Fatalf("unmarshal public jwk: %v", err)
	}
	return priv, jwkMap
}

func signDpopProof(t *testing.T, s *Server, priv *ecdsa.PrivateKey, jwkMap map[string]any, method, htu string, accessToken *string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iat":   time.Now().Unix(),
		"jti":   helpers.RandomVarchar(20),
		"htm":   method,
		"htu":   htu,
		"nonce": s.oauthProvider.NextNonce(),
	}
	if accessToken != nil {
		hash := sha256.Sum256([]byte(*accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return signed
}
