package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// RFC 7636 appendix B test vector (S256).
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// newTestDpopProofForKey signs a DPoP proof JWT with the provided ES256 key
// (same shape as newTestDpopProof, but the key is supplied so the caller can
// also compute its JKT).
func newTestDpopProofForKey(t *testing.T, s *Server, priv *ecdsa.PrivateKey, method, htu string, accessToken *string) string {
	t.Helper()

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

	claims := map[string]any{
		"iat":   time.Now().Unix(),
		"jti":   helpers.RandomVarchar(20),
		"htm":   method,
		"htu":   htu,
		"nonce": s.oauthProvider.NextNonce(),
	}
	if accessToken != nil {
		sum := sha256.Sum256([]byte(*accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return signed
}

// newTestDpopProofWithJkt is newTestDpopProof extended to also return the
// proof key's JKT (RFC 9449 thumbprint), so a PAR row can be seeded with the
// matching dpop_jkt.
func newTestDpopProofWithJkt(t *testing.T, s *Server, method, htu string) (string, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	proof := newTestDpopProofForKey(t, s, priv, method, htu, nil)

	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("build public jwk: %v", err)
	}
	thumbBytes, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	return proof, base64.RawURLEncoding.EncodeToString(thumbBytes)
}

// seedPendingAuthRequest inserts a pending (not yet authorized) PAR row for
// the given subject DID, with PKCE and DPoP binding, returning its request_uri.
func seedPendingAuthRequest(t *testing.T, s *Server, did, dpopJkt string, expiresAt time.Time) string {
	t.Helper()

	authReq := provider.OauthAuthorizationRequest{
		RequestId: "req-" + helpers.RandomVarchar(8),
		ClientId:  "http://localhost",
		Parameters: provider.ParRequest{
			AuthenticateClientRequestBase: provider.AuthenticateClientRequestBase{ClientID: "http://localhost"},
			ResponseType:                  "code",
			RedirectURI:                   "http://127.0.0.1/",
			State:                         "state-admin-1",
			Scope:                         "atproto",
			CodeChallenge:                 to.StringPtr(pkceChallenge),
			CodeChallengeMethod:           "S256",
			DpopJkt:                       to.StringPtr(dpopJkt),
		},
		ExpiresAt: expiresAt,
	}
	if err := s.db.Create(context.Background(), &authReq, nil).Error; err != nil {
		t.Fatalf("seed authorization request: %v", err)
	}
	return oauth.EncodeRequestUri(authReq.RequestId)
}

// callAdminAuthorize drives the middleware-wrapped admin authorize endpoint
// (Basic auth lives in handleAdminMiddleware, so the chain must be exercised,
// not the bare handler). Empty user/pass sends no Authorization header.
func callAdminAuthorize(t *testing.T, s *Server, body, user, pass string) (*httptest.ResponseRecorder, map[string]string) {
	t.Helper()

	headers := map[string]string{}
	if user != "" || pass != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	c, rec := newRequestContext(http.MethodPost, "/admin/oauth/authorize", body, headers)

	h := s.handleAdminMiddleware(s.handleAdminOauthAuthorize)
	if err := h(c); err != nil {
		c.Error(err)
	}

	var resp map[string]string
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
		}
	}
	return rec, resp
}

// TestAdminOauthAuthorizeHappyPath verifies that valid admin Basic auth
// completes a pending PAR request for an existing DID: the response code
// matches the persisted row, sub equals the DID, and accepted is set.
func TestAdminOauthAuthorizeHappyPath(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	requestUri := seedPendingAuthRequest(t, s, acct.Did, "", time.Now().Add(time.Hour))

	body, err := json.Marshal(map[string]string{"requestUri": requestUri, "did": acct.Did})
	if err != nil {
		t.Fatal(err)
	}
	rec, resp := callAdminAuthorize(t, s, string(body), "admin", "admin-test-password")

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body %s)", rec.Code, rec.Body.String())
	}
	if resp["code"] == "" {
		t.Fatal("expected non-empty code in response")
	}
	if resp["state"] != "state-admin-1" {
		t.Fatalf("expected state %q, got %q", "state-admin-1", resp["state"])
	}
	if resp["redirectUri"] != "http://127.0.0.1/" {
		t.Fatalf("expected redirectUri %q, got %q", "http://127.0.0.1/", resp["redirectUri"])
	}
	if resp["iss"] != "https://"+testHostname {
		t.Fatalf("expected iss %q, got %q", "https://"+testHostname, resp["iss"])
	}

	var row provider.OauthAuthorizationRequest
	if err := s.db.Raw(context.Background(), "SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, decodeReqUri(t, requestUri)).Scan(&row).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	if row.Sub == nil || *row.Sub != acct.Did {
		t.Fatalf("expected sub %q, got %v", acct.Did, row.Sub)
	}
	if row.Code == nil || *row.Code != resp["code"] {
		t.Fatalf("expected persisted code %q, got %v", resp["code"], row.Code)
	}
	if row.Accepted == nil || !*row.Accepted {
		t.Fatal("expected accepted to be set true")
	}
}

func decodeReqUri(t *testing.T, requestUri string) string {
	t.Helper()
	id, err := oauth.DecodeRequestUri(requestUri)
	if err != nil {
		t.Fatalf("decode request uri: %v", err)
	}
	return id
}

// TestAdminOauthAuthorizeExchange proves the full headless loop: a code minted
// by the admin endpoint exchanges at /oauth/token with DPoP + PKCE for tokens
// whose sub is the requested DID.
func TestAdminOauthAuthorizeExchange(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	acct := s.createTestAccount(t, "bob.pds.test")

	proof, jkt := newTestDpopProofWithJkt(t, s, http.MethodPost, "https://"+testHostname+"/oauth/token")
	requestUri := seedPendingAuthRequest(t, s, acct.Did, jkt, time.Now().Add(time.Hour))

	body, err := json.Marshal(map[string]string{"requestUri": requestUri, "did": acct.Did})
	if err != nil {
		t.Fatal(err)
	}
	rec, resp := callAdminAuthorize(t, s, string(body), "admin", "admin-test-password")
	if rec.Code != 200 {
		t.Fatalf("expected 200 from admin authorize, got %d (body %s)", rec.Code, rec.Body.String())
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"http://localhost"},
		"code":          {resp["code"]},
		"redirect_uri":  {"http://127.0.0.1/"},
		"code_verifier": {pkceVerifier},
	}
	c, trec := newRequestContext(http.MethodPost, "/oauth/token", form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         proof,
	})
	if err := s.handleOauthToken(c); err != nil {
		c.Error(err)
	}

	if trec.Code != 200 {
		t.Fatalf("expected 200 from token exchange, got %d (body %s)", trec.Code, trec.Body.String())
	}

	var tokResp OauthTokenResponse
	if err := json.Unmarshal(trec.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokResp.Sub != acct.Did {
		t.Fatalf("expected sub %q, got %q", acct.Did, tokResp.Sub)
	}
	if tokResp.AccessToken == "" || tokResp.RefreshToken == "" {
		t.Fatal("expected non-empty access and refresh tokens")
	}
	if tokResp.TokenType != "DPoP" {
		t.Fatalf("expected DPoP token type, got %q", tokResp.TokenType)
	}
}

// TestAdminOauthAuthorizeAuthRejection verifies wrong and missing Basic auth
// are both rejected (HTTP 400 per handleAdminMiddleware's existing behavior).
func TestAdminOauthAuthorizeAuthRejection(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "carol.pds.test")
	requestUri := seedPendingAuthRequest(t, s, acct.Did, "", time.Now().Add(time.Hour))

	body, err := json.Marshal(map[string]string{"requestUri": requestUri, "did": acct.Did})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		user string
		pass string
	}{
		{name: "wrong password", user: "admin", pass: "wrong"},
		{name: "wrong user", user: "root", pass: "admin-test-password"},
		{name: "missing auth", user: "", pass: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, resp := callAdminAuthorize(t, s, string(body), tc.user, tc.pass)
			if rec.Code != 400 {
				t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
			}
			if resp["error"] != "Unauthorized" {
				t.Fatalf("expected error Unauthorized, got %q", resp["error"])
			}
		})
	}

	// A rejected call must not have authorized the pending request.
	var row provider.OauthAuthorizationRequest
	if err := s.db.Raw(context.Background(), "SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, decodeReqUri(t, requestUri)).Scan(&row).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	if row.Code != nil {
		t.Fatal("expected no code minted for unauthenticated call")
	}
}

// TestAdminOauthAuthorizeNegatives covers expired, already-authorized,
// unknown-DID, malformed-requestUri, invalid-DID, and unknown-request cases.
func TestAdminOauthAuthorizeNegatives(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "dave.pds.test")

	const admin = "admin"
	const pass = "admin-test-password"

	t.Run("expired request", func(t *testing.T) {
		requestUri := seedPendingAuthRequest(t, s, acct.Did, "", time.Now().Add(-time.Minute))
		body, _ := json.Marshal(map[string]string{"requestUri": requestUri, "did": acct.Did})
		rec, resp := callAdminAuthorize(t, s, string(body), admin, pass)
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
		if resp["error"] != "the request has expired" {
			t.Fatalf("expected expiry error, got %q", resp["error"])
		}
	})

	t.Run("already authorized", func(t *testing.T) {
		requestUri := seedPendingAuthRequest(t, s, acct.Did, "", time.Now().Add(time.Hour))
		// authorize once
		body, _ := json.Marshal(map[string]string{"requestUri": requestUri, "did": acct.Did})
		rec, _ := callAdminAuthorize(t, s, string(body), admin, pass)
		if rec.Code != 200 {
			t.Fatalf("setup: expected 200, got %d", rec.Code)
		}
		// authorize again
		rec, resp := callAdminAuthorize(t, s, string(body), admin, pass)
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
		if resp["error"] != "this request was already authorized" {
			t.Fatalf("expected already-authorized error, got %q", resp["error"])
		}
	})

	t.Run("unknown did", func(t *testing.T) {
		requestUri := seedPendingAuthRequest(t, s, acct.Did, "", time.Now().Add(time.Hour))
		body, _ := json.Marshal(map[string]string{"requestUri": requestUri, "did": "did:plc:doesnotexistaaaaaaaaaaa"})
		rec, resp := callAdminAuthorize(t, s, string(body), admin, pass)
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
		if resp["error"] != "unable to find actor" {
			t.Fatalf("expected unknown-actor error, got %q", resp["error"])
		}
	})

	t.Run("unparseable request uri", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"requestUri": "not-a-request-uri", "did": acct.Did})
		rec, resp := callAdminAuthorize(t, s, string(body), admin, pass)
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
		if resp["error"] == "" || resp["error"] == "InvalidRequest" {
			t.Fatalf("expected specific decode error, got %q", resp["error"])
		}
	})

	t.Run("invalid did format", func(t *testing.T) {
		requestUri := seedPendingAuthRequest(t, s, acct.Did, "", time.Now().Add(time.Hour))
		body, _ := json.Marshal(map[string]string{"requestUri": requestUri, "did": "not-a-did"})
		rec, _ := callAdminAuthorize(t, s, string(body), admin, pass)
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown request", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"requestUri": oauth.EncodeRequestUri("req-doesnotexist"), "did": acct.Did})
		rec, resp := callAdminAuthorize(t, s, string(body), admin, pass)
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
		if resp["error"] == "" {
			t.Fatal("expected an error message")
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		rec, _ := callAdminAuthorize(t, s, `{}`, admin, pass)
		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d (body %s)", rec.Code, rec.Body.String())
		}
	})
}
