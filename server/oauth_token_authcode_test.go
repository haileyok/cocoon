package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/oauth/client"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func attachOauthProvider(t *testing.T, s *Server) {
	t.Helper()
	s.oauthProvider = provider.NewProvider(provider.Args{
		Hostname: testHostname,
		ClientManagerArgs: client.ManagerArgs{
			Cli:    http.DefaultClient,
			Logger: s.logger,
		},
		DpopManagerArgs: dpop.ManagerArgs{
			NonceSecret:           []byte("test-nonce-secret"),
			NonceRotationInterval: time.Hour,
			Logger:                s.logger,
			Hostname:              testHostname,
		},
	})
}

// TestOauthTokenAuthorizationCodeMissingActor drives the authorization_code
// grant with an authorization request whose subject has no repo (e.g. the
// account was deleted between consent and token exchange). The handler must
// return an error response, not dereference a nil repo and panic.
func TestOauthTokenAuthorizationCodeMissingActor(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	attachOauthProvider(t, s)

	const (
		clientID    = "http://localhost"
		redirectURI = "http://127.0.0.1/"
		code        = "test-auth-code"
	)

	authReq := provider.OauthAuthorizationRequest{
		RequestId:  "req-1",
		ClientId:   clientID,
		ClientAuth: provider.ClientAuth{Method: "none"},
		Parameters: provider.ParRequest{
			AuthenticateClientRequestBase: provider.AuthenticateClientRequestBase{ClientID: clientID},
			ResponseType:                  "code",
			RedirectURI:                   redirectURI,
			State:                         "state-1",
			Scope:                         "atproto",
		},
		ExpiresAt: time.Now().Add(time.Hour),
		Sub:       to.StringPtr("did:plc:doesnotexistxxxxxxxxxxxx"),
		Code:      to.StringPtr(code),
	}
	if err := s.db.Create(ctx, &authReq, nil).Error; err != nil {
		t.Fatalf("seed authorization request: %v", err)
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {clientID},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	c, rec := newRequestContext(http.MethodPost, "/oauth/token", form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/token", nil),
	})

	// Must not panic, and must surface an error response (not a token).
	if err := s.handleOauthToken(c); err != nil {
		c.Error(err)
	}
	if rec.Code/100 == 2 {
		t.Fatalf("expected an error response for a missing actor, got %d", rec.Code)
	}
}

func authorizationCodeFixture(t *testing.T, s *Server, account *testAccount) (provider.OauthAuthorizationRequest, url.Values) {
	t.Helper()
	key, err := jwk.FromRaw(s.privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	auth := provider.OauthAuthorizationRequest{
		RequestId: "exchange-request", ClientId: "http://localhost",
		ClientAuth: provider.ClientAuth{Method: "none"},
		Sub:        &account.Did, Code: to.StringPtr("exchange-code"), Accepted: to.BoolPtr(true),
		ExpiresAt: time.Now().Add(time.Minute),
		Parameters: provider.ParRequest{
			Scope: "atproto", RedirectURI: "http://127.0.0.1/",
			DpopJkt: to.StringPtr(base64.RawURLEncoding.EncodeToString(thumb)),
			// RFC 7636 Appendix B's independent S256 test vector.
			CodeChallenge: to.StringPtr("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), CodeChallengeMethod: "S256",
		},
	}
	form := url.Values{
		"client_id": {auth.ClientId}, "grant_type": {"authorization_code"},
		"code": {*auth.Code}, "redirect_uri": {auth.Parameters.RedirectURI},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}
	return auth, form
}

func authorizationCodeRequest(t *testing.T, s *Server, form url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "https://"+testHostname+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("DPoP", newTestDpopProofWithKey(t, s, r.Method, r.URL.String(), nil, s.privateKey))
	return r
}

type codeExchangeResolver func(context.Context)

func (f codeExchangeResolver) ResolvePermissionSet(ctx context.Context, _ string) (*lexicon.SchemaPermissionSet, error) {
	f(ctx)
	return &lexicon.SchemaPermissionSet{Permissions: []lexicon.SchemaPermission{
		{Resource: "repo", Collection: []string{"com.example.record"}, Action: []string{"create"}},
	}}, nil
}

func TestOauthCodeExchangeValidation(t *testing.T) {
	for _, name := range []string{
		"expired", "wrong client", "changed auth method", "missing proof", "wrong proof",
		"missing proof without prior binding", "wrong redirect", "missing verifier", "wrong verifier", "revoked session",
	} {
		t.Run(name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			auth, form := authorizationCodeFixture(t, s, account)
			switch name {
			case "expired":
				auth.ExpiresAt = time.Now().Add(-time.Second)
			case "wrong client":
				auth.ClientId = "http://localhost?scope=atproto"
			case "changed auth method":
				auth.ClientAuth.Method = "private_key_jwt"
			case "missing proof without prior binding":
				auth.Parameters.DpopJkt = nil
			case "wrong redirect":
				form.Set("redirect_uri", "http://127.0.0.1/other")
			case "missing verifier":
				form.Del("code_verifier")
			case "wrong verifier":
				form.Set("code_verifier", strings.Repeat("x", 43))
			case "revoked session":
				auth.SessionVersion = -1
			}
			if err := s.db.Create(context.Background(), &auth, nil).Error; err != nil {
				t.Fatal(err)
			}
			var before provider.OauthAuthorizationRequest
			if err := s.db.First(context.Background(), &before, "request_id = ?", auth.RequestId).Error; err != nil {
				t.Fatal(err)
			}
			r := authorizationCodeRequest(t, s, form)
			switch name {
			case "missing proof", "missing proof without prior binding":
				r.Header.Del("DPoP")
			case "wrong proof":
				r.Header.Set("DPoP", newTestDpopProof(t, s, r.Method, r.URL.String(), nil))
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Errorf("status = %d, want 400: %s", w.Code, w.Body.String())
			}
			wantError := "invalid_grant"
			switch name {
			case "missing proof without prior binding":
				wantError = "invalid_dpop_proof"
			case "wrong redirect", "missing verifier":
				wantError = ""
			}
			var response map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || (wantError != "" && response["error"] != wantError) {
				t.Fatalf("expected %s: %s", wantError, w.Body.String())
			}
			var after provider.OauthAuthorizationRequest
			if err := s.db.First(context.Background(), &after, "request_id = ?", auth.RequestId).Error; err != nil {
				t.Fatalf("rejected exchange consumed grant: %v", err)
			}
			if !reflect.DeepEqual(before, after) || countOauthTokens(t, s) != 0 {
				t.Fatal("rejected exchange changed the grant or issued a token")
			}
		})
	}
}

func TestOauthCodeExchangeSingleUse(t *testing.T) {
	for _, name := range []string{"bound", "bound at exchange", "concurrent", "issuance failure"} {
		t.Run(name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			auth, form := authorizationCodeFixture(t, s, account)
			wantJkt := *auth.Parameters.DpopJkt
			wantScope := "atproto"
			n := 1
			if name == "bound at exchange" {
				auth.Parameters.DpopJkt = nil
			}
			if name == "concurrent" {
				n = 8
				sqlDB, err := s.db.Client().DB()
				if err != nil {
					t.Fatal(err)
				}
				sqlDB.SetMaxOpenConns(1)
				auth.Parameters.Scope = "atproto include:com.example.permissions"
				wantScope = auth.Parameters.Scope + " repo:com.example.record?action=create"
				var arrived atomic.Int32
				release := make(chan struct{})
				s.scopeResolver = codeExchangeResolver(func(ctx context.Context) {
					if arrived.Add(1) == int32(n) {
						close(release)
					}
					select {
					case <-release:
					case <-ctx.Done():
					}
				})
			}
			if err := s.db.Create(ctx, &auth, nil).Error; err != nil {
				t.Fatal(err)
			}
			if name == "issuance failure" {
				if err := s.db.Exec(ctx, "CREATE TRIGGER fail_token BEFORE INSERT ON oauth_tokens BEGIN SELECT RAISE(ABORT, 'test failure'); END", nil).Error; err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
				if w.Code != 500 || countAuthRequests(t, s) != 1 || countOauthTokens(t, s) != 0 {
					t.Fatalf("failed issuance must preserve grant without tokens: %d %s", w.Code, w.Body.String())
				}
				if err := s.db.Exec(ctx, "DROP TRIGGER fail_token", nil).Error; err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			results := make(chan *httptest.ResponseRecorder, n)
			for range n {
				r := authorizationCodeRequest(t, s, form).WithContext(ctx)
				go func() {
					<-start
					w := httptest.NewRecorder()
					s.echo.ServeHTTP(w, r)
					results <- w
				}()
			}
			close(start)
			var response OauthTokenResponse
			successes := 0
			for range n {
				w := <-results
				if w.Code == 200 {
					successes++
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
				} else {
					assertInvalidGrant(t, w)
				}
			}
			if successes != 1 || countAuthRequests(t, s) != 0 || countOauthTokens(t, s) != 1 {
				t.Fatalf("wanted exactly one consumed grant and token, got %d successful exchanges", successes)
			}
			var token provider.OauthToken
			if err := s.db.First(ctx, &token, "token = ?", response.AccessToken).Error; err != nil {
				t.Fatal(err)
			}
			if response.TokenType != "DPoP" || response.Sub != account.Did || response.Scope != wantScope || token.Parameters.Scope != wantScope ||
				token.RefreshToken != response.RefreshToken || token.Parameters.DpopJkt == nil || *token.Parameters.DpopJkt != wantJkt {
				t.Fatalf("incorrect issued credentials: %+v", response)
			}
			parsed, err := jwt.Parse(response.AccessToken, func(*jwt.Token) (any, error) { return s.privateKey.Public(), nil }, jwt.WithValidMethods([]string{"ES256"}))
			if err != nil {
				t.Fatal(err)
			}
			claims := parsed.Claims.(jwt.MapClaims)
			cnf, ok := claims["cnf"].(map[string]any)
			if !ok || cnf["jkt"] != wantJkt || claims["scope"] != wantScope {
				t.Fatal("JWT scope or DPoP confirmation differs from the issued grant")
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
			assertInvalidGrant(t, w)
			if countOauthTokens(t, s) != 1 {
				t.Fatal("replay changed token count")
			}
		})
	}
}

func TestOauthCodeExchangeRechecksAfterScopeResolution(t *testing.T) {
	for _, name := range []string{"expiry", "revocation", "deletion"} {
		t.Run(name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			auth, form := authorizationCodeFixture(t, s, account)
			auth.Parameters.Scope = "atproto include:com.example.permissions"
			if err := s.db.Create(context.Background(), &auth, nil).Error; err != nil {
				t.Fatal(err)
			}
			s.scopeResolver = codeExchangeResolver(func(ctx context.Context) {
				var err error
				switch name {
				case "expiry":
					err = s.db.Exec(ctx, "UPDATE oauth_authorization_requests SET expires_at = ? WHERE request_id = ?", nil, time.Now().Add(-time.Second), auth.RequestId).Error
				case "revocation":
					err = s.db.Exec(ctx, "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, account.Did).Error
				case "deletion":
					err = s.db.Exec(ctx, "DELETE FROM oauth_authorization_requests WHERE request_id = ?", nil, auth.RequestId).Error
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
			assertInvalidGrant(t, w)
			if countOauthTokens(t, s) != 0 {
				t.Fatal("invalidated grant issued tokens")
			}
		})
	}
}
