package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		"missing proof without prior binding", "wrong redirect", "missing redirect", "missing verifier", "short verifier", "wrong verifier", "revoked session",
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
			case "missing redirect":
				form.Del("redirect_uri")
			case "missing verifier":
				form.Del("code_verifier")
			case "short verifier":
				form.Set("code_verifier", strings.Repeat("x", 42))
			case "wrong verifier":
				form.Set("code_verifier", strings.Repeat("x", 43))
			case "revoked session":
				auth.SessionVersion = -1
			}
			if err := s.db.Create(context.Background(), &auth, nil).Error; err != nil {
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
			}
			var response map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response["error"] != wantError {
				t.Fatalf("expected %s: %s", wantError, w.Body.String())
			}
			if countAuthRequests(t, s) != 0 || countOauthTokens(t, s) != 0 {
				t.Fatal("rejected exchange must consume the grant without issuing a token")
			}
		})
	}
}

func TestOauthCodeExchangeSingleUse(t *testing.T) {
	for _, name := range []string{"bound", "bound at exchange", "issuance failure", "scope failure"} {
		t.Run(name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			auth, form := authorizationCodeFixture(t, s, account)
			wantJkt := *auth.Parameters.DpopJkt
			auth.Parameters.Scope = "atproto include:com.example.permissions"
			wantScope := auth.Parameters.Scope + " repo:com.example.record?action=create"
			s.scopeResolver = codeExchangeResolver(func(context.Context) {})
			if name == "bound at exchange" {
				auth.Parameters.DpopJkt = nil
			}
			if name == "scope failure" {
				auth.Parameters.Scope = "atproto space:com.example.space"
				s.spaceTypes = declaredSpaceTypes{}
			}
			if err := s.db.Create(ctx, &auth, nil).Error; err != nil {
				t.Fatal(err)
			}
			if name == "issuance failure" || name == "scope failure" {
				wantStatus := 400
				if name == "issuance failure" {
					wantStatus = 500
					if err := s.db.Exec(ctx, "CREATE TRIGGER fail_token BEFORE INSERT ON oauth_tokens BEGIN SELECT RAISE(ABORT, 'test failure'); END", nil).Error; err != nil {
						t.Fatal(err)
					}
				}
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
				if w.Code != wantStatus || countAuthRequests(t, s) != 0 || countOauthTokens(t, s) != 0 {
					t.Fatalf("failed issuance must consume grant without tokens: %d %s", w.Code, w.Body.String())
				}
				if err := s.db.Exec(ctx, "DROP TRIGGER IF EXISTS fail_token", nil).Error; err != nil {
					t.Fatal(err)
				}
				s.spaceTypes = declaredSpaceTypes{"com.example.space": {"com.example.record"}}
				w = httptest.NewRecorder()
				s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
				assertInvalidGrant(t, w)
				return
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
			var response OauthTokenResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || countAuthRequests(t, s) != 0 || countOauthTokens(t, s) != 1 {
				t.Fatalf("wanted one consumed grant and token: %d %s", w.Code, w.Body.String())
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
			if !ok || cnf["jkt"] != wantJkt {
				t.Fatal("JWT DPoP confirmation differs from the issued grant")
			}
			if _, present := claims["scope"]; present {
				t.Fatal("JWT duplicates database-backed scopes")
			}
			refreshForm := url.Values{"client_id": {auth.ClientId}, "grant_type": {"refresh_token"}, "refresh_token": {response.RefreshToken}}
			if name == "bound at exchange" {
				w = httptest.NewRecorder()
				s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, refreshForm))
				if w.Code != 200 {
					t.Fatalf("refresh before code replay: %d %s", w.Code, w.Body.String())
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				refreshForm.Set("refresh_token", response.RefreshToken)
			}
			seedRefreshToken(t, s, account.Did, "unrelated-session")
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
			assertInvalidGrant(t, w)
			if countOauthTokens(t, s) != 1 {
				t.Fatal("replay must revoke only the session issued from this code")
			}
			if err := s.db.First(ctx, &provider.OauthToken{}, "refresh_token = ?", "unrelated-session").Error; err != nil {
				t.Fatalf("replay revoked unrelated session: %v", err)
			}
			r := httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
			r.Header.Set("Authorization", "DPoP "+response.AccessToken)
			r.Header.Set("DPoP", newTestDpopProofWithKey(t, s, r.Method, "https://"+testHostname+r.URL.String(), &response.AccessToken, s.privateKey))
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("replayed session still permits access: %d %s", w.Code, w.Body.String())
			}
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, refreshForm))
			assertInvalidGrant(t, w)
		})
	}
}

func TestOauthTokenDatabaseScopes(t *testing.T) {
	s, account := endpointTestServer(t)
	s.evtman = s.newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	auth, form := authorizationCodeFixture(t, s, account)
	auth.Parameters.Scope = "atproto include:com.example.permissions"
	wantScope := auth.Parameters.Scope + " repo:com.example.record?action=create"
	s.scopeResolver = codeExchangeResolver(func(context.Context) {})
	if err := s.db.Create(t.Context(), &auth, nil).Error; err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", grant, w.Code, w.Body.String())
		}
		var response OauthTokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Scope != wantScope {
			t.Fatalf("%s response lost granted scopes: %q", grant, response.Scope)
		}
		var stored provider.OauthToken
		if err := s.db.First(t.Context(), &stored, "token = ?", response.AccessToken).Error; err != nil {
			t.Fatal(err)
		}
		if stored.Parameters.Scope != wantScope {
			t.Fatalf("%s stored grant lost expanded scopes: %q", grant, stored.Parameters.Scope)
		}
		parsed, err := jwt.Parse(response.AccessToken, func(*jwt.Token) (any, error) {
			return s.privateKey.Public(), nil
		}, jwt.WithValidMethods([]string{"ES256"}))
		if err != nil {
			t.Fatal(err)
		}
		if _, present := parsed.Claims.(jwt.MapClaims)["scope"]; present {
			t.Fatalf("%s JWT duplicates database-backed scopes", grant)
		}
		for _, operation := range []struct {
			endpoint string
			status   int
		}{{"createRecord", 200}, {"deleteRecord", 403}} {
			r := repoSwapRequest(t, account.Did, response.AccessToken, operation.endpoint, map[string]any{
				"collection": "com.example.record", "rkey": grant,
				"record": map[string]any{"$type": "com.example.record", "text": "scope test"},
			})
			r.Header.Set("Authorization", "DPoP "+response.AccessToken)
			r.Header.Set("DPoP", newTestDpopProofWithKey(t, s, r.Method, "https://"+testHostname+r.URL.String(), &response.AccessToken, s.privateKey))
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != operation.status {
				t.Fatalf("%s %s: %d %s", grant, operation.endpoint, w.Code, w.Body.String())
			}
			if operation.status == 403 {
				assertInsufficientScope(t, w.Code, w.Body.Bytes())
			}
		}
		w = httptest.NewRecorder()
		s.echo.ServeHTTP(w, httptest.NewRequest("GET", "/xrpc/com.atproto.repo.getRecord?repo="+account.Did+"&collection=com.example.record&rkey="+grant, nil))
		var record ComAtprotoRepoGetRecordResponse
		if err := json.Unmarshal(w.Body.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || record.Value["text"] != "scope test" {
			t.Fatalf("%s must create the record and deny its deletion: %d %s", grant, w.Code, w.Body.String())
		}
		form = url.Values{"client_id": {auth.ClientId}, "grant_type": {"refresh_token"}, "refresh_token": {response.RefreshToken}}
	}
}

func TestOauthCodeExchangeRechecksAfterScopeResolution(t *testing.T) {
	for _, name := range []string{"revocation", "account deletion"} {
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
				case "revocation":
					err = s.db.ResetPassword(ctx, account.Did, "unused-test-password-hash", nil)
				case "account deletion":
					err = s.db.Exec(ctx, "DELETE FROM repos WHERE did = ?", nil, account.Did).Error
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

func TestOauthCodeExchangeConcurrentConsumption(t *testing.T) {
	s, account := endpointTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sqlDB, err := s.db.Client().DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	auth, form := authorizationCodeFixture(t, s, account)
	auth.Parameters.Scope = "atproto include:com.example.permissions"
	if err := s.db.Create(ctx, &auth, nil).Error; err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var resolutions atomic.Int32
	s.scopeResolver = codeExchangeResolver(func(ctx context.Context) {
		if resolutions.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	winner := make(chan *httptest.ResponseRecorder, 1)
	r := authorizationCodeRequest(t, s, form).WithContext(ctx)
	go func() {
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		winner <- w
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first exchange never reached scope resolution")
	}
	losers := make(chan *httptest.ResponseRecorder, 7)
	for range 7 {
		r := authorizationCodeRequest(t, s, form).WithContext(ctx)
		go func() {
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			losers <- w
		}()
	}
	for range 7 {
		assertInvalidGrant(t, <-losers)
	}
	close(release)
	w := <-winner
	if w.Code != 200 || resolutions.Load() != 1 || countAuthRequests(t, s) != 0 {
		t.Fatalf("only the code consumer may issue tokens: %d %s; resolutions=%d", w.Code, w.Body.String(), resolutions.Load())
	}
	// Like the reference, replay revokes a session once it has been issued.
	w = httptest.NewRecorder()
	s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
	assertInvalidGrant(t, w)
	if countOauthTokens(t, s) != 0 {
		t.Fatal("code replay did not revoke the issued session")
	}
}

func TestOauthCodeExchangeProtocolFailurePreservesGrant(t *testing.T) {
	for _, name := range []string{"invalid proof", "invalid client", "unsupported grant"} {
		t.Run(name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			auth, form := authorizationCodeFixture(t, s, account)
			if err := s.db.Create(context.Background(), &auth, nil).Error; err != nil {
				t.Fatal(err)
			}
			badForm, _ := url.ParseQuery(form.Encode())
			if name == "invalid client" {
				badForm.Set("client_id", "not-a-url")
			} else if name == "unsupported grant" {
				badForm.Set("grant_type", "unsupported")
			}
			r := authorizationCodeRequest(t, s, badForm)
			if name == "invalid proof" {
				r.Header.Set("DPoP", "not-a-proof")
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != 400 || countAuthRequests(t, s) != 1 {
				t.Fatalf("protocol failure consumed grant: %d %s", w.Code, w.Body.String())
			}
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
			if w.Code != 200 {
				t.Fatalf("corrected exchange: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
