package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type unreadEndpointBody struct{ reads int }

func (b *unreadEndpointBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *unreadEndpointBody) Close() error             { return nil }

func endpointTestServer(t *testing.T) (*Server, *testAccount) {
	t.Helper()
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.config.FallbackProxy = "did:web:appview.test#view"
	s.echo = echo.New()
	s.echo.Validator = newTestValidator()
	s.addRoutes()
	return s, s.createTestAccount(t, "endpoint.pds.test")
}

func TestEndpointAuthorizationDenied(t *testing.T) {
	for _, tc := range []struct{ method, nsid, scope string }{
		{"POST", "com.atproto.identity.updateHandle", "atproto"},
		{"POST", "com.atproto.identity.updateHandle", "transition:generic"},
		{"POST", "com.atproto.identity.requestPlcOperationSignature", "identity:handle"},
		{"POST", "com.atproto.identity.signPlcOperation", "identity:handle"},
		{"POST", "com.atproto.identity.submitPlcOperation", "transition:generic"},
		{"POST", "com.atproto.repo.importRepo", "account:repo"},
		{"POST", "com.atproto.repo.importRepo", "transition:generic"},
		{"POST", "com.atproto.repo.uploadBlob", "blob:video/*"},
		{"POST", "com.atproto.server.confirmEmail", "account:email"},
		{"POST", "com.atproto.server.requestEmailConfirmation", "transition:email"},
		{"POST", "com.atproto.server.requestEmailUpdate", "account:email?action=manage"},
		{"POST", "com.atproto.server.updateEmail", "transition:generic account:email?action=manage"},
		{"POST", "com.atproto.server.requestAccountDelete", "account:repo?action=manage"},
		{"POST", "com.atproto.server.activateAccount", "transition:generic"},
		{"POST", "com.atproto.server.deactivateAccount", "account:repo?action=manage"},
		{"GET", "app.bsky.actor.getPreferences", "atproto"},
		{"POST", "app.bsky.actor.putPreferences", "rpc:app.bsky.actor.getPreferences?aud=did:web:appview.test%23view"},
	} {
		t.Run(tc.nsid+"/"+tc.scope, func(t *testing.T) {
			s, account := endpointTestServer(t)
			before, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			body := &unreadEndpointBody{}
			r := httptest.NewRequest(tc.method, "/xrpc/"+tc.nsid, nil)
			r.Body = body
			r.Header.Set("Content-Type", "image/png")
			setProxyTestOAuth(t, s, r, account.Did, tc.scope)
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", w.Code)
			}
			if body.reads != 0 {
				t.Fatal("denied request body was consumed")
			}
			after, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("denied request mutated the account")
			}
		})
	}
}

func TestEndpointAuthorizationAllowed(t *testing.T) {
	for _, tc := range []struct{ method, nsid, scope string }{
		{"POST", "com.atproto.identity.updateHandle", "identity:handle"},
		{"POST", "com.atproto.identity.requestPlcOperationSignature", "identity:*"},
		{"POST", "com.atproto.identity.signPlcOperation", "identity:*"},
		{"POST", "com.atproto.identity.submitPlcOperation", "identity:*"},
		{"POST", "com.atproto.repo.importRepo", "account:repo?action=manage"},
		{"POST", "com.atproto.repo.uploadBlob", "blob:image/*"},
		{"POST", "com.atproto.server.confirmEmail", "account:email?action=manage"},
		{"POST", "com.atproto.server.requestEmailConfirmation", "account:email?action=manage"},
		{"GET", "app.bsky.actor.getPreferences", "rpc:app.bsky.actor.getPreferences?aud=did:web:appview.test%23view"},
		{"POST", "app.bsky.actor.putPreferences", "transition:generic"},
		{"GET", "com.atproto.identity.getRecommendedDidCredentials", "atproto"},
		{"GET", "com.atproto.server.checkAccountStatus", "atproto"},
		{"GET", "com.atproto.repo.listMissingBlobs", "atproto"},
	} {
		t.Run(tc.nsid, func(t *testing.T) {
			s, account := endpointTestServer(t)
			// Keep production middleware; stub the handler to isolate authorization.
			path := "/xrpc/" + tc.nsid
			s.echo.Add(tc.method, path, func(c echo.Context) error { return c.NoContent(204) }, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
			r := httptest.NewRequest(tc.method, path, nil)
			r.Header.Set("Content-Type", "Image/PNG; charset=utf-8")
			setProxyTestOAuth(t, s, r, account.Did, tc.scope)
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != 204 {
				t.Fatalf("permission rejected: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSessionEmailPermission(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  bool
	}{
		{"atproto", false}, {"transition:generic", false}, {"transition:email", true},
		{"account:email", true}, {"account:email?action=manage", true}, {"account:repo?action=manage", false},
		{"legacy", true},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			s, account := endpointTestServer(t)
			r := httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
			if tc.scope == "legacy" {
				repo, err := s.getRepoActorByDid(context.Background(), account.Did)
				if err != nil {
					t.Fatal(err)
				}
				session, err := s.createSession(context.Background(), &repo.Repo)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			} else {
				setProxyTestOAuth(t, s, r, account.Did, tc.scope)
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("getSession: %d", w.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"email", "emailConfirmed", "emailAuthFactor"} {
				if _, ok := body[key]; ok != tc.want {
					t.Fatalf("%s presence = %v, want %v", key, ok, tc.want)
				}
			}
			if tc.want && (body["email"] != account.Email || body["emailConfirmed"] != false || body["emailAuthFactor"] != false) {
				t.Fatal("email fields changed, including false values")
			}
			if body["did"] != account.Did {
				t.Fatal("missing account identity")
			}
		})
	}
}

func TestEndpointLegacyAndServicePolicy(t *testing.T) {
	for _, nsid := range []string{
		"com.atproto.server.requestEmailUpdate", "com.atproto.server.updateEmail",
		"com.atproto.server.requestAccountDelete", "com.atproto.server.activateAccount", "com.atproto.server.deactivateAccount",
		"com.atproto.identity.updateHandle", "com.atproto.repo.importRepo", "com.atproto.repo.uploadBlob",
	} {
		t.Run(nsid, func(t *testing.T) {
			s, account := endpointTestServer(t)
			path := "/xrpc/" + nsid
			s.echo.POST(path, func(c echo.Context) error { return c.NoContent(204) }, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			session, err := s.createSession(context.Background(), &repo.Repo)
			if err != nil {
				t.Fatal(err)
			}
			service := mintServiceAuthToken(t, account.SigningKey, account.Did, testDid, nsid, time.Now().Add(time.Minute))
			for _, auth := range []string{session.AccessToken, service} {
				r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
				r.Header.Set("Authorization", "Bearer "+auth)
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, r)
				want := 204
				if auth == service && nsid != "com.atproto.repo.uploadBlob" {
					want = 403
				}
				if w.Code != want {
					t.Fatalf("status %d, want %d", w.Code, want)
				}
			}
		})
	}
}

func TestEndpointPreferencesAudience(t *testing.T) {
	for _, tc := range []struct {
		audience, header string
		want             int
	}{
		{"did:web:appview.test#view", "", 200},
		{"did:web:appview.test#view", "did:web:appview.test#view", 200},
		{"did:web:other.test#view", "", 403},
		{"did:web:other.test#view", "did:web:other.test#view", 403},
		{"did:web:appview.test#view", "did:web:other.test#view", 403},
	} {
		t.Run(tc.audience+"/"+tc.header, func(t *testing.T) {
			s, account := endpointTestServer(t)
			r := httptest.NewRequest("GET", "/xrpc/app.bsky.actor.getPreferences", nil)
			r.Header.Set("atproto-proxy", tc.header)
			setProxyTestOAuth(t, s, r, account.Did, "rpc:app.bsky.actor.getPreferences?aud="+tc.audience)
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestEndpointPreferenceWrite(t *testing.T) {
	s, account := endpointTestServer(t)
	body := `{"preferences":[{"$type":"app.bsky.actor.defs.adultContentPref","enabled":false}]}`
	r := httptest.NewRequest("POST", "/xrpc/app.bsky.actor.putPreferences", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	setProxyTestOAuth(t, s, r, account.Did, "rpc:app.bsky.actor.putPreferences?aud=did:web:appview.test%23view")
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("preference write: %d %s", w.Code, w.Body.String())
	}
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(repo.Preferences, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(body), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("preferences were not persisted intact")
	}
}

func TestEndpointEmailConfirmation(t *testing.T) {
	for _, code := range []string{"correct-code", "wrong-code"} {
		t.Run(code, func(t *testing.T) {
			s, account := endpointTestServer(t)
			if err := s.db.Exec(context.Background(), "UPDATE repos SET email_verification_code = ?, email_verification_code_expires_at = ? WHERE did = ?", nil, "correct-code", time.Now().Add(time.Hour), account.Did).Error; err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]string{"email": account.Email, "token": code})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/xrpc/com.atproto.server.confirmEmail", strings.NewReader(string(body)))
			r.Header.Set("Content-Type", "application/json")
			setProxyTestOAuth(t, s, r, account.Did, "account:email?action=manage")
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			wantStatus := 200
			if code != "correct-code" {
				wantStatus = 400
			}
			if w.Code != wantStatus {
				t.Fatalf("confirmation status = %d, want %d", w.Code, wantStatus)
			}
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			if (repo.EmailConfirmedAt != nil) != (code == "correct-code") {
				t.Fatal("unexpected confirmation state")
			}
			if (repo.EmailVerificationCode == nil) != (code == "correct-code") {
				t.Fatal("unexpected challenge consumption")
			}
		})
	}
}

func TestEndpointBlobUpload(t *testing.T) {
	s, account := endpointTestServer(t)
	s.repoman = NewRepoMan(s)
	const payload = "local blob test bytes"
	r := httptest.NewRequest("POST", "/xrpc/com.atproto.repo.uploadBlob", strings.NewReader(payload))
	r.Header.Set("Content-Type", "Text/Plain; charset=utf-8")
	setProxyTestOAuth(t, s, r, account.Did, "blob:text/*")
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("blob upload: %d %s", w.Code, w.Body.String())
	}
	var response ComAtprotoRepoUploadBlobResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Blob.Size != len(payload) || response.Blob.Ref.Link == "" {
		t.Fatal("invalid uploaded blob response")
	}
	var parts []models.BlobPart
	if err := s.db.Client().Find(&parts).Error; err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || string(parts[0].Data) != payload {
		t.Fatal("blob payload not stored intact")
	}
}

func TestEndpointScopeStateFailsClosed(t *testing.T) {
	var s Server
	for _, kind := range []any{nil, credentialOAuth, credentialLegacyRefresh} {
		for _, state := range []any{nil, "transition:generic", []string{"transition:generic"}} {
			c, _ := newRequestContext("POST", "/", "", map[string]string{"Authorization": "Bearer unverified"})
			c.Set("credentialKind", kind)
			c.Set("scopes", state)
			if s.hasEndpointScope(c, "account:repo?action=manage") {
				t.Fatal("invalid state granted account manage")
			}
			if kind != credentialOAuth || reflect.TypeOf(state) != reflect.TypeOf([]string{}) {
				if s.hasRepoScope(c, "app.bsky.feed.post", "create") || s.hasRPCScope(c, "did:web:appview.test#view", "app.bsky.feed.getTimeline") {
					t.Fatal("unverified or malformed state granted repo/RPC access")
				}
			}
		}
	}
}
