package server

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestGetServiceAuthPermissions(t *testing.T) {
	const method = "app.bsky.feed.getTimeline"
	for _, tc := range []struct {
		name, scope, aud, lxm string
		legacy                bool
		want                  int
	}{
		{"atproto only", "atproto", testDid, "com.atproto.repo.createRecord", false, 403},
		{"matching RPC", "atproto rpc:" + method + "?aud=did:web:appview.test", "did:web:appview.test", method, false, 200},
		{"wrong audience", "rpc:" + method + "?aud=did:web:other.test", "did:web:appview.test", method, false, 403},
		{"wrong method", "rpc:app.bsky.feed.getFeed?aud=did:web:appview.test", "did:web:appview.test", method, false, 403},
		{"methodless requires wildcard", "rpc:" + method + "?aud=did:web:appview.test", "did:web:appview.test", "", false, 403},
		{"wildcard method", "rpc:*?aud=did:web:appview.test", "did:web:appview.test", "", false, 200},
		{"wildcard audience", "rpc:" + method + "?aud=*", "did:web:appview.test", method, false, 200},
		{"generic", "atproto transition:generic", "did:web:appview.test", method, false, 200},
		{"generic excludes chat", "transition:generic", "did:web:chat.test", "chat.bsky.convo.getConvo", false, 403},
		{"chat", "transition:chat.bsky", "did:web:chat.test", "chat.bsky.convo.getConvo", false, 200},
		{"chat excludes other RPCs", "transition:chat.bsky", "did:web:appview.test", method, false, 403},
		{"email grants no RPC", "transition:email", "did:web:appview.test", method, false, 403},
		{"legacy unchanged", "", "did:web:appview.test", method, true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			attachOauthProvider(t, s)
			account := s.createTestAccount(t, "service.pds.test")
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			s.echo = echo.New()
			s.echo.Validator = newTestValidator()
			s.addRoutes()
			target := "/xrpc/com.atproto.server.getServiceAuth?" + url.Values{"aud": {tc.aud}, "lxm": {tc.lxm}}.Encode()
			r := httptest.NewRequest(http.MethodGet, target, nil)
			if tc.legacy {
				session, err := s.createSession(context.Background(), &repo.Repo)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			} else {
				// Seed an OAuth resource grant with a real, matching DPoP proof.
				access := "service-auth-test-access"
				proof := newTestDpopProof(t, s, http.MethodGet, "https://"+testHostname+target, &access)
				parsed, _, err := new(jwt.Parser).ParseUnverified(proof, jwt.MapClaims{})
				if err != nil {
					t.Fatal(err)
				}
				keyJSON, err := json.Marshal(parsed.Header["jwk"])
				if err != nil {
					t.Fatal(err)
				}
				key, err := jwk.ParseKey(keyJSON)
				if err != nil {
					t.Fatal(err)
				}
				thumb, err := key.Thumbprint(crypto.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				jkt := base64.RawURLEncoding.EncodeToString(thumb)
				grant := provider.OauthToken{
					Token: access, Sub: account.Did, ClientId: "http://localhost",
					RefreshToken: "service-auth-test-refresh", ExpiresAt: time.Now().Add(time.Hour),
					Parameters: provider.ParRequest{Scope: tc.scope, DpopJkt: &jkt},
				}
				if err := s.db.Create(context.Background(), &grant, nil).Error; err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "DPoP "+access)
				r.Header.Set("DPoP", proof)
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
			var response map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if tc.want == 403 {
				if response["error"] != "insufficient_scope" || response["token"] != "" {
					t.Fatal("expected insufficient_scope without a service token")
				}
				return
			}
			token, _, err := new(jwt.Parser).ParseUnverified(response["token"], jwt.MapClaims{})
			if err != nil {
				t.Fatal(err)
			}
			claims := token.Claims.(jwt.MapClaims)
			if claims["iss"] != account.Did || claims["aud"] != tc.aud {
				t.Fatal("service token changed subject or audience")
			}
			if tc.lxm == "" {
				if _, ok := claims["lxm"]; ok {
					t.Fatal("methodless token unexpectedly contains lxm")
				}
			} else if claims["lxm"] != tc.lxm {
				t.Fatal("service token changed method")
			}
		})
	}
}
