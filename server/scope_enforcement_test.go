package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

func ctxWithScopes(scopes any) echo.Context {
	c, _ := newRequestContext(http.MethodPost, "/", "", nil)
	if scopes != nil {
		c.Set("scopes", scopes)
		c.Set("credentialKind", credentialOAuth)
	} else {
		c.Set("credentialKind", credentialLegacyAccess)
	}
	return c
}

func TestHasRPCScopeStateAndAudience(t *testing.T) {
	var s Server
	const method = "app.bsky.feed.getTimeline"
	for _, tc := range []struct {
		name, scheme, aud string
		scopes            any
		want              bool
	}{
		{"missing OAuth state", "DPoP", testDid, nil, false},
		{"malformed OAuth state", "DPoP", testDid, "transition:generic", false},
		{"empty OAuth state", "DPoP", testDid, []string{}, false},
		{"legacy bearer", "bearer", testDid, nil, true},
		{"invalid double wildcard", "DPoP", testDid, []string{"rpc:*?aud=*"}, false},
		{"matching service fragment", "DPoP", "did:web:appview.test#view", []string{"rpc:" + method + "?aud=did:web:appview.test%23view"}, true},
		{"different service fragment", "DPoP", "did:web:appview.test#other", []string{"rpc:" + method + "?aud=did:web:appview.test%23view"}, false},
		{"fragment must not be discarded", "DPoP", "did:web:appview.test", []string{"rpc:" + method + "?aud=did:web:appview.test%23view"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ctxWithScopes(tc.scopes)
			c.Request().Header.Set("Authorization", tc.scheme+" token")
			if tc.scheme == "DPoP" {
				c.Set("credentialKind", credentialOAuth)
			}
			if got := s.hasRPCScope(c, tc.aud, method); got != tc.want {
				t.Fatalf("hasRPCScope = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHasRepoScope(t *testing.T) {
	s := newTestServer(t)

	tests := []struct {
		name       string
		scopes     any // nil means "no scopes key"
		collection string
		action     string
		want       bool
	}{
		{"no scopes key (password session)", nil, "earth.cirrus.check.testrecord", "create", true},
		{"transition:generic grants all", []string{"atproto", "transition:generic"}, "anything.at.all", "delete", true},
		{"granular allows matching collection", []string{"atproto", "repo:earth.cirrus.check.testrecord"}, "earth.cirrus.check.testrecord", "create", true},
		{"granular denies other collection", []string{"atproto", "repo:earth.cirrus.check.testrecord"}, "earth.cirrus.check.othertestrecord", "create", false},
		{"granular wildcard collection", []string{"repo:*"}, "earth.cirrus.check.testrecord", "update", true},
		{"granular action restriction", []string{"repo:earth.cirrus.check.testrecord?action=create"}, "earth.cirrus.check.testrecord", "delete", false},
		{"atproto alone does not grant write", []string{"atproto"}, "earth.cirrus.check.testrecord", "create", false},
		{"empty scopes slice denies", []string{}, "earth.cirrus.check.testrecord", "create", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ctxWithScopes(tt.scopes)
			if got := s.hasRepoScope(c, tt.collection, tt.action); got != tt.want {
				t.Fatalf("hasRepoScope(%q,%q) = %v, want %v", tt.collection, tt.action, got, tt.want)
			}
		})
	}
}

func repoActorFor(t *testing.T, s *Server, handle string) *models.RepoActor {
	t.Helper()
	acct := s.createTestAccount(t, handle)
	ra, err := s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	return ra
}

func assertInsufficientScope(t *testing.T, code int, body []byte) {
	t.Helper()
	if code != 403 {
		t.Fatalf("expected 403 insufficient_scope, got %d (body %s)", code, string(body))
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if m["error"] != "insufficient_scope" {
		t.Fatalf("expected error insufficient_scope, got %q", m["error"])
	}
}

func TestCreateRecordInsufficientScope(t *testing.T) {
	s := newTestServer(t)
	ra := repoActorFor(t, s, "alice.pds.test")

	body := `{"repo":"` + ra.Repo.Did + `","collection":"earth.cirrus.check.othertestrecord","record":{"foo":"bar"}}`
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", body, nil)
	c.Set("repo", ra)
	c.Set("credentialKind", credentialOAuth)
	c.Set("scopes", []string{"atproto", "repo:earth.cirrus.check.testrecord"})

	if err := s.handleCreateRecord(c); err != nil {
		c.Error(err)
	}
	assertInsufficientScope(t, rec.Code, rec.Body.Bytes())
}

func TestPutRecordInsufficientScope(t *testing.T) {
	s := newTestServer(t)
	ra := repoActorFor(t, s, "alice.pds.test")

	body := `{"repo":"` + ra.Repo.Did + `","collection":"earth.cirrus.check.othertestrecord","rkey":"self","record":{"foo":"bar"}}`
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.putRecord", body, nil)
	c.Set("repo", ra)
	c.Set("credentialKind", credentialOAuth)
	c.Set("scopes", []string{"atproto", "repo:earth.cirrus.check.testrecord"})

	if err := s.handlePutRecord(c); err != nil {
		c.Error(err)
	}
	assertInsufficientScope(t, rec.Code, rec.Body.Bytes())
}

func TestDeleteRecordInsufficientScope(t *testing.T) {
	s := newTestServer(t)
	ra := repoActorFor(t, s, "alice.pds.test")

	body := `{"repo":"` + ra.Repo.Did + `","collection":"earth.cirrus.check.othertestrecord","rkey":"self"}`
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.deleteRecord", body, nil)
	c.Set("repo", ra)
	c.Set("credentialKind", credentialOAuth)
	c.Set("scopes", []string{"atproto", "repo:earth.cirrus.check.testrecord"})

	if err := s.handleDeleteRecord(c); err != nil {
		c.Error(err)
	}
	assertInsufficientScope(t, rec.Code, rec.Body.Bytes())
}

func TestApplyWritesInsufficientScope(t *testing.T) {
	s := newTestServer(t)
	ra := repoActorFor(t, s, "alice.pds.test")

	body := `{"repo":"` + ra.Repo.Did + `","writes":[{"$type":"com.atproto.repo.applyWrites#create","collection":"earth.cirrus.check.othertestrecord","rkey":"self","value":{"foo":"bar"}}]}`
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.applyWrites", body, nil)
	c.Set("repo", ra)
	c.Set("credentialKind", credentialOAuth)
	c.Set("scopes", []string{"atproto", "repo:earth.cirrus.check.testrecord"})

	if err := s.handleApplyWrites(c); err != nil {
		c.Error(err)
	}
	assertInsufficientScope(t, rec.Code, rec.Body.Bytes())
}

func TestRepoWriteActualAction(t *testing.T) {
	for _, endpoint := range []string{"createRecord", "putRecord", "applyWrites"} {
		for _, tc := range []struct {
			name, action, key string
			swap, allowed     bool
		}{
			{"create new", "create", "new", false, true},
			{"create cannot replace", "create", "existing", false, false},
			{"update existing", "update", "existing", false, true},
			{"update cannot create", "update", "new", false, false},
			{"update hint cannot create", "update", "new", true, false},
			{"update hint existing", "update", "existing", true, true},
		} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				s, account := endpointTestServer(t)
				s.repoman = NewRepoMan(s)
				_, record := blobRecord(t, "original media")
				root, blocks, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/existing"}, record)
				if code, msg := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, blocks))); code != 200 {
					t.Fatalf("import: %d %s", code, msg)
				}
				uploadTestBlob(t, s, account, "original media")
				s.evtman = newTestEvtman(t)
				before := importState(t, s, account.Did)
				body := map[string]any{"repo": account.Did, "collection": "app.bsky.feed.post", "rkey": tc.key, "record": postRecord("replacement")}
				if tc.swap {
					body["swapRecord"] = walkMstLeaves(t, s, account.Did)["app.bsky.feed.post/existing"].String()
				}
				if endpoint == "applyWrites" {
					op := OpTypeCreate
					if tc.swap {
						op = OpTypeUpdate
					}
					body = map[string]any{"repo": account.Did, "writes": []any{map[string]any{
						"$type": op, "collection": "app.bsky.feed.post", "rkey": tc.key, "value": postRecord("replacement"),
					}}}
				}
				payload, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("POST", "/xrpc/com.atproto.repo."+endpoint, bytes.NewReader(payload))
				r.Header.Set("Content-Type", "application/json")
				setProxyTestOAuth(t, s, r, account.Did, "atproto repo:app.bsky.feed.post?action="+tc.action)
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, r)
				if !tc.allowed {
					assertInsufficientScope(t, w.Code, w.Body.Bytes())
					if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
						t.Fatal("denied write changed repository or blob state")
					}
					return
				}
				if w.Code != 200 {
					t.Fatalf("write: %d %s", w.Code, w.Body.String())
				}
				w = httptest.NewRecorder()
				s.echo.ServeHTTP(w, httptest.NewRequest("GET", "/xrpc/com.atproto.repo.getRecord?repo="+account.Did+"&collection=app.bsky.feed.post&rkey="+tc.key, nil))
				var got ComAtprotoRepoGetRecordResponse
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || got.Value["text"] != "replacement" {
					t.Fatalf("read after write: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestRepoWriteBatchAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, scope string
		first       OpType
		firstKey    string
		secondKey   string
		allowed     bool
	}{
		{"late overwrite", "repo:app.bsky.feed.post?action=create", OpTypeCreate, "new", "existing", false},
		{"same key twice", "repo:app.bsky.feed.post?action=create", OpTypeCreate, "new", "new", false},
		{"delete then recreate denied", "repo:app.bsky.feed.post?action=delete&action=update", OpTypeDelete, "existing", "existing", false},
		{"delete then recreate allowed", "repo:app.bsky.feed.post?action=delete&action=create", OpTypeDelete, "existing", "existing", true},
		{"create and update allowed", "repo:app.bsky.feed.post?action=create&action=update", OpTypeCreate, "new", "new", true},
		{"generic", "transition:generic", OpTypeCreate, "new", "existing", true},
		{"legacy", "", OpTypeCreate, "new", "existing", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			s.repoman = NewRepoMan(s)
			s.evtman = newTestEvtman(t)
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			mustApply(t, s, account.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("existing"), Record: rmPostRecord("original")})
			events, persister := newTestEvtmanPersister(t)
			s.evtman = events
			before := importState(t, s, account.Did)
			body := ComAtprotoRepoApplyWritesInput{Repo: account.Did, Writes: []ComAtprotoRepoApplyWritesItem{
				{Type: tc.first.String(), Collection: "app.bsky.feed.post", Rkey: tc.firstKey, Value: rmPostRecord("first")},
				{Type: OpTypeCreate.String(), Collection: "app.bsky.feed.post", Rkey: tc.secondKey, Value: rmPostRecord("second")},
			}}
			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/xrpc/com.atproto.repo.applyWrites", bytes.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			if tc.scope == "" {
				session, err := s.createSession(context.Background(), &mustRepoActor(t, s, account.Did).Repo)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			} else {
				setProxyTestOAuth(t, s, r, account.Did, "atproto "+tc.scope)
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if !tc.allowed {
				assertInsufficientScope(t, w.Code, w.Body.Bytes())
				if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
					t.Fatal("denied batch changed repository state")
				}
				if _, _, ok, err := persister.EventSeqRange(context.Background()); err != nil || ok {
					t.Fatalf("denied batch published an event: %v", err)
				}
				return
			}
			if w.Code != 200 {
				t.Fatalf("batch: %d %s", w.Code, w.Body.String())
			}
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, httptest.NewRequest("GET", "/xrpc/com.atproto.repo.getRecord?repo="+account.Did+"&collection=app.bsky.feed.post&rkey="+tc.secondKey, nil))
			var got ComAtprotoRepoGetRecordResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || got.Value["text"] != "second" {
				t.Fatalf("read after batch: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
