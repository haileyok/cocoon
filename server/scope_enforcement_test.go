package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func ctxWithScopes(scopes any) echo.Context {
	c, _ := newRequestContext(http.MethodPost, "/", "", nil)
	if scopes != nil {
		c.Set("scopes", scopes)
	}
	return c
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
	c.Set("scopes", []string{"atproto", "repo:earth.cirrus.check.testrecord"})

	if err := s.handleApplyWrites(c); err != nil {
		c.Error(err)
	}
	assertInsufficientScope(t, rec.Code, rec.Body.Bytes())
}
