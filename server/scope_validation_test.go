package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/haileyok/cocoon/oauth/scopes"
)

// stubResolver is a hermetic PermissionSetResolver: only NSIDs in valid resolve.
type stubResolver struct {
	valid map[string]bool
}

func (r stubResolver) ResolvePermissionSet(ctx context.Context, nsid string) (*lexicon.SchemaPermissionSet, error) {
	if r.valid[nsid] {
		return &lexicon.SchemaPermissionSet{}, nil
	}
	return nil, fmt.Errorf("permission set %q not found", nsid)
}

type expandedScopeResolver struct {
	scopes []string
}

func (r expandedScopeResolver) ResolvePermissionSet(ctx context.Context, nsid string) (*lexicon.SchemaPermissionSet, error) {
	return &lexicon.SchemaPermissionSet{}, nil
}

func (r expandedScopeResolver) ResolvePermissionSetScopes(ctx context.Context, nsid string) ([]string, error) {
	return append([]string(nil), r.scopes...), nil
}

func parScopeForm(scope string) string {
	form := url.Values{
		"client_id":             {"http://localhost"},
		"response_type":         {"code"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"state-1"},
		"redirect_uri":          {"http://127.0.0.1/"},
		"scope":                 {scope},
	}
	return form.Encode()
}

func postPar(t *testing.T, s *Server, scope string) (int, map[string]string) {
	t.Helper()
	proof := newTestDpopProof(t, s, http.MethodPost, "https://"+testHostname+"/oauth/par", nil)
	c, rec := newRequestContext(http.MethodPost, "/oauth/par", parScopeForm(scope), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         proof,
	})
	if err := s.handleOauthPar(c); err != nil {
		c.Error(err)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestParRejectsMalformedScope(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = stubResolver{valid: map[string]bool{}}

	code, body := postPar(t, s, "atproto repo:not a nsid")
	if code != 400 {
		t.Fatalf("expected 400 for malformed scope, got %d (%v)", code, body)
	}
	if body["error"] != "invalid_scope" {
		t.Fatalf("expected error invalid_scope, got %q", body["error"])
	}
}

func TestParRejectsUnresolvableInclude(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = stubResolver{valid: map[string]bool{"site.standard.authFull": true}}

	code, body := postPar(t, s, "atproto include:earth.cirrus.check.invalidnonexistentpermissionset")
	if code != 400 {
		t.Fatalf("expected 400 for unresolvable include, got %d (%v)", code, body)
	}
	if body["error"] != "invalid_scope" {
		t.Fatalf("expected error invalid_scope, got %q", body["error"])
	}
}

func TestParAcceptsResolvableInclude(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = stubResolver{valid: map[string]bool{"site.standard.authFull": true}}

	code, body := postPar(t, s, "atproto include:site.standard.authFull")
	if code != 201 {
		t.Fatalf("expected 201 for resolvable include, got %d (%v)", code, body)
	}
}

func TestParAcceptsLegacyScopes(t *testing.T) {
	s := newTestServer(t)
	attachOauthProvider(t, s)
	// No resolver needed; legacy scopes contain no include.
	s.scopeResolver = stubResolver{valid: map[string]bool{}}

	code, body := postPar(t, s, "atproto transition:generic")
	if code != 201 {
		t.Fatalf("expected 201 for legacy scopes, got %d (%v)", code, body)
	}
}

func TestExpandScopesIncludesSpacePermissionSetEntries(t *testing.T) {
	s := newTestServer(t)
	s.scopeResolver = expandedScopeResolver{scopes: []string{
		"space:my.bulletin.board?authority=*&skey=self&collection=my.bulletin.post&collection=my.bulletin.removal&collection=my.bulletin.position&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete",
	}}

	got := s.expandScopes(context.Background(), "atproto include:my.bulletin.permissions")
	if !strings.Contains(got, "space:my.bulletin.board") {
		t.Fatalf("expanded scopes = %q, missing space permission", got)
	}
	parsed, err := scopes.ParseList(got)
	if err != nil {
		t.Fatalf("parse expanded scopes: %v", err)
	}
	for _, grant := range parsed {
		if grant.Resource == scopes.ResourceSpace && grant.SpaceType == "my.bulletin.board" {
			return
		}
	}
	t.Fatalf("expanded scopes = %q, no parsed space permission", got)
}
