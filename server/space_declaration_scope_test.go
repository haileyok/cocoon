package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/oauth/scopes"
)

// declaredSpaceTypes resolves the space types it lists and fails for the rest,
// as the lexicon resolver does for a type that is unpublished or whose
// declaration fails validation.
type declaredSpaceTypes map[string][]string

func (d declaredSpaceTypes) ResolveSpaceCollections(_ context.Context, nsid string) ([]string, error) {
	if c, ok := d[nsid]; ok {
		return c, nil
	}
	return nil, errors.New("no valid declaration")
}

func newSpaceTypeServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = fakeSpaceSets{
		"my.bulletin.permissions": {scopes.ParseSpacePermission("space:my.bulletin.board?skey=self")},
		"my.bulletin.unknown":     {scopes.ParseSpacePermission("space:my.bulletin.missing")},
		"my.bulletin.anytype":     {scopes.ParseSpacePermission("space:*?authority=*")},
	}
	s.spaceTypes = declaredSpaceTypes{
		"my.bulletin.board": {"my.bulletin.post"},
	}
	return s
}

// The reference answers invalid_scope ("Unable to retrieve space
// declarations") when a requested space type has no usable declaration, rather
// than letting the sign-in proceed with a grant that can't write anything.
func TestParRejectsUnresolvableSpaceType(t *testing.T) {
	t.Parallel()
	s := newSpaceTypeServer(t)

	for name, scope := range map[string]string{
		"bare":                     "atproto space:my.bulletin.missing",
		"names collections":        "atproto space:my.bulletin.missing?collection=my.bulletin.post",
		"through a permission set": "atproto include:my.bulletin.unknown",
	} {
		code, body := postPar(t, s, scope)
		if code != 400 || body["error"] != "invalid_scope" {
			t.Errorf("%s: expected 400 invalid_scope, got %d (%v)", name, code, body)
			continue
		}
		if !strings.Contains(body["error_description"], "my.bulletin.missing") {
			t.Errorf("%s: description does not name the space type: %q", name, body["error_description"])
		}
	}
}

func TestParAcceptsResolvableSpaceType(t *testing.T) {
	t.Parallel()
	s := newSpaceTypeServer(t)

	for name, scope := range map[string]string{
		"direct":                   "atproto space:my.bulletin.board",
		"with parameters":          "atproto space:my.bulletin.board?authority=*&skey=self&manage=create",
		"through a permission set": "atproto include:my.bulletin.permissions",
		"wildcard type":            "atproto space:*?authority=*",
		"wildcard in a set":        "atproto include:my.bulletin.anytype",
	} {
		if code, body := postPar(t, s, scope); code != 201 {
			t.Errorf("%s: expected 201, got %d (%v)", name, code, body)
		}
	}
}

// With no space type resolver there is nothing to check against; include:
// resolution is skipped the same way.
func TestParSkipsSpaceTypesWithoutResolver(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	attachOauthProvider(t, s)
	s.scopeResolver = stubResolver{valid: map[string]bool{}}

	if code, body := postPar(t, s, "atproto space:my.bulletin.missing"); code != 201 {
		t.Fatalf("expected 201, got %d (%v)", code, body)
	}
}

// At issuance the reference refuses to mint a token whose bare space: grant
// has no declaration to draw its collections from.
func TestIssueScopeRefusesUnresolvableBareGrant(t *testing.T) {
	t.Parallel()
	s := newSpaceTypeServer(t)
	const did = "did:plc:alice"

	got, err := s.issueScope(context.Background(), "atproto space:my.bulletin.board", did)
	if err != nil {
		t.Fatalf("resolvable grant refused: %v", err)
	}
	if !strings.Contains(got, "collection=my.bulletin.post") {
		t.Fatalf("collections not materialized: %q", got)
	}

	if _, err := s.issueScope(context.Background(), "atproto space:my.bulletin.missing", did); err == nil {
		t.Fatal("token issued for a bare grant of an unresolvable space type")
	}
	if _, err := s.issueScope(context.Background(), "atproto include:my.bulletin.unknown", did); err == nil {
		t.Fatal("token issued for a permission set granting an unresolvable space type")
	}

	// A grant that names its collections doesn't need the declaration, and a
	// wildcard type has none to resolve.
	for _, scope := range []string{
		"atproto space:my.bulletin.missing?collection=my.bulletin.post",
		"atproto space:*?authority=*",
	} {
		if _, err := s.issueScope(context.Background(), scope, did); err != nil {
			t.Errorf("%q refused: %v", scope, err)
		}
	}

	// expandScopes is for display (the consent screen) and never fails.
	if got := s.expandScopes(context.Background(), "atproto space:my.bulletin.missing", did); !strings.Contains(got, "space:my.bulletin.missing") {
		t.Fatalf("display expansion dropped the grant: %q", got)
	}
}
