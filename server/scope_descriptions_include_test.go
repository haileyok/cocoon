package server

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/oauth/scopes"
)

// An app that asks for include:<set> should have the set's permissions shown
// on the consent page, not just "a bundle of permissions".
func TestConsentScopesDescribeIncludedPermissions(t *testing.T) {
	s := newTestServer(t)
	s.scopeResolver = fakeSpaceSets{"my.bulletin.permissions": {
		scopes.ParseSpacePermission("space:my.bulletin.board?authority=*&skey=self&collection=my.bulletin.post&manage=create"),
	}}
	raw, perms := s.consentScopes(context.Background(), "atproto include:my.bulletin.permissions", "did:plc:alice")

	if !slices.Contains(raw, "include:my.bulletin.permissions") {
		t.Fatalf("requested scopes lost the include: %v", raw)
	}
	if !slices.ContainsFunc(raw, func(r string) bool { return strings.HasPrefix(r, "space:my.bulletin.board?") }) {
		t.Fatalf("requested scopes don't list what the set grants: %v", raw)
	}
	var titles []string
	for _, p := range perms {
		titles = append(titles, p.Title)
		if strings.HasPrefix(p.Title, "Permissions defined by") && !strings.Contains(p.Title+p.Detail, "my.bulletin.permissions") {
			t.Fatalf("permission set entry doesn't name the set: %+v", p)
		}
	}
	for _, want := range []string{"Your private spaces", "Manage your private spaces"} {
		if !slices.Contains(titles, want) {
			t.Fatalf("consent page is missing %q: %v", want, titles)
		}
	}
}

// When a set can't be resolved, the page still says it was requested.
func TestConsentScopesUnresolvedInclude(t *testing.T) {
	s := newTestServer(t)
	s.scopeResolver = fakeSpaceSets{}
	_, perms := s.consentScopes(context.Background(), "atproto include:com.example.missing", "did:plc:alice")
	found := false
	for _, p := range perms {
		if strings.Contains(p.Title+p.Detail, "com.example.missing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unresolved permission set not shown: %+v", perms)
	}
}
