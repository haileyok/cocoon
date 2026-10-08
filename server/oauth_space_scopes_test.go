package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/haileyok/cocoon/oauth/scopes"
)

// fakeSpaceSets resolves include: permission sets that grant space access.
type fakeSpaceSets map[string][]*scopes.SpacePermission

func (f fakeSpaceSets) ResolvePermissionSet(_ context.Context, nsid string) (*lexicon.SchemaPermissionSet, error) {
	if _, ok := f[nsid]; !ok {
		return nil, errors.New("not found")
	}
	return &lexicon.SchemaPermissionSet{}, nil
}

func (f fakeSpaceSets) ResolveSpacePermissions(_ context.Context, nsid string) ([]*scopes.SpacePermission, error) {
	p, ok := f[nsid]
	if !ok {
		return nil, errors.New("not found")
	}
	return p, nil
}

func grants(scope string, m scopes.SpaceMatch) bool {
	for _, raw := range strings.Fields(scope) {
		if p := scopes.ParseSpacePermission(raw); p != nil && p.Matches(m) {
			return true
		}
	}
	return false
}

// An app like bulletin.my requests include:<set>, and decides whether the PDS
// supports spaces from the scope the token endpoint returns.
func TestExpandScopesIncludesSpacePermissions(t *testing.T) {
	s := newTestServer(t)
	s.scopeResolver = fakeSpaceSets{"my.bulletin.permissions": {
		scopes.ParseSpacePermission("space:my.bulletin.board?authority=*&skey=self&collection=my.bulletin.post&manage=create"),
	}}
	const did = "did:plc:alice"
	got := s.expandScopes(context.Background(), "atproto include:my.bulletin.permissions", did)
	board := scopes.SpaceMatch{Type: "my.bulletin.board", Authority: did, Skey: "self"}
	create := board
	create.Manage = "create"
	if !grants(got, create) {
		t.Fatalf("token scope %q does not let the user create their board", got)
	}
	// Re-expanding (as a refresh does) adds nothing new.
	if again := s.expandScopes(context.Background(), got, did); again != got {
		t.Fatalf("re-expansion changed the scope:\n%s\n%s", got, again)
	}
}

// A self authority resolves to the user at issuance, as the reference does.
func TestExpandScopesResolvesSelfAuthority(t *testing.T) {
	s := newTestServer(t)
	got := s.expandScopes(context.Background(), "atproto space:my.bulletin.board?skey=self&manage=create", "did:plc:alice")
	if !strings.Contains(got, "space:my.bulletin.board?authority=did:plc:alice&skey=self") {
		t.Fatalf("self not resolved: %q", got)
	}
}
