package scopes

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/haileyok/cocoon/space"
)

var _ SpaceValue = CanonicalSpaceValue{}
var _ SpaceValue = space.SpaceURI{}

func TestRawSpaceTypeResolverValidInvalidUnknownDeclarations(t *testing.T) {
	valid := `{"lexicon":1,"id":"com.example.forum","defs":{"main":{"type":"space","key":"any","name":"Forum","collections":["com.example.post","com.example.comment"]}}}`
	invalid := `{"lexicon":1,"id":"com.example.forum","defs":{"main":{"type":"record","key":"literal:self","record":{"type":"object","required":["collections"],"properties":{"collections":{"type":"array","items":{"type":"string","format":"nsid"}}}}}}}`
	resolver := NewRawSpaceTypeResolver(func(_ context.Context, nsid string) ([]byte, error) {
		switch nsid {
		case "com.example.forum":
			return []byte(valid), nil
		case "com.example.invalid":
			return []byte(invalid), nil
		default:
			return nil, errors.New("unknown declaration")
		}
	})
	declaration, err := resolver.ResolveSpaceType("com.example.forum")
	if err != nil || !reflect.DeepEqual(declaration.Collections, []string{"com.example.post", "com.example.comment"}) {
		t.Fatalf("valid declaration = %#v, err=%v", declaration, err)
	}
	if _, err := resolver.ResolveSpaceType("com.example.invalid"); err == nil {
		t.Fatal("invalid declaration resolved")
	}
	if _, err := resolver.ResolveSpaceType("com.example.unknown"); err == nil {
		t.Fatal("unknown declaration resolved")
	}
}

func TestParseValid(t *testing.T) {
	tests := []struct {
		raw  string
		want *Scope
	}{
		{"atproto", &Scope{Raw: "atproto", Resource: ResourceAtproto}},
		{"transition:generic", &Scope{Raw: "transition:generic", Resource: ResourceTransition, Transition: "generic"}},
		{"transition:email", &Scope{Raw: "transition:email", Resource: ResourceTransition, Transition: "email"}},
		{"transition:chat.bsky", &Scope{Raw: "transition:chat.bsky", Resource: ResourceTransition, Transition: "chat.bsky"}},
		{
			"repo:app.bsky.feed.post",
			&Scope{Raw: "repo:app.bsky.feed.post", Resource: ResourceRepo, Collections: []string{"app.bsky.feed.post"}, Actions: []string{"create", "update", "delete"}},
		},
		{
			"repo:app.bsky.feed.post?action=create",
			&Scope{Raw: "repo:app.bsky.feed.post?action=create", Resource: ResourceRepo, Collections: []string{"app.bsky.feed.post"}, Actions: []string{"create"}},
		},
		{
			"repo:*",
			&Scope{Raw: "repo:*", Resource: ResourceRepo, Collections: []string{"*"}, Actions: []string{"create", "update", "delete"}},
		},
		{
			"rpc:app.bsky.feed.getFeed?aud=did:web:api.bsky.app%23svc_appview",
			&Scope{Raw: "rpc:app.bsky.feed.getFeed?aud=did:web:api.bsky.app%23svc_appview", Resource: ResourceRPC, Lxm: []string{"app.bsky.feed.getFeed"}, Aud: "did:web:api.bsky.app#svc_appview"},
		},
		{
			"rpc:*?aud=did:web:api.bsky.app%23svc_appview",
			&Scope{Raw: "rpc:*?aud=did:web:api.bsky.app%23svc_appview", Resource: ResourceRPC, Lxm: []string{"*"}, Aud: "did:web:api.bsky.app#svc_appview"},
		},
		{
			"include:site.standard.authFull",
			&Scope{Raw: "include:site.standard.authFull", Resource: ResourceInclude, Nsid: "site.standard.authFull"},
		},
		{
			"include:site.standard.authFull?aud=did:web:api.bsky.app%23svc",
			&Scope{Raw: "include:site.standard.authFull?aud=did:web:api.bsky.app%23svc", Resource: ResourceInclude, Nsid: "site.standard.authFull", Aud: "did:web:api.bsky.app#svc"},
		},
		{
			"blob:image/*",
			&Scope{Raw: "blob:image/*", Resource: ResourceBlob, Accept: []string{"image/*"}},
		},
		{
			"account:email",
			&Scope{Raw: "account:email", Resource: ResourceAccount, Attr: "email", Action: "read"},
		},
		{
			"account:repo?action=manage",
			&Scope{Raw: "account:repo?action=manage", Resource: ResourceAccount, Attr: "repo", Action: "manage"},
		},
		{
			"identity:*",
			&Scope{Raw: "identity:*", Resource: ResourceIdentity, Attr: "*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.raw, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Parse(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	invalid := []string{
		"",
		"bogus",
		"transition:bogus",
		"transition:",
		"repo",
		"repo:not a nsid",
		"repo:app.bsky.feed.post?action=*",
		"repo:app.bsky.feed.post?action=bogus",
		"rpc:app.bsky.feed.getFeed", // missing aud
		"rpc:*?aud=*",
		"rpc:not a nsid?aud=did:web:x",
		"include:not_a_valid_nsid",
		"include:",
		"account:bogus",
		"account:email?action=manage",
		"identity:bogus",
	}

	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatalf("Parse(%q) expected error, got nil", raw)
			}
		})
	}
}

func TestParseListRejectsBadToken(t *testing.T) {
	if _, err := ParseList("atproto repo:app.bsky.feed.post include:not_a_valid_nsid"); err == nil {
		t.Fatal("expected ParseList to fail on an invalid token")
	}
	got, err := ParseList("atproto transition:generic repo:app.bsky.feed.post")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 parsed scopes, got %d", len(got))
	}
}

func TestAllowsRepoWrite(t *testing.T) {
	tests := []struct {
		scope      string
		collection string
		action     string
		want       bool
	}{
		{"repo:app.bsky.feed.post", "app.bsky.feed.post", "create", true},
		{"repo:app.bsky.feed.post", "app.bsky.feed.post", "delete", true},
		{"repo:app.bsky.feed.post?action=create", "app.bsky.feed.post", "delete", false},
		{"repo:app.bsky.feed.post", "app.bsky.feed.like", "create", false},
		{"repo:*", "anything.at.all", "update", true},
		{"rpc:app.bsky.feed.getFeed?aud=did:web:x", "app.bsky.feed.post", "create", false},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			sc, err := Parse(tt.scope)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := sc.AllowsRepoWrite(tt.collection, tt.action); got != tt.want {
				t.Fatalf("AllowsRepoWrite(%q,%q) = %v, want %v", tt.collection, tt.action, got, tt.want)
			}
		})
	}
}

func testCanonicalSpace(t *testing.T, authority, spaceType, skey string) space.SpaceURI {
	t.Helper()
	value, err := space.NewSpaceURI(authority, spaceType, skey)
	if err != nil {
		t.Fatalf("NewSpaceURI: %v", err)
	}
	return value
}

type testSpaceResolver struct {
	collections map[string][]string
	err         error
}

func (r testSpaceResolver) ResolveSpaceType(spaceType string) (SpaceTypeDeclaration, error) {
	if r.err != nil {
		return SpaceTypeDeclaration{}, r.err
	}
	return SpaceTypeDeclaration{Collections: r.collections[spaceType]}, nil
}

func TestSpaceScopeParsing(t *testing.T) {
	raw := "space:com.example.space?authority=did:plc:z72i7hdynmk6r22z27h6tvur&skey=alpha&collection=com.example.post&collection=com.example.reply&action=read_self&action=create&manage=update&manage=delete"
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", raw, err)
	}
	want := &Scope{
		Raw:         raw,
		Resource:    ResourceSpace,
		SpaceType:   "com.example.space",
		Authority:   "did:plc:z72i7hdynmk6r22z27h6tvur",
		SKey:        "alpha",
		Collections: []string{"com.example.post", "com.example.reply"},
		Actions:     []string{"read_self", "create"},
		Manage:      []string{"update", "delete"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse(%q) = %+v, want %+v", raw, got, want)
	}

	defaults, err := Parse("space:com.example.space")
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Authority != "self" || defaults.SKey != "*" || len(defaults.Collections) != 0 || !reflect.DeepEqual(defaults.Actions, []string{"read", "create", "update", "delete"}) {
		t.Fatalf("space defaults = %+v", defaults)
	}
}

func TestSpaceScopeRejectsUnknownAndDuplicateSingletons(t *testing.T) {
	invalid := []string{
		"space:com.example.space?unknown=x",
		"space:com.example.space?authority=self&authority=*",
		"space:com.example.space?skey=one&skey=two",
		"space:com.example.space?authority=not-a-did",
		"space:com.example.space?skey=not/a/key",
		"space:com.example.space?action=bogus",
		"space:com.example.space?manage=read",
		"space:com.example.space?collection=not-a-nsid",
		"space:not-a-nsid",
		"space:com.example.space?action=*",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded", raw)
			}
		})
	}
}

func TestSpaceScopeMatchingMatrix(t *testing.T) {
	const (
		grantor = "did:plc:z72i7hdynmk6r22z27h6tvur"
		other   = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
		typeID  = "com.example.space"
	)
	selfSpace := testCanonicalSpace(t, grantor, typeID, "alpha")
	otherSpace := testCanonicalSpace(t, other, typeID, "alpha")
	otherType := testCanonicalSpace(t, grantor, "com.example.other", "alpha")
	otherKey := testCanonicalSpace(t, grantor, typeID, "beta")

	tests := []struct {
		name           string
		scope          string
		value          space.SpaceURI
		repoDID        string
		wantMatch      bool
		wantRead       bool
		wantDelegation bool
	}{
		{"self defaults", "space:" + typeID, selfSpace, grantor, true, true, true},
		{"self rejects other authority", "space:" + typeID, otherSpace, grantor, false, false, false},
		{"authority wildcard", "space:" + typeID + "?authority=*", otherSpace, grantor, true, true, true},
		{"space type wildcard", "space:*?authority=*", otherType, grantor, true, true, true},
		{"skey exact", "space:" + typeID + "?skey=alpha", selfSpace, grantor, true, true, true},
		{"skey mismatch", "space:" + typeID + "?skey=alpha", otherKey, grantor, false, false, false},
		{"read_self own repo", "space:" + typeID + "?authority=*&action=read_self", selfSpace, grantor, true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := Parse(tt.scope)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := sc.MatchesSpace(tt.value, grantor); got != tt.wantMatch {
				t.Fatalf("MatchesSpace = %v, want %v", got, tt.wantMatch)
			}
			if got := sc.AllowsSpaceRead(tt.value, tt.repoDID, grantor); got != tt.wantRead {
				t.Fatalf("AllowsSpaceRead = %v, want %v", got, tt.wantRead)
			}
			if got := sc.AllowsSpaceDelegation(tt.value, grantor); got != tt.wantDelegation {
				t.Fatalf("AllowsSpaceDelegation = %v, want %v", got, tt.wantDelegation)
			}
		})
	}
}

func TestSpaceScopeReadSelfCannotDelegate(t *testing.T) {
	const (
		grantor = "did:plc:z72i7hdynmk6r22z27h6tvur"
		other   = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	)
	value := testCanonicalSpace(t, grantor, "com.example.space", "alpha")
	self, err := Parse("space:com.example.space?action=read_self")
	if err != nil {
		t.Fatal(err)
	}
	if !self.AllowsSpaceRead(value, grantor, grantor) {
		t.Fatal("read_self did not allow the granting user's repo")
	}
	if self.AllowsSpaceRead(value, other, grantor) {
		t.Fatal("read_self allowed another repo")
	}
	if self.AllowsSpaceDelegation(value, grantor) {
		t.Fatal("read_self allowed delegation")
	}

	read, err := Parse("space:com.example.space?action=read")
	if err != nil {
		t.Fatal(err)
	}
	if !read.AllowsSpaceRead(value, other, grantor) || !read.AllowsSpaceReadSelf(value, other, grantor) || !read.AllowsSpaceDelegation(value, grantor) {
		t.Fatal("read did not imply any-repo read_self and delegation")
	}
}

func TestSpaceWriteCollectionAndActionEnforcement(t *testing.T) {
	const grantor = "did:plc:z72i7hdynmk6r22z27h6tvur"
	value := testCanonicalSpace(t, grantor, "com.example.space", "alpha")
	resolver := testSpaceResolver{collections: map[string][]string{"com.example.space": {"com.example.post"}}}

	explicit, err := Parse("space:com.example.space?collection=com.example.post&action=create")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, collection, action string
		want                     bool
	}{
		{"allowed", "com.example.post", "create", true},
		{"wrong action", "com.example.post", "update", false},
		{"wrong collection", "com.example.reply", "create", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := explicit.AllowsSpaceWrite(value, tt.collection, tt.action, grantor, nil); got != tt.want {
				t.Fatalf("AllowsSpaceWrite = %v, want %v", got, tt.want)
			}
		})
	}

	wildcard, err := Parse("space:com.example.space?collection=*&action=update")
	if err != nil {
		t.Fatal(err)
	}
	if !wildcard.AllowsSpaceWrite(value, "com.example.reply", "update", grantor, nil) {
		t.Fatal("collection=* did not widen writes")
	}

	bare, err := Parse("space:com.example.space?action=create")
	if err != nil {
		t.Fatal(err)
	}
	if !bare.AllowsSpaceWrite(value, "com.example.post", "create", grantor, resolver) {
		t.Fatal("declaration collection did not permit a bare write")
	}
	request := SpaceRequest{Value: value, RepoDID: grantor, Collection: "com.example.post", Action: "create", GrantingDID: grantor}
	if !bare.AllowsSpaceRequest(request, resolver) {
		t.Fatal("typed space request was not authorized")
	}
}

func TestSpaceManageScopeEnforcement(t *testing.T) {
	const grantor = "did:plc:z72i7hdynmk6r22z27h6tvur"
	value := testCanonicalSpace(t, grantor, "com.example.space", "alpha")
	sc, err := Parse("space:com.example.space?manage=update&manage=delete")
	if err != nil {
		t.Fatal(err)
	}
	if !sc.AllowsSpaceManage(value, "update", grantor) || !sc.AllowsSpaceManage(value, "delete", grantor) {
		t.Fatal("allowed management action rejected")
	}
	if sc.AllowsSpaceManage(value, "create", grantor) {
		t.Fatal("unrequested management action allowed")
	}
	if sc.AllowsSpaceManage(value, "update", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("authority=self allowed a different granting DID")
	}
	if !sc.AllowsSpaceManage(value, "update", grantor) {
		t.Fatal("management unexpectedly depended on collection")
	}
}

func TestSpaceScopeUnknownDeclarationFailsClosed(t *testing.T) {
	const grantor = "did:plc:z72i7hdynmk6r22z27h6tvur"
	value := testCanonicalSpace(t, grantor, "com.example.space", "alpha")
	bare, err := Parse("space:com.example.space?action=create")
	if err != nil {
		t.Fatal(err)
	}
	if bare.AllowsSpaceWrite(value, "com.example.post", "create", grantor, nil) {
		t.Fatal("bare write succeeded without a declaration")
	}
	if bare.AllowsSpaceWrite(value, "com.example.post", "create", grantor, testSpaceResolver{err: errors.New("unknown declaration")}) {
		t.Fatal("bare write succeeded with an unknown declaration")
	}
	if bare.AllowsSpaceWrite(value, "com.example.post", "create", grantor, testSpaceResolver{collections: map[string][]string{"com.example.space": {"not-an-nsid"}}}) {
		t.Fatal("bare write succeeded with an invalid declaration")
	}
	wildcard, err := Parse("space:*?authority=*&action=create")
	if err != nil {
		t.Fatal(err)
	}
	if wildcard.AllowsSpaceWrite(value, "com.example.post", "create", grantor, testSpaceResolver{collections: map[string][]string{"com.example.space": {"com.example.post"}}}) {
		t.Fatal("spaceType=* received implicit declaration collections")
	}
	wildExplicit, err := Parse("space:*?authority=*&collection=*&action=create")
	if err != nil {
		t.Fatal(err)
	}
	if !wildExplicit.AllowsSpaceWrite(value, "com.example.post", "create", grantor, nil) {
		t.Fatal("explicit collection=* did not permit wildcard-space write")
	}
}

func TestExistingRepoScopesUnaffected(t *testing.T) {
	repo, err := Parse("repo:app.bsky.feed.post?action=create")
	if err != nil {
		t.Fatal(err)
	}
	if !repo.AllowsRepoWrite("app.bsky.feed.post", "create") || repo.AllowsRepoWrite("app.bsky.feed.post", "delete") {
		t.Fatal("repo scope behavior changed")
	}
	include, err := Parse("include:site.standard.authFull")
	if err != nil {
		t.Fatal(err)
	}
	if include.Resource != ResourceInclude || include.Nsid != "site.standard.authFull" {
		t.Fatal("include scope behavior changed")
	}
}

func TestExpandPermissionSetScopesIncludesSpacePermission(t *testing.T) {
	var data map[string]any
	if err := json.Unmarshal([]byte(`{
		"lexicon": 1,
		"id": "my.bulletin.permissions",
		"defs": {"main": {
			"type": "permission-set",
			"permissions": [{
				"type": "permission",
				"resource": "space",
				"spaceType": "my.bulletin.board",
				"authority": "*",
				"skey": "self",
				"collection": ["my.bulletin.post", "my.bulletin.removal", "my.bulletin.position"],
				"action": ["read", "create", "update", "delete"],
				"manage": ["create", "update", "delete"]
			}]
		}}
	}`), &data); err != nil {
		t.Fatal(err)
	}

	got, err := expandPermissionSetScopes(data, "my.bulletin.permissions")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expanded scopes = %#v", got)
	}
	grant, err := Parse(got[0])
	if err != nil {
		t.Fatalf("parse expanded space scope %q: %v", got[0], err)
	}
	if grant.Resource != ResourceSpace || grant.SpaceType != "my.bulletin.board" || grant.Authority != "*" || grant.SKey != "self" {
		t.Fatalf("expanded space grant = %#v", grant)
	}
	for _, collection := range []string{"my.bulletin.post", "my.bulletin.removal", "my.bulletin.position"} {
		if !contains(grant.Collections, collection) {
			t.Fatalf("expanded space grant missing collection %q: %#v", collection, grant)
		}
	}
	for _, action := range []string{"read", "create", "update", "delete"} {
		if !contains(grant.Actions, action) {
			t.Fatalf("expanded space grant missing action %q: %#v", action, grant)
		}
	}
	for _, operation := range []string{"create", "update", "delete"} {
		if !contains(grant.Manage, operation) {
			t.Fatalf("expanded space grant missing manage operation %q: %#v", operation, grant)
		}
	}
}
