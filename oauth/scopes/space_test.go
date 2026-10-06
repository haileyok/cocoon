package scopes

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// Ported from packages/oauth/oauth-scopes/src/scopes/space-permission.test.ts
// (bluesky-social/atproto 5b95b2f2).

var defaultSpaceActions = []string{"read", "create", "update", "delete"}

func mustSpace(t *testing.T, s string) *SpacePermission {
	t.Helper()
	p := ParseSpacePermission(s)
	if p == nil {
		t.Fatalf("%q did not parse", s)
	}
	return p
}

func TestSpacePermissionFromString(t *testing.T) {
	p := mustSpace(t, "space:com.atmoboards.forum")
	if p.Type != "com.atmoboards.forum" || p.Authority != "self" || p.Skey != "*" || p.Collection != nil ||
		!reflect.DeepEqual(p.Action, defaultSpaceActions) || p.Manage != nil {
		t.Fatalf("defaults %+v", p)
	}
	p = mustSpace(t, "space:*?authority=did:plc:abc123xyz")
	if p.Type != "*" || p.Authority != "did:plc:abc123xyz" {
		t.Fatalf("%+v", p)
	}
	if mustSpace(t, "space:com.atmoboards.forum?authority=*").Authority != "*" {
		t.Fatal("authority=*")
	}
	p = mustSpace(t, "space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create&action=update")
	if p.Type != "com.atmoboards.forum" || p.Authority != "did:plc:abc123xyz" || p.Skey != "default" ||
		!reflect.DeepEqual(p.Collection, []string{"com.atmoboards.thread"}) || !reflect.DeepEqual(p.Action, []string{"create", "update"}) {
		t.Fatalf("%+v", p)
	}
	if !reflect.DeepEqual(mustSpace(t, "space:com.atmoboards.forum?collection=*").Action, defaultSpaceActions) {
		t.Fatal("omitted action")
	}
	if !reflect.DeepEqual(mustSpace(t, "space:com.atmoboards.forum?action=read_self&collection=*").Action, []string{"read_self"}) {
		t.Fatal("read_self")
	}
	if !reflect.DeepEqual(mustSpace(t, "space:com.atmoboards.forum?manage=update&manage=delete").Manage, []string{"update", "delete"}) {
		t.Fatal("manage")
	}
	for _, bad := range []string{
		"space:com.example.x?manage=bogus",
		"space:foo bar",
		"space:short",
		"space:*?authority=not-a-did",
		"space:*?authority=did:",
		"space:com.example.x?action=bogus",
		"space:com.example.x?collection=not_an_nsid",
		"space:com.example.x?skey=",
		"repo:com.example.x",
		"whatever",
	} {
		if ParseSpacePermission(bad) != nil {
			t.Errorf("%q parsed", bad)
		}
	}
	for _, skey := range []string{"self", "3jui7kd54zh2y", "a.b-c_d~e:f", strings.Repeat("x", 512)} {
		if p := ParseSpacePermission("space:com.example.x?skey=" + skey); p == nil || p.Skey != skey {
			t.Errorf("skey %q", skey)
		}
	}
	for _, skey := range []string{"hello world", ".", "..", "a/b", "a#b", strings.Repeat("x", 513)} {
		if ParseSpacePermission("space:com.example.x?skey="+url.QueryEscape(skey)) != nil {
			t.Errorf("skey %q parsed", skey)
		}
	}
}

func TestSpacePermissionScopeNeededFor(t *testing.T) {
	base := SpaceMatch{Type: "com.atmoboards.forum", Authority: "did:plc:abc", Skey: "default"}
	read := base
	read.Action = "read"
	if got := SpaceScopeNeededFor(read); got != "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read" {
		t.Fatal(got)
	}
	create := base
	create.Action, create.Collection = "create", "com.atmoboards.thread"
	if got := SpaceScopeNeededFor(create); got != "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&collection=com.atmoboards.thread&action=create" {
		t.Fatal(got)
	}
	manage := base
	manage.Manage = "update"
	if got := SpaceScopeNeededFor(manage); got != "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read_self&manage=update" {
		t.Fatal(got)
	}

	readSelf := base
	readSelf.Action = "read_self"
	del := base
	del.Manage = "delete"
	for _, target := range []SpaceMatch{read, readSelf, create, del} {
		re := ParseSpacePermission(SpaceScopeNeededFor(target))
		if re == nil || !re.Matches(target) {
			t.Fatalf("%+v does not round-trip", target)
		}
		if target.Collection == "" && re.Matches(create) {
			t.Fatalf("%+v widens to writes", target)
		}
	}
}

func TestSpacePermissionMatches(t *testing.T) {
	base := SpaceMatch{Type: "com.atmoboards.forum", Authority: "did:plc:abc", Skey: "default"}
	with := func(f func(*SpaceMatch)) SpaceMatch {
		m := base
		f(&m)
		return m
	}
	read := with(func(m *SpaceMatch) { m.Action = "read" })
	readSelf := with(func(m *SpaceMatch) { m.Action = "read_self" })
	create := func(c string) SpaceMatch {
		return with(func(m *SpaceMatch) { m.Action, m.Collection = "create", c })
	}
	manage := func(op string) SpaceMatch { return with(func(m *SpaceMatch) { m.Manage = op }) }
	anyAuth := func(rest string) *SpacePermission {
		return mustSpace(t, "space:com.atmoboards.forum?authority=*"+rest)
	}

	check := func(name string, got, want bool) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	check("default grants read", anyAuth("").Matches(read), true)
	check("action=create refuses read", anyAuth("&action=create").Matches(read), false)
	check("action=read reads", anyAuth("&action=read").Matches(read), true)
	check("action=read blocks writes", anyAuth("&action=read").Matches(create("com.atmoboards.thread")), false)
	check("omitted collection blocks writes", anyAuth("").Matches(create("com.atmoboards.thread")), false)
	check("collection=* create", anyAuth("&collection=*").Matches(create("any.collection.name")), true)
	check("collection=* update", anyAuth("&collection=*").Matches(with(func(m *SpaceMatch) { m.Action, m.Collection = "update", "another.one.here" })), true)
	check("manage=update", anyAuth("&action=read&manage=update").Matches(manage("update")), true)
	check("manage=update not delete", anyAuth("&action=read&manage=update").Matches(manage("delete")), false)
	check("record-only grant no manage", anyAuth("&action=read").Matches(manage("update")), false)
	check("default grant no manage", anyAuth("").Matches(manage("update")), false)
	check("read implies read_self", anyAuth("&action=read").Matches(readSelf), true)
	check("read_self own", anyAuth("&action=read_self").Matches(readSelf), true)
	check("read_self not read", anyAuth("&action=read_self").Matches(read), false)
	check("read_self ignores collection", anyAuth("&action=read_self&collection=com.atmoboards.thread").Matches(readSelf), true)
	check("explicit collection", anyAuth("&collection=com.atmoboards.thread&action=create").Matches(create("com.atmoboards.thread")), true)
	check("explicit collection other", anyAuth("&collection=com.atmoboards.thread&action=create").Matches(create("com.atmoboards.reply")), false)

	wild := mustSpace(t, "space:*?authority=did:plc:abc")
	check("type=*", wild.Matches(read), true)
	check("type=* other type", wild.Matches(with(func(m *SpaceMatch) { m.Type, m.Action = "com.example.different", "read" })), true)

	concrete := mustSpace(t, "space:com.atmoboards.forum?authority=did:plc:abc&skey=default")
	check("concrete", concrete.Matches(read), true)
	check("concrete wrong authority", concrete.Matches(with(func(m *SpaceMatch) { m.Authority, m.Action = "did:plc:other", "read" })), false)
	check("concrete wrong skey", concrete.Matches(with(func(m *SpaceMatch) { m.Skey, m.Action = "other", "read" })), false)

	self := mustSpace(t, "space:com.atmoboards.forum")
	check("unresolved self", self.Authority == "self" && !self.Matches(read), true)
	resolved := mustSpace(t, "space:com.atmoboards.forum?action=read").WithResolvedAuthority("did:plc:abc")
	check("resolved self", resolved.Matches(read), true)
	check("resolved self other", resolved.Matches(with(func(m *SpaceMatch) { m.Authority, m.Action = "did:plc:other", "read" })), false)
}

func TestSpacePermissionString(t *testing.T) {
	if s := mustSpace(t, "space:com.atmoboards.forum").String(); s != "space:com.atmoboards.forum" {
		t.Fatal(s)
	}
	in := "space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create"
	if s := mustSpace(t, in).String(); s != in {
		t.Fatal(s)
	}
}

func TestSpacePermissionWithResolvedAuthority(t *testing.T) {
	p := mustSpace(t, "space:com.atmoboards.forum")
	if !p.IsSelfAuthority() || p.WithResolvedAuthority("did:plc:abc").Authority != "did:plc:abc" {
		t.Fatal("self")
	}
	for _, s := range []string{"space:com.atmoboards.forum?authority=did:plc:xyz", "space:com.atmoboards.forum?authority=*"} {
		p := mustSpace(t, s)
		if p.WithResolvedAuthority("did:plc:abc") != p {
			t.Fatalf("%s changed", s)
		}
	}
}

func TestSpacePermissionWithDefaultCollections(t *testing.T) {
	p := mustSpace(t, "space:com.atmoboards.forum?authority=*")
	if p.HasCollections() {
		t.Fatal("has collections")
	}
	e := p.WithDefaultCollections([]string{"com.atmoboards.thread", "com.atmoboards.reply"})
	if !reflect.DeepEqual(e.Collection, []string{"com.atmoboards.thread", "com.atmoboards.reply"}) {
		t.Fatal(e.Collection)
	}
	if !e.Matches(SpaceMatch{Type: "com.atmoboards.forum", Authority: "did:plc:abc", Skey: "default", Action: "create", Collection: "com.atmoboards.thread"}) {
		t.Fatal("declared collection write")
	}
	for _, s := range []string{"space:com.atmoboards.forum?collection=com.atmoboards.thread", "space:com.atmoboards.forum?collection=*"} {
		p := mustSpace(t, s)
		if !p.HasCollections() || p.WithDefaultCollections([]string{"com.atmoboards.reply"}) != p {
			t.Fatalf("%s changed", s)
		}
	}
	p = mustSpace(t, "space:com.atmoboards.forum")
	if p.WithDefaultCollections(nil) != p {
		t.Fatal("empty default list")
	}
}

func TestParseAcceptsSpaceScopes(t *testing.T) {
	s, err := Parse("space:com.atmoboards.forum?collection=*")
	if err != nil || s.Resource != ResourceSpace || s.Space == nil {
		t.Fatalf("%v %+v", err, s)
	}
	if _, err := Parse("space:short"); err == nil {
		t.Fatal("invalid space scope parsed")
	}
}
