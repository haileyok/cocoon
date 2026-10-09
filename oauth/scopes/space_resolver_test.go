package scopes

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeSpaceTypes map[string][]string

func (f fakeSpaceTypes) ResolveSpaceCollections(_ context.Context, nsid string) ([]string, error) {
	if c, ok := f[nsid]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

func TestExpandSpaceCollections(t *testing.T) {
	r := fakeSpaceTypes{"com.example.group": {"com.example.groupNote", "com.example.groupPost"}}
	got, err := ExpandSpaceCollections(context.Background(), r, []string{
		"atproto",
		"space:com.example.group",
		"space:com.example.group?collection=com.example.other",
		"space:*?authority=*",
		"space:com.example.unknown",
	})
	// The unresolvable bare grant is reported, and left as it is for callers
	// that only display it.
	if err == nil || !strings.Contains(err.Error(), "com.example.unknown") {
		t.Fatalf("unresolvable space type not reported: %v", err)
	}
	want := []string{
		"atproto",
		"space:com.example.group?collection=com.example.groupNote&collection=com.example.groupPost",
		"space:com.example.group?collection=com.example.other",
		"space:*?authority=*",
		"space:com.example.unknown",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestSpaceCollectionsFromLexicon(t *testing.T) {
	cols, err := SpaceCollectionsFromLexicon(map[string]any{"defs": map[string]any{"main": map[string]any{"type": "space", "key": "any", "name": "Group", "collections": []any{"com.example.groupNote"}}}})
	if err != nil || !reflect.DeepEqual(cols, []string{"com.example.groupNote"}) {
		t.Fatalf("%v %v", cols, err)
	}
	if _, err := SpaceCollectionsFromLexicon(map[string]any{"defs": map[string]any{"main": map[string]any{"type": "record"}}}); err == nil {
		t.Fatal("non-space lexicon accepted")
	}
}

func spaceDoc(main map[string]any) map[string]any {
	return map[string]any{"lexicon": 1, "id": "com.example.group", "defs": map[string]any{"main": main}}
}

func validSpaceMain() map[string]any {
	return map[string]any{
		"type":        "space",
		"key":         "any",
		"name":        "Group",
		"collections": []any{"com.example.groupNote"},
	}
}

// The reference validates a space type declaration against the lexicon space
// schema: key, name and collections are required.
func TestParseSpaceDeclaration(t *testing.T) {
	t.Parallel()

	with := func(mut func(m map[string]any)) map[string]any {
		m := validSpaceMain()
		mut(m)
		return spaceDoc(m)
	}

	valid := map[string]map[string]any{
		"minimal":         spaceDoc(validSpaceMain()),
		"key nsid":        with(func(m map[string]any) { m["key"] = "nsid" }),
		"key tid":         with(func(m map[string]any) { m["key"] = "tid" }),
		"key literal":     with(func(m map[string]any) { m["key"] = "literal:self" }),
		"no collections":  with(func(m map[string]any) { m["collections"] = []any{} }),
		"description":     with(func(m map[string]any) { m["description"] = "A group" }),
		"name 64 bytes":   with(func(m map[string]any) { m["name"] = strings.Repeat("a", 64) }),
		"localized names": with(func(m map[string]any) { m["name:lang"] = map[string]any{"es": "Grupo", "ja": "グループ"} }),
	}
	for name, doc := range valid {
		if _, err := ParseSpaceDeclaration(doc); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}

	invalid := map[string]map[string]any{
		"not a space":            spaceDoc(map[string]any{"type": "record"}),
		"no main":                {"lexicon": 1, "defs": map[string]any{}},
		"missing key":            with(func(m map[string]any) { delete(m, "key") }),
		"key not a string":       with(func(m map[string]any) { m["key"] = 1 }),
		"key unknown type":       with(func(m map[string]any) { m["key"] = "uuid" }),
		"key empty literal":      with(func(m map[string]any) { m["key"] = "literal:" }),
		"key bad literal":        with(func(m map[string]any) { m["key"] = "literal:a/b" }),
		"missing name":           with(func(m map[string]any) { delete(m, "name") }),
		"name not a string":      with(func(m map[string]any) { m["name"] = 7 }),
		"empty name":             with(func(m map[string]any) { m["name"] = "" }),
		"name over 64":           with(func(m map[string]any) { m["name"] = strings.Repeat("a", 65) }),
		"missing collections":    with(func(m map[string]any) { delete(m, "collections") }),
		"collections wrong type": with(func(m map[string]any) { m["collections"] = "com.example.groupNote" }),
		"collection not NSID":    with(func(m map[string]any) { m["collections"] = []any{"nope"} }),
		"collection wildcard":    with(func(m map[string]any) { m["collections"] = []any{"*"} }),
		"collection not string":  with(func(m map[string]any) { m["collections"] = []any{3} }),
		"description not string": with(func(m map[string]any) { m["description"] = 3 }),
		"name:lang not a map":    with(func(m map[string]any) { m["name:lang"] = "es" }),
		"name:lang bad tag":      with(func(m map[string]any) { m["name:lang"] = map[string]any{"not a tag!": "x"} }),
		"name:lang bad value":    with(func(m map[string]any) { m["name:lang"] = map[string]any{"es": 1} }),
	}
	for name, doc := range invalid {
		if _, err := ParseSpaceDeclaration(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The declaration engram-garden published before it had key and name.
func TestSpaceCollectionsFromLexiconRequiresKeyAndName(t *testing.T) {
	t.Parallel()
	doc := spaceDoc(map[string]any{"type": "space", "collections": []any{"com.example.groupNote"}})
	if _, err := SpaceCollectionsFromLexicon(doc); err == nil {
		t.Fatal("declaration without key and name accepted")
	}
}

// A grant that names its collections never needs the declaration, so an
// unresolvable type is only an error for bare grants.
func TestExpandSpaceCollectionsOnlyResolvesBareGrants(t *testing.T) {
	t.Parallel()
	in := []string{"space:com.example.unknown?collection=com.example.other", "space:*?authority=*", "repo:com.example.x"}
	got, err := ExpandSpaceCollections(context.Background(), fakeSpaceTypes{}, in)
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Fatalf("%v %v", got, err)
	}
}

// A declaration with no collections confers no write targets: the grant stays
// bare, which is not an error.
func TestExpandSpaceCollectionsEmptyDeclaration(t *testing.T) {
	t.Parallel()
	in := []string{"space:com.example.group"}
	got, err := ExpandSpaceCollections(context.Background(), fakeSpaceTypes{"com.example.group": {}}, in)
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Fatalf("%v %v", got, err)
	}
}
