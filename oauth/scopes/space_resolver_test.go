package scopes

import (
	"context"
	"errors"
	"reflect"
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
	got := ExpandSpaceCollections(context.Background(), r, []string{
		"atproto",
		"space:com.example.group",
		"space:com.example.group?collection=com.example.other",
		"space:*?authority=*",
		"space:com.example.unknown",
	})
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
	cols, err := SpaceCollectionsFromLexicon(map[string]any{"defs": map[string]any{"main": map[string]any{"type": "space", "name": "Group", "collections": []any{"com.example.groupNote"}}}})
	if err != nil || !reflect.DeepEqual(cols, []string{"com.example.groupNote"}) {
		t.Fatalf("%v %v", cols, err)
	}
	if _, err := SpaceCollectionsFromLexicon(map[string]any{"defs": map[string]any{"main": map[string]any{"type": "record"}}}); err == nil {
		t.Fatal("non-space lexicon accepted")
	}
}
