package scopes

import (
	"encoding/json"
	"testing"
)

// bulletin.my's published permission set (my.bulletin.permissions).
const bulletinPermissionSet = `{
  "lexicon": 1,
  "id": "my.bulletin.permissions",
  "defs": {
    "main": {
      "type": "permission-set",
      "title": "Bulletin",
      "permissions": [
        {
          "type": "permission",
          "resource": "space",
          "spaceType": "my.bulletin.board",
          "authority": "*",
          "skey": "self",
          "collection": ["my.bulletin.post", "my.bulletin.removal", "my.bulletin.position"],
          "action": ["read", "create", "update", "delete"],
          "manage": ["create", "update", "delete"]
        },
        {
          "type": "permission",
          "resource": "space",
          "spaceType": "com.other.board",
          "collection": ["com.other.post"]
        },
        {
          "type": "permission",
          "resource": "repo",
          "collection": ["my.bulletin.profile"]
        }
      ]
    }
  }
}`

func TestSpacePermissionsFromLexicon(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(bulletinPermissionSet), &doc); err != nil {
		t.Fatal(err)
	}
	perms, err := SpacePermissionsFromLexicon("my.bulletin.permissions", doc)
	if err != nil {
		t.Fatal(err)
	}
	// The space type outside the set's authority is left out, as is the repo
	// permission (expanded elsewhere).
	if len(perms) != 1 {
		t.Fatalf("%d permissions: %v", len(perms), perms)
	}
	p := perms[0]
	base := SpaceMatch{Type: "my.bulletin.board", Authority: "did:plc:alice", Skey: "self"}
	manage := base
	manage.Manage = "create"
	write := base
	write.Action, write.Collection = "create", "my.bulletin.post"
	if !p.Matches(manage) || !p.Matches(write) {
		t.Fatalf("%s does not grant the board", p)
	}
	if got := p.String(); got != "space:my.bulletin.board?authority=*&skey=self&collection=my.bulletin.position&collection=my.bulletin.post&collection=my.bulletin.removal&manage=create&manage=update&manage=delete" {
		t.Fatal(got)
	}
}

func TestSpacePermissionsFromLexiconRejectsNonSets(t *testing.T) {
	if _, err := SpacePermissionsFromLexicon("my.bulletin.permissions", map[string]any{"defs": map[string]any{"main": map[string]any{"type": "record"}}}); err == nil {
		t.Fatal("non permission-set accepted")
	}
}
