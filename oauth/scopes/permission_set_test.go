package scopes

import (
	"net/url"
	"testing"
)

const sampleAuthFull = `{
  "uri": "at://did:web:example.com/com.atproto.lexicon.schema/com.example.authFull",
  "cid": "bafyreigabc",
  "value": {
    "lexicon": 1,
    "id": "com.example.authFull",
    "defs": {
      "main": {
        "type": "permission-set",
        "title": "Full Access",
        "permissions": [
          { "type": "permission", "resource": "repo", "collection": ["app.example.post"] },
          { "type": "permission", "resource": "repo", "collection": ["app.example.like"], "action": ["create", "delete"] },
          { "type": "permission", "resource": "blob", "accept": ["image/*"] },
          { "type": "permission", "resource": "rpc", "inheritAud": true, "lxm": ["app.example.getFeed"] },
          { "type": "permission", "resource": "rpc", "aud": "did:web:fixed.example.com", "lxm": ["app.example.ping"] }
        ]
      }
    }
  }
}`

func TestPermissionsFromRecord(t *testing.T) {
	rec, err := parseRecordJSON([]byte(sampleAuthFull))
	if err != nil {
		t.Fatalf("parseRecordJSON: %v", err)
	}

	params := url.Values{}
	params.Set("aud", "did:web:caller.example.com")

	perms, err := permissionsFromRecord(rec, params)
	if err != nil {
		t.Fatalf("permissionsFromRecord: %v", err)
	}

	// repo:app.example.post (no action) -> any action allowed
	if !RepoWriteAllowed(perms, "app.example.post", "create") {
		t.Errorf("expected create allowed on app.example.post")
	}
	if !RepoWriteAllowed(perms, "app.example.post", "delete") {
		t.Errorf("expected delete allowed on app.example.post (no action filter)")
	}

	// repo:app.example.like with action=[create,delete]
	if !RepoWriteAllowed(perms, "app.example.like", "create") {
		t.Errorf("expected create allowed on app.example.like")
	}
	if RepoWriteAllowed(perms, "app.example.like", "update") {
		t.Errorf("did not expect update allowed on app.example.like (action filtered)")
	}

	// collection not in the set
	if RepoWriteAllowed(perms, "app.example.other", "create") {
		t.Errorf("did not expect create allowed on unlisted collection")
	}

	// blob
	if !BlobAllowed(perms) {
		t.Errorf("expected blob allowed")
	}

	// rpc with inheritAud should pick up the caller's aud
	var inheritedAud, fixedAud string
	for _, p := range perms {
		if p.Resource == "rpc" && p.Positional == "app.example.getFeed" {
			inheritedAud = p.Params.Get("aud")
		}
		if p.Resource == "rpc" && p.Positional == "app.example.ping" {
			fixedAud = p.Params.Get("aud")
		}
	}
	if inheritedAud != "did:web:caller.example.com" {
		t.Errorf("inheritAud rpc: got aud %q, want caller aud", inheritedAud)
	}
	if fixedAud != "did:web:fixed.example.com" {
		t.Errorf("fixed-aud rpc: got aud %q, want fixed aud", fixedAud)
	}
}

func TestPermissionsFromRecordInheritAudMissing(t *testing.T) {
	rec, err := parseRecordJSON([]byte(sampleAuthFull))
	if err != nil {
		t.Fatalf("parseRecordJSON: %v", err)
	}

	// No aud supplied by the include: the inheritAud rpc permission must be
	// dropped, while the fixed-aud one survives.
	perms, err := permissionsFromRecord(rec, url.Values{})
	if err != nil {
		t.Fatalf("permissionsFromRecord: %v", err)
	}

	for _, p := range perms {
		if p.Resource == "rpc" && p.Positional == "app.example.getFeed" {
			t.Errorf("inheritAud rpc with no include aud should be dropped")
		}
	}
}

func TestPermissionsFromRecordWrongType(t *testing.T) {
	const notPermSet = `{"value":{"defs":{"main":{"type":"record"}}}}`
	rec, err := parseRecordJSON([]byte(notPermSet))
	if err != nil {
		t.Fatalf("parseRecordJSON: %v", err)
	}
	if _, err := permissionsFromRecord(rec, nil); err == nil {
		t.Errorf("expected error for non-permission-set record")
	}
}

func TestParseRecordJSONInvalid(t *testing.T) {
	if _, err := parseRecordJSON([]byte("not json")); err == nil {
		t.Errorf("expected error for invalid JSON")
	}
}
