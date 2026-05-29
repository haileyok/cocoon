package scopes

import "testing"

func TestParseToken(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		resource   string
		positional string
		params     map[string][]string
		wantErr    bool
	}{
		{name: "bare atproto", token: "atproto", resource: "atproto"},
		{name: "transition generic", token: "transition:generic", resource: "transition", positional: "generic"},
		{name: "transition email", token: "transition:email", resource: "transition", positional: "email"},
		{name: "repo collection", token: "repo:app.bsky.feed.post", resource: "repo", positional: "app.bsky.feed.post"},
		{
			name:       "repo collection with action",
			token:      "repo:app.bsky.feed.post?action=create",
			resource:   "repo",
			positional: "app.bsky.feed.post",
			params:     map[string][]string{"action": {"create"}},
		},
		{name: "repo wildcard", token: "repo:*", resource: "repo", positional: "*"},
		{
			name:       "repo wildcard with action",
			token:      "repo:*?action=delete",
			resource:   "repo",
			positional: "*",
			params:     map[string][]string{"action": {"delete"}},
		},
		{
			name:       "include with aud",
			token:      "include:site.standard.authFull?aud=did:web:example.com",
			resource:   "include",
			positional: "site.standard.authFull",
			params:     map[string][]string{"aud": {"did:web:example.com"}},
		},
		{name: "blob positional", token: "blob:image/png", resource: "blob", positional: "image/png"},
		{
			name:     "blob accept param",
			token:    "blob?accept=image/*",
			resource: "blob",
			params:   map[string][]string{"accept": {"image/*"}},
		},
		{name: "empty token", token: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseToken(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got none", tt.token)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Resource != tt.resource {
				t.Errorf("resource: got %q, want %q", p.Resource, tt.resource)
			}
			if p.Positional != tt.positional {
				t.Errorf("positional: got %q, want %q", p.Positional, tt.positional)
			}
			for k, want := range tt.params {
				got := p.Params[k]
				if len(got) != len(want) {
					t.Errorf("param %q: got %v, want %v", k, got, want)
					continue
				}
				for i := range want {
					if got[i] != want[i] {
						t.Errorf("param %q[%d]: got %q, want %q", k, i, got[i], want[i])
					}
				}
			}
		})
	}
}

func TestParse(t *testing.T) {
	perms, err := Parse("  atproto   transition:generic repo:app.bsky.feed.post?action=create  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(perms) != 3 {
		t.Fatalf("expected 3 perms, got %d: %+v", len(perms), perms)
	}
	if !Has(perms, "atproto") {
		t.Errorf("expected atproto present")
	}
}

func TestParseEmpty(t *testing.T) {
	perms, err := Parse("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(perms) != 0 {
		t.Errorf("expected 0 perms, got %d", len(perms))
	}
}

func TestGrantsAllRepoWrites(t *testing.T) {
	yes, _ := Parse("atproto transition:generic")
	if !GrantsAllRepoWrites(yes) {
		t.Errorf("transition:generic should grant all repo writes")
	}
	no, _ := Parse("atproto transition:email repo:app.bsky.feed.post")
	if GrantsAllRepoWrites(no) {
		t.Errorf("transition:email + repo should not grant all repo writes")
	}
}

func TestRepoWriteAllowed(t *testing.T) {
	tests := []struct {
		name       string
		scope      string
		collection string
		action     string
		want       bool
	}{
		{"exact collection any action", "repo:app.bsky.feed.post", "app.bsky.feed.post", "create", true},
		{"exact collection any action update", "repo:app.bsky.feed.post", "app.bsky.feed.post", "update", true},
		{"exact collection action match", "repo:app.bsky.feed.post?action=create", "app.bsky.feed.post", "create", true},
		{"exact collection action mismatch", "repo:app.bsky.feed.post?action=create", "app.bsky.feed.post", "delete", false},
		{"different collection", "repo:app.bsky.feed.post", "app.bsky.feed.like", "create", false},
		{"wildcard any collection", "repo:*", "com.example.thing", "delete", true},
		{"wildcard with action match", "repo:*?action=delete", "com.example.thing", "delete", true},
		{"wildcard with action mismatch", "repo:*?action=delete", "com.example.thing", "create", false},
		{"no repo scope", "atproto", "app.bsky.feed.post", "create", false},
		{"repeated action params", "repo:app.bsky.feed.post?action=create&action=update", "app.bsky.feed.post", "update", true},
		{"comma separated actions", "repo:app.bsky.feed.post?action=create,delete", "app.bsky.feed.post", "delete", true},
		{"comma separated actions mismatch", "repo:app.bsky.feed.post?action=create,delete", "app.bsky.feed.post", "update", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms, err := Parse(tt.scope)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if got := RepoWriteAllowed(perms, tt.collection, tt.action); got != tt.want {
				t.Errorf("RepoWriteAllowed(%q, %q, %q) = %v, want %v", tt.scope, tt.collection, tt.action, got, tt.want)
			}
		})
	}
}

func TestBlobAllowed(t *testing.T) {
	if !BlobAllowed(mustParse(t, "atproto blob:image/png")) {
		t.Errorf("blob:image/png should allow blobs")
	}
	if !BlobAllowed(mustParse(t, "atproto blob?accept=image/*")) {
		t.Errorf("blob?accept=image/* should allow blobs")
	}
	if BlobAllowed(mustParse(t, "atproto repo:*")) {
		t.Errorf("repo:* alone should not allow blobs")
	}
}

func mustParse(t *testing.T, scope string) []Permission {
	t.Helper()
	perms, err := Parse(scope)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return perms
}
