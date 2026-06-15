package scopes

import (
	"reflect"
	"testing"
)

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
