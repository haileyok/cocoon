// Package scopes parses and evaluates atproto OAuth permission scopes.
//
// Scope tokens follow the grammar described at https://atproto.com/specs/permission:
//
//	resource[:positional][?params]
//
// Examples:
//
//	atproto
//	transition:generic
//	repo:app.bsky.feed.post
//	repo:app.bsky.feed.post?action=create
//	repo:*
//	blob:image/png
//	blob?accept=image/*
//	include:site.standard.authFull?aud=did:web:example.com
package scopes

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Permission is a single parsed scope token.
type Permission struct {
	// Resource is the scope resource type, e.g. "atproto", "repo", "blob",
	// "rpc", "include", "transition".
	Resource string
	// Positional is the (percent-decoded) positional parameter that follows the
	// first ":" in the token, e.g. the collection for "repo:<collection>" or the
	// NSID for "include:<nsid>". Empty when the token has no positional segment.
	Positional string
	// Params holds the query-style parameters that follow "?" in the token.
	Params url.Values
}

// ParseToken parses a single scope token of the form
// resource[:positional][?params].
func ParseToken(tok string) (Permission, error) {
	if tok == "" {
		return Permission{}, fmt.Errorf("empty scope token")
	}

	p := Permission{Params: url.Values{}}

	// Split the query parameters off on the first "?".
	left := tok
	if idx := strings.IndexByte(tok, '?'); idx >= 0 {
		left = tok[:idx]
		vals, err := url.ParseQuery(tok[idx+1:])
		if err != nil {
			return Permission{}, fmt.Errorf("invalid params in scope %q: %w", tok, err)
		}
		p.Params = vals
	}

	// Split the resource from the positional on the first ":".
	if idx := strings.IndexByte(left, ':'); idx >= 0 {
		p.Resource = left[:idx]
		pos := left[idx+1:]
		if decoded, err := url.PathUnescape(pos); err == nil {
			pos = decoded
		}
		p.Positional = pos
	} else {
		p.Resource = left
	}

	if p.Resource == "" {
		return Permission{}, fmt.Errorf("scope %q is missing a resource", tok)
	}

	return p, nil
}

// Parse parses a space-separated scope string into individual permissions.
func Parse(scope string) ([]Permission, error) {
	fields := strings.Fields(scope)
	perms := make([]Permission, 0, len(fields))
	for _, f := range fields {
		p, err := ParseToken(f)
		if err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// Has reports whether perms contains a bare resource token (no positional, no
// params), such as "atproto".
func Has(perms []Permission, resource string) bool {
	for _, p := range perms {
		if p.Resource == resource && p.Positional == "" {
			return true
		}
	}
	return false
}

// GrantsAllRepoWrites reports whether perms grant unrestricted repo write
// access. The legacy "transition:generic" scope is app-password-equivalent and
// grants full read/write to the repo, so it bypasses granular repo checks.
func GrantsAllRepoWrites(perms []Permission) bool {
	for _, p := range perms {
		if p.Resource == "transition" && p.Positional == "generic" {
			return true
		}
	}
	return false
}

// repoActions returns the set of actions a repo permission allows. An empty
// result means the permission specified no action filter and therefore allows
// every action (create, update, delete). The "action" parameter may be encoded
// either as repeated params (action=create&action=update) or as a
// comma-separated list (action=create,update); both forms are accepted.
func repoActions(p Permission) []string {
	var actions []string
	for _, v := range p.Params["action"] {
		for _, a := range strings.Split(v, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				actions = append(actions, a)
			}
		}
	}
	return actions
}

// RepoWriteAllowed reports whether perms permit the given action on the given
// collection. action must be one of "create", "update", "delete". A repo
// permission matches when its positional is "*" or equals collection, and
// either it specifies no action filter or its action set contains action.
func RepoWriteAllowed(perms []Permission, collection, action string) bool {
	for _, p := range perms {
		if p.Resource != "repo" {
			continue
		}
		if p.Positional != "*" && p.Positional != collection {
			continue
		}
		actions := repoActions(p)
		if len(actions) == 0 || slices.Contains(actions, action) {
			return true
		}
	}
	return false
}

// BlobAllowed reports whether perms permit uploading a blob. Per the scope
// grammar a "blob" permission may constrain the accepted MIME types; MIME
// filtering is intentionally not enforced here, so the mere presence of any
// blob permission is sufficient.
func BlobAllowed(perms []Permission) bool {
	for _, p := range perms {
		if p.Resource == "blob" {
			return true
		}
	}
	return false
}
