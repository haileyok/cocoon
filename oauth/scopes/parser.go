// Package scopes parses and validates atproto OAuth permission scopes
// (proposal 0011-auth-scopes). It models the granular resources (repo, rpc,
// blob, account, identity, include) alongside the legacy static scopes
// (atproto, transition:*), and exposes enough structure for PAR-time validation
// and resource-server enforcement.
package scopes

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// Resource identifiers for parsed scopes.
const (
	ResourceRepo       = "repo"
	ResourceRPC        = "rpc"
	ResourceBlob       = "blob"
	ResourceAccount    = "account"
	ResourceIdentity   = "identity"
	ResourceInclude    = "include"
	ResourceAtproto    = "atproto"
	ResourceTransition = "transition"
)

// repoActions are the valid repo write actions.
var repoActions = map[string]bool{"create": true, "update": true, "delete": true}

// transitionValues are the accepted legacy transition scope suffixes.
var transitionValues = map[string]bool{"generic": true, "email": true, "chat.bsky": true}

// Scope is a single parsed scope token. Only the fields relevant to its
// Resource are populated.
type Scope struct {
	Raw      string
	Resource string

	// repo
	Collections []string
	Actions     []string

	// rpc
	Lxm []string
	Aud string

	// blob
	Accept []string

	// account / identity
	Attr   string
	Action string

	// include
	Nsid string

	// transition:<value>
	Transition string
}

// ParseList splits a space-delimited scope string and parses each token. It
// returns an error on the first token that fails to parse.
func ParseList(scope string) ([]*Scope, error) {
	fields := strings.Fields(scope)
	out := make([]*Scope, 0, len(fields))
	for _, f := range fields {
		s, err := Parse(f)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Parse parses a single scope token, returning an error if it is syntactically
// invalid or uses a disallowed wildcard combination.
func Parse(raw string) (*Scope, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty scope")
	}

	if raw == ResourceAtproto {
		return &Scope{Raw: raw, Resource: ResourceAtproto}, nil
	}

	left := raw
	query := ""
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		left, query = raw[:i], raw[i+1:]
	}

	resource := left
	positional := ""
	hasPositional := false
	if i := strings.IndexByte(left, ':'); i >= 0 {
		resource, positional = left[:i], left[i+1:]
		hasPositional = true
	}

	if resource == ResourceTransition {
		if !hasPositional || positional == "" {
			return nil, fmt.Errorf("transition scope %q is missing a value", raw)
		}
		if query != "" {
			return nil, fmt.Errorf("transition scope %q must not have parameters", raw)
		}
		if !transitionValues[positional] {
			return nil, fmt.Errorf("unknown transition scope %q", raw)
		}
		return &Scope{Raw: raw, Resource: ResourceTransition, Transition: positional}, nil
	}

	params, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("invalid scope parameters in %q: %w", raw, err)
	}

	switch resource {
	case ResourceRepo:
		return parseRepo(raw, positional, hasPositional, params)
	case ResourceRPC:
		return parseRPC(raw, positional, hasPositional, params)
	case ResourceBlob:
		return parseBlob(raw, positional, hasPositional, params)
	case ResourceAccount:
		return parseAccount(raw, positional, hasPositional, params)
	case ResourceIdentity:
		return parseIdentity(raw, positional, hasPositional, params)
	case ResourceInclude:
		return parseInclude(raw, positional, hasPositional, params)
	default:
		return nil, fmt.Errorf("unknown scope resource %q", resource)
	}
}

func parseRepo(raw, positional string, hasPositional bool, params url.Values) (*Scope, error) {
	var collections []string
	if hasPositional && positional != "" {
		collections = append(collections, positional)
	}
	collections = append(collections, params["collection"]...)
	if len(collections) == 0 {
		return nil, fmt.Errorf("repo scope %q requires a collection", raw)
	}
	for _, c := range collections {
		if c == "*" {
			continue
		}
		if _, err := syntax.ParseNSID(c); err != nil {
			return nil, fmt.Errorf("repo scope %q has invalid collection %q: %w", raw, c, err)
		}
	}

	actions := params["action"]
	for _, a := range actions {
		if a == "*" {
			return nil, fmt.Errorf("repo scope %q must not use action=*", raw)
		}
		if !repoActions[a] {
			return nil, fmt.Errorf("repo scope %q has invalid action %q", raw, a)
		}
	}
	if len(actions) == 0 {
		actions = []string{"create", "update", "delete"}
	}

	return &Scope{Raw: raw, Resource: ResourceRepo, Collections: collections, Actions: actions}, nil
}

func parseRPC(raw, positional string, hasPositional bool, params url.Values) (*Scope, error) {
	var lxm []string
	if hasPositional && positional != "" {
		lxm = append(lxm, positional)
	}
	lxm = append(lxm, params["lxm"]...)
	if len(lxm) == 0 {
		return nil, fmt.Errorf("rpc scope %q requires an lxm", raw)
	}
	hasWildcardLxm := false
	for _, l := range lxm {
		if l == "*" {
			hasWildcardLxm = true
			continue
		}
		if _, err := syntax.ParseNSID(l); err != nil {
			return nil, fmt.Errorf("rpc scope %q has invalid lxm %q: %w", raw, l, err)
		}
	}

	aud := params.Get("aud")
	if aud == "" {
		return nil, fmt.Errorf("rpc scope %q requires an aud", raw)
	}
	if hasWildcardLxm && aud == "*" {
		return nil, fmt.Errorf("rpc scope %q must not use both lxm=* and aud=*", raw)
	}

	return &Scope{Raw: raw, Resource: ResourceRPC, Lxm: lxm, Aud: aud}, nil
}

func parseBlob(raw, positional string, hasPositional bool, params url.Values) (*Scope, error) {
	var accept []string
	if hasPositional && positional != "" {
		accept = append(accept, positional)
	}
	accept = append(accept, params["accept"]...)
	if len(accept) == 0 {
		return nil, fmt.Errorf("blob scope %q requires an accept pattern", raw)
	}
	return &Scope{Raw: raw, Resource: ResourceBlob, Accept: accept}, nil
}

func parseAccount(raw, positional string, hasPositional bool, params url.Values) (*Scope, error) {
	if !hasPositional || positional == "" {
		return nil, fmt.Errorf("account scope %q requires an attribute", raw)
	}
	if positional != "email" && positional != "repo" {
		return nil, fmt.Errorf("account scope %q has invalid attribute %q", raw, positional)
	}
	action := params.Get("action")
	switch action {
	case "", "read":
		action = "read"
	case "manage":
		// only repo supports manage
		if positional != "repo" {
			return nil, fmt.Errorf("account scope %q does not support action=manage", raw)
		}
	default:
		return nil, fmt.Errorf("account scope %q has invalid action %q", raw, action)
	}
	return &Scope{Raw: raw, Resource: ResourceAccount, Attr: positional, Action: action}, nil
}

func parseIdentity(raw, positional string, hasPositional bool, params url.Values) (*Scope, error) {
	if !hasPositional || positional == "" {
		return nil, fmt.Errorf("identity scope %q requires an attribute", raw)
	}
	if positional != "handle" && positional != "*" {
		return nil, fmt.Errorf("identity scope %q has invalid attribute %q", raw, positional)
	}
	return &Scope{Raw: raw, Resource: ResourceIdentity, Attr: positional}, nil
}

func parseInclude(raw, positional string, hasPositional bool, params url.Values) (*Scope, error) {
	if !hasPositional || positional == "" {
		return nil, fmt.Errorf("include scope %q requires an nsid", raw)
	}
	if _, err := syntax.ParseNSID(positional); err != nil {
		return nil, fmt.Errorf("include scope %q has invalid nsid %q: %w", raw, positional, err)
	}
	return &Scope{Raw: raw, Resource: ResourceInclude, Nsid: positional, Aud: params.Get("aud")}, nil
}

// AllowsRepoWrite reports whether this scope grants the given repo write action
// on the given collection. Non-repo scopes always return false.
func (s *Scope) AllowsRepoWrite(collection, action string) bool {
	if s.Resource != ResourceRepo {
		return false
	}
	hasAction := false
	for _, a := range s.Actions {
		if a == action {
			hasAction = true
			break
		}
	}
	if !hasAction {
		return false
	}
	for _, c := range s.Collections {
		if c == "*" || c == collection {
			return true
		}
	}
	return false
}
