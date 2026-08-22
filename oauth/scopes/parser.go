// Package scopes parses and validates atproto OAuth permission scopes
// (proposal 0011-auth-scopes). It models the granular resources (repo, rpc,
// blob, account, identity, include, space) alongside the legacy static scopes
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
	ResourceSpace      = "space"
	ResourceAtproto    = "atproto"
	ResourceTransition = "transition"
)

// repoActions are the valid repo write actions.
var repoActions = map[string]bool{"create": true, "update": true, "delete": true}

var spaceActions = map[string]bool{"read_self": true, "read": true, "create": true, "update": true, "delete": true}
var spaceManageActions = map[string]bool{"create": true, "update": true, "delete": true}
var spaceWriteActions = map[string]bool{"create": true, "update": true, "delete": true}

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

	// space
	SpaceType string
	Authority string
	SKey      string
	Manage    []string

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
	case ResourceSpace:
		return parseSpace(raw, positional, hasPositional, params)
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

func parseSpace(raw, positional string, hasPositional bool, params url.Values) (*Scope, error) {
	if !hasPositional || positional == "" {
		return nil, fmt.Errorf("space scope %q requires a space type", raw)
	}
	if positional != "*" {
		if _, err := syntax.ParseNSID(positional); err != nil {
			return nil, fmt.Errorf("space scope %q has invalid space type %q: %w", raw, positional, err)
		}
	}

	for key := range params {
		switch key {
		case "authority", "skey", "collection", "action", "manage":
		default:
			return nil, fmt.Errorf("space scope %q has unknown parameter %q", raw, key)
		}
	}

	authority := "self"
	if values, ok := params["authority"]; ok {
		if len(values) != 1 || values[0] == "" {
			return nil, fmt.Errorf("space scope %q requires exactly one authority", raw)
		}
		authority = values[0]
		if authority != "self" && authority != "*" {
			if _, err := syntax.ParseDID(authority); err != nil {
				return nil, fmt.Errorf("space scope %q has invalid authority %q: %w", raw, authority, err)
			}
		}
	}

	skey := "*"
	if values, ok := params["skey"]; ok {
		if len(values) != 1 || values[0] == "" {
			return nil, fmt.Errorf("space scope %q requires exactly one skey", raw)
		}
		skey = values[0]
		if skey != "*" {
			if _, err := syntax.ParseRecordKey(skey); err != nil {
				return nil, fmt.Errorf("space scope %q has invalid skey %q: %w", raw, skey, err)
			}
		}
	}

	collections := append([]string(nil), params["collection"]...)
	for _, collection := range collections {
		if collection == "*" {
			continue
		}
		if collection == "" {
			return nil, fmt.Errorf("space scope %q has an empty collection", raw)
		}
		if _, err := syntax.ParseNSID(collection); err != nil {
			return nil, fmt.Errorf("space scope %q has invalid collection %q: %w", raw, collection, err)
		}
	}

	actions := append([]string(nil), params["action"]...)
	for _, action := range actions {
		if !spaceActions[action] {
			return nil, fmt.Errorf("space scope %q has invalid action %q", raw, action)
		}
	}
	if len(actions) == 0 {
		actions = []string{"read", "create", "update", "delete"}
	}

	manage := append([]string(nil), params["manage"]...)
	for _, operation := range manage {
		if !spaceManageActions[operation] {
			return nil, fmt.Errorf("space scope %q has invalid manage operation %q", raw, operation)
		}
	}

	return &Scope{
		Raw:         raw,
		Resource:    ResourceSpace,
		Collections: collections,
		Actions:     actions,
		SpaceType:   positional,
		Authority:   authority,
		SKey:        skey,
		Manage:      manage,
	}, nil
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

// SpaceTypeDeclaration describes a concrete space type's default record
// collections. A nil or invalid declaration fails closed for omitted-collection
// writes.
type SpaceTypeDeclaration struct {
	Collections []string
}

// SpaceTypeResolver resolves a concrete space type declaration. Resolution is
// supplied by the caller; this package performs no network lookup.
type SpaceTypeResolver interface {
	ResolveSpaceType(spaceType string) (SpaceTypeDeclaration, error)
}

// SpaceValue is the typed value consumed by space-scope matching.
type SpaceValue interface {
	SpaceScopeComponents() (authority, spaceType, skey string)
}

// CanonicalSpaceValue is a string-based canonical space value that satisfies
// SpaceValue without importing the space package.
type CanonicalSpaceValue struct {
	Authority string
	SpaceType string
	SKey      string
}

// SpaceScopeComponents implements SpaceValue.
func (v CanonicalSpaceValue) SpaceScopeComponents() (authority, spaceType, skey string) {
	return v.Authority, v.SpaceType, v.SKey
}

// SpaceRequest describes a single record operation against a space grant.
// Value is preferred; Space is a compatibility alias for callers that name the
// target after the resource.
type SpaceRequest struct {
	Value       SpaceValue
	Space       SpaceValue
	RepoDID     string
	Collection  string
	Action      string
	GrantingDID string
}

// MatchesSpace reports whether value matches this scope's authority,
// spaceType, and skey selectors. authority=self resolves against grantingDID.
func (s *Scope) MatchesSpace(value SpaceValue, grantingDID string) bool {
	if s == nil || s.Resource != ResourceSpace || value == nil {
		return false
	}
	authority, spaceType, skey := value.SpaceScopeComponents()
	if !validCanonicalSpace(authority, spaceType, skey) {
		return false
	}
	if s.Authority == "self" {
		if grantingDID == "" || authority != grantingDID {
			return false
		}
	} else if s.Authority != "*" && s.Authority != authority {
		return false
	}
	return (s.SpaceType == "*" || s.SpaceType == spaceType) &&
		(s.SKey == "*" || s.SKey == skey)
}

// AllowsSpaceRead reports whether this scope grants reading repoDID in value.
// read covers every repo and implies read_self; read_self covers only the
// granting user's own repo.
func (s *Scope) AllowsSpaceRead(value SpaceValue, repoDID, grantingDID string) bool {
	if !s.MatchesSpace(value, grantingDID) {
		return false
	}
	for _, action := range s.Actions {
		switch action {
		case "read":
			return true
		case "read_self":
			if repoDID != "" && repoDID == grantingDID {
				return true
			}
		}
	}
	return false
}

// AllowsSpaceReadSelf is the read_self operation matcher. A read action also
// satisfies it, as read implies read_self.
func (s *Scope) AllowsSpaceReadSelf(value SpaceValue, repoDID, grantingDID string) bool {
	return s.AllowsSpaceRead(value, repoDID, grantingDID)
}

// AllowsSpaceDelegation reports whether this scope permits obtaining a space
// delegation token. Only read grants delegation; read_self does not.
func (s *Scope) AllowsSpaceDelegation(value SpaceValue, grantingDID string) bool {
	if !s.MatchesSpace(value, grantingDID) {
		return false
	}
	return contains(s.Actions, "read")
}

// AllowsSpaceWrite reports whether this scope permits a create, update, or
// delete record operation for collection. Omitted grant collections are
// resolved through resolver and fail closed when unavailable or invalid.
func (s *Scope) AllowsSpaceWrite(value SpaceValue, collection, action, grantingDID string, resolver SpaceTypeResolver) bool {
	if s == nil || s.Resource != ResourceSpace || !spaceWriteActions[action] {
		return false
	}
	if !s.MatchesSpace(value, grantingDID) || !contains(s.Actions, action) {
		return false
	}
	_, spaceType, _ := value.SpaceScopeComponents()
	return s.allowsCollection(spaceType, collection, resolver)
}

// AllowsSpaceManage reports whether this scope permits a management operation
// on the target space. Management ignores record collections and declarations.
func (s *Scope) AllowsSpaceManage(value SpaceValue, action, grantingDID string) bool {
	if s == nil || s.Resource != ResourceSpace || !spaceManageActions[action] {
		return false
	}
	return s.MatchesSpace(value, grantingDID) && contains(s.Manage, action)
}

// AllowsSpaceRequest evaluates a complete record request against this grant.
func (s *Scope) AllowsSpaceRequest(request SpaceRequest, resolver SpaceTypeResolver) bool {
	value := request.Value
	if value == nil {
		value = request.Space
	}
	if request.Action == "read" || request.Action == "read_self" {
		return s.AllowsSpaceRead(value, request.RepoDID, request.GrantingDID)
	}
	return s.AllowsSpaceWrite(value, request.Collection, request.Action, request.GrantingDID, resolver)
}

func (s *Scope) allowsCollection(spaceType, collection string, resolver SpaceTypeResolver) bool {
	if collection == "" {
		return false
	}
	if _, err := syntax.ParseNSID(collection); err != nil {
		return false
	}
	if len(s.Collections) != 0 {
		return contains(s.Collections, "*") || contains(s.Collections, collection)
	}
	if s.SpaceType == "*" || spaceType == "" || resolver == nil {
		return false
	}
	declaration, err := resolver.ResolveSpaceType(spaceType)
	if err != nil || declaration.Collections == nil {
		return false
	}
	return validDeclaredCollections(declaration.Collections) && contains(declaration.Collections, collection)
}

func validCanonicalSpace(authority, spaceType, skey string) bool {
	_, authorityErr := syntax.ParseDID(authority)
	_, spaceTypeErr := syntax.ParseNSID(spaceType)
	_, skeyErr := syntax.ParseRecordKey(skey)
	return authorityErr == nil && spaceTypeErr == nil && skeyErr == nil
}

func validDeclaredCollections(collections []string) bool {
	for _, collection := range collections {
		if collection == "*" {
			return false
		}
		if _, err := syntax.ParseNSID(collection); err != nil {
			return false
		}
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
