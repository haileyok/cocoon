package scopes

import (
	"net/url"
	"sort"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// ResourceSpace is the permissioned-data (Spaces) scope resource.
const ResourceSpace = "space"

// SpaceActions lists the record actions in canonical order. read implies
// read_self.
var SpaceActions = []string{"read_self", "read", "create", "update", "delete"}

// SpaceDefaultActions applies when a grant names no action.
var SpaceDefaultActions = []string{"read", "create", "update", "delete"}

// SpaceManageOps lists the space-level management operations.
var SpaceManageOps = []string{"create", "update", "delete"}

// SpacePermission is a parsed `space:` scope, following SpacePermission in
// @atproto/oauth-scopes (bluesky-social/atproto 5b95b2f2):
//
//	space:<type>?authority=<did|self|*>&skey=<rkey|*>&collection=<nsid|*>&action=..&manage=..
//
// Authority defaults to "self", resolved to the granting user's DID when a
// token is issued; an unresolved "self" matches nothing. A grant without a
// collection permits no writes.
type SpacePermission struct {
	Type       string
	Authority  string
	Skey       string
	Collection []string // nil: no write targets
	Action     []string
	Manage     []string // nil: no manage operations
}

// SpaceMatch is the operation a request needs: Action (with Collection for a
// write) or Manage.
type SpaceMatch struct {
	Type       string
	Authority  string
	Skey       string
	Action     string
	Collection string
	Manage     string
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func isNSID(v string) bool {
	_, err := syntax.ParseNSID(v)
	return err == nil
}

func validSpaceType(v string) bool { return v == "*" || isNSID(v) }

func validSpaceAuthority(v string) bool {
	if v == "*" || v == "self" {
		return true
	}
	_, err := syntax.ParseDID(v)
	return err == nil
}

func validSpaceKey(v string) bool {
	if v == "*" {
		return true
	}
	_, err := syntax.ParseRecordKey(v)
	return err == nil
}

// IsScopeFor reports whether a scope string belongs to a resource prefix.
func isScopeFor(scope, prefix string) bool {
	return scope == prefix || strings.HasPrefix(scope, prefix+":") || strings.HasPrefix(scope, prefix+"?")
}

// ParseSpacePermission parses a `space:` scope, returning nil when it is not
// one or is invalid.
func ParseSpacePermission(scope string) *SpacePermission {
	if !isScopeFor(scope, ResourceSpace) {
		return nil
	}
	rest := scope[len(ResourceSpace):]
	var positional *string
	query := ""
	hasQuery := false
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		query, hasQuery = rest[q+1:], true
		rest = rest[:q]
	}
	if strings.HasPrefix(rest, ":") {
		p, err := url.PathUnescape(rest[1:])
		if err != nil {
			return nil
		}
		positional = &p
	}
	params := map[string][]string{}
	if hasQuery && query != "" {
		for _, pair := range strings.Split(query, "&") {
			if pair == "" {
				continue
			}
			k, v, _ := strings.Cut(pair, "=")
			dk, err1 := url.QueryUnescape(k)
			dv, err2 := url.QueryUnescape(v)
			if err1 != nil || err2 != nil {
				return nil
			}
			params[dk] = append(params[dk], dv)
		}
	}
	for k := range params {
		switch k {
		case "type", "authority", "skey", "collection", "action", "manage":
		default:
			return nil
		}
	}
	single := func(key, def string, validate func(string) bool) (string, bool) {
		v, ok := params[key]
		if !ok {
			return def, true
		}
		if len(v) != 1 || !validate(v[0]) {
			return "", false
		}
		return v[0], true
	}
	multi := func(key string, validate func(string) bool) ([]string, bool) {
		v, ok := params[key]
		if !ok {
			return nil, true
		}
		if len(v) == 0 {
			return nil, false
		}
		for _, x := range v {
			if !validate(x) {
				return nil, false
			}
		}
		return v, true
	}

	p := &SpacePermission{}
	if v, ok := params["type"]; ok {
		if positional != nil || len(v) != 1 || !validSpaceType(v[0]) {
			return nil
		}
		p.Type = v[0]
	} else if positional != nil {
		if !validSpaceType(*positional) {
			return nil
		}
		p.Type = *positional
	} else {
		return nil
	}
	var ok bool
	if p.Authority, ok = single("authority", "self", validSpaceAuthority); !ok {
		return nil
	}
	if p.Skey, ok = single("skey", "*", validSpaceKey); !ok {
		return nil
	}
	if p.Collection, ok = multi("collection", func(v string) bool { return v == "*" || isNSID(v) }); !ok {
		return nil
	}
	if p.Action, ok = multi("action", func(v string) bool { return contains(SpaceActions, v) }); !ok {
		return nil
	}
	if p.Action == nil {
		p.Action = append([]string(nil), SpaceDefaultActions...)
	}
	if p.Manage, ok = multi("manage", func(v string) bool { return contains(SpaceManageOps, v) }); !ok {
		return nil
	}
	return p
}

// Matches reports whether the grant covers an operation.
func (p *SpacePermission) Matches(t SpaceMatch) bool {
	if p.Type != "*" && p.Type != t.Type {
		return false
	}
	if p.Authority != "*" && p.Authority != t.Authority {
		return false
	}
	if p.Skey != "*" && p.Skey != t.Skey {
		return false
	}
	if t.Action == "" {
		return p.Manage != nil && contains(p.Manage, t.Manage)
	}
	switch t.Action {
	case "read":
		return contains(p.Action, "read")
	case "read_self":
		return contains(p.Action, "read") || contains(p.Action, "read_self")
	}
	if !contains(p.Action, t.Action) || p.Collection == nil {
		return false
	}
	return contains(p.Collection, "*") || contains(p.Collection, t.Collection)
}

// HasCollections reports whether the grant names write collections.
func (p *SpacePermission) HasCollections() bool { return p.Collection != nil }

// IsSelfAuthority reports whether the authority is the unresolved "self".
func (p *SpacePermission) IsSelfAuthority() bool { return p.Authority == "self" }

// WithDefaultCollections materializes a space type's declared collections
// into a grant that names none.
func (p *SpacePermission) WithDefaultCollections(collections []string) *SpacePermission {
	if p.HasCollections() || len(collections) == 0 {
		return p
	}
	c := *p
	c.Collection = append([]string(nil), collections...)
	return &c
}

// WithResolvedAuthority resolves a "self" authority to the user's DID.
func (p *SpacePermission) WithResolvedAuthority(did string) *SpacePermission {
	if p.Authority != "self" {
		return p
	}
	c := *p
	c.Authority = did
	return &c
}

func filterCanonical(canon, values []string) []string {
	var out []string
	for _, c := range canon {
		if contains(values, c) {
			out = append(out, c)
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !contains(a, x) {
			return false
		}
	}
	return true
}

// String formats the grant canonically, leaving out defaults.
func (p *SpacePermission) String() string {
	type kv struct{ k, v string }
	var params []kv
	if p.Authority != "self" {
		params = append(params, kv{"authority", p.Authority})
	}
	if p.Skey != "*" {
		params = append(params, kv{"skey", p.Skey})
	}
	if p.Collection != nil {
		coll := p.Collection
		if len(coll) > 1 {
			if contains(coll, "*") {
				coll = []string{"*"}
			} else {
				coll = dedupe(coll)
				sort.Strings(coll)
			}
		}
		for _, c := range dedupe(coll) {
			params = append(params, kv{"collection", c})
		}
	}
	if actions := filterCanonical(SpaceActions, p.Action); !sameSet(actions, SpaceDefaultActions) {
		for _, a := range actions {
			params = append(params, kv{"action", a})
		}
	}
	if p.Manage != nil {
		for _, m := range filterCanonical(SpaceManageOps, p.Manage) {
			params = append(params, kv{"manage", m})
		}
	}
	out := ResourceSpace + ":" + normalizeScopeComponent(encodeURIComponent(p.Type))
	if len(params) > 0 {
		parts := make([]string, len(params))
		for i, x := range params {
			parts[i] = formEncode(x.k) + "=" + formEncode(x.v)
		}
		out += "?" + normalizeScopeComponent(strings.Join(parts, "&"))
	}
	return out
}

func dedupe(v []string) []string {
	var out []string
	for _, x := range v {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// SpaceScopeNeededFor is the narrowest grant that covers an operation, for an
// insufficient-scope error.
func SpaceScopeNeededFor(t SpaceMatch) string {
	p := &SpacePermission{Type: t.Type, Authority: t.Authority, Skey: t.Skey}
	if t.Manage != "" {
		p.Action = []string{"read_self"}
		p.Manage = []string{t.Manage}
	} else {
		p.Action = []string{t.Action}
		if t.Action != "read" && t.Action != "read_self" {
			p.Collection = []string{t.Collection}
		}
	}
	return p.String()
}

const upperHex = "0123456789ABCDEF"

func percentEncode(s string, keep func(byte) bool, spacePlus bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case keep(c):
			b.WriteByte(c)
		case c == ' ' && spacePlus:
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&15])
		}
	}
	return b.String()
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// encodeURIComponent matches JavaScript's.
func encodeURIComponent(s string) string {
	return percentEncode(s, func(c byte) bool { return isAlnum(c) || strings.IndexByte("-_.!~*'()", c) >= 0 }, false)
}

// formEncode matches URLSearchParams serialization.
func formEncode(s string) string {
	return percentEncode(s, func(c byte) bool { return isAlnum(c) || strings.IndexByte("*-._", c) >= 0 }, true)
}

var scopeNormalizer = strings.NewReplacer("%3A", ":", "%2F", "/", "%2B", "+", "%2C", ",", "%40", "@", "%25", "%")

// normalizeScopeComponent leaves the characters scopes allow unencoded.
func normalizeScopeComponent(s string) string { return scopeNormalizer.Replace(s) }
