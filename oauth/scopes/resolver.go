package scopes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// PermissionSetResolver resolves an `include:<nsid>` scope to its permission-set
// lexicon. ResolvePermissionSet returns the parsed permission-set when the NSID
// resolves to a valid permission-set record, or an error otherwise.
type PermissionSetResolver interface {
	ResolvePermissionSet(ctx context.Context, nsid string) (*lexicon.SchemaPermissionSet, error)
}

// PermissionSetScopeResolver optionally materializes a permission set into
// OAuth scope strings. It is separate from PermissionSetResolver because older
// resolver implementations may parse only the repo/rpc permission fields.
type PermissionSetScopeResolver interface {
	ResolvePermissionSetScopes(ctx context.Context, nsid string) ([]string, error)
}

// directory is the subset of indigo's identity.Directory used here.
type directory = identity.Directory

type cacheEntry struct {
	ps      *lexicon.SchemaPermissionSet
	err     error
	expires time.Time
}

// IndigoResolver resolves permission sets using indigo's lexicon resolution
// (DNS TXT `_lexicon.<authority>` -> DID -> `com.atproto.lexicon.schema`
// record), with a small in-memory TTL cache for both positive and negative
// results.
type IndigoResolver struct {
	dir directory

	posTTL time.Duration
	negTTL time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewIndigoResolver builds a resolver backed by the default identity directory.
func NewIndigoResolver() *IndigoResolver {
	return NewIndigoResolverWithDirectory(identity.DefaultDirectory())
}

// NewIndigoResolverWithDirectory builds a resolver using the supplied directory.
func NewIndigoResolverWithDirectory(dir directory) *IndigoResolver {
	return &IndigoResolver{
		dir:    dir,
		posTTL: time.Hour,
		negTTL: time.Minute,
		cache:  map[string]cacheEntry{},
	}
}

func (r *IndigoResolver) ResolvePermissionSet(ctx context.Context, nsidStr string) (*lexicon.SchemaPermissionSet, error) {
	if cached, ok := r.lookup(nsidStr); ok {
		return cached.ps, cached.err
	}

	ps, err := r.resolve(ctx, nsidStr)
	r.store(nsidStr, ps, err)
	return ps, err
}

// ResolvePermissionSetScopes materializes all supported permissions in a
// permission-set lexicon. The generic Indigo SchemaPermission type predates the
// Spaces permission fields and silently drops them during JSON unmarshalling,
// so this path reads the resolved lexicon data into a local wire-shape instead.
func (r *IndigoResolver) ResolvePermissionSetScopes(ctx context.Context, nsidStr string) ([]string, error) {
	nsid, err := syntax.ParseNSID(nsidStr)
	if err != nil || string(nsid) != nsidStr {
		return nil, fmt.Errorf("invalid permission set %q", nsidStr)
	}
	data, err := lexicon.ResolveLexiconData(ctx, r.dir, nsid)
	if err != nil {
		return nil, fmt.Errorf("could not resolve permission set %q: %w", nsidStr, err)
	}
	return expandPermissionSetScopes(data, nsidStr)
}

type rawPermissionSet struct {
	Lexicon int                        `json:"lexicon"`
	ID      string                     `json:"id"`
	Defs    map[string]json.RawMessage `json:"defs"`
}

type rawPermission struct {
	Type       string   `json:"type"`
	Resource   string   `json:"resource"`
	Collection []string `json:"collection"`
	Action     []string `json:"action"`
	LXM        []string `json:"lxm"`
	Audience   string   `json:"aud"`
	InheritAud bool     `json:"inheritAud"`

	SpaceType string   `json:"spaceType"`
	Authority string   `json:"authority"`
	SKey      string   `json:"skey"`
	Manage    []string `json:"manage"`
}

func expandPermissionSetScopes(data map[string]any, nsid string) ([]string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode permission set %q: %w", nsid, err)
	}
	var document rawPermissionSet
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("decode permission set %q: %w", nsid, err)
	}
	if document.Lexicon != 1 || document.ID != nsid || document.Defs == nil {
		return nil, fmt.Errorf("invalid permission set identity for %q", nsid)
	}
	mainRaw, ok := document.Defs["main"]
	if !ok {
		return nil, fmt.Errorf("permission set %q has no main definition", nsid)
	}
	var main struct {
		Type        string          `json:"type"`
		Permissions []rawPermission `json:"permissions"`
	}
	if err := json.Unmarshal(mainRaw, &main); err != nil {
		return nil, fmt.Errorf("decode permission set %q main definition: %w", nsid, err)
	}
	if main.Type != "permission-set" {
		return nil, fmt.Errorf("permission set %q has invalid main definition", nsid)
	}

	var out []string
	for _, permission := range main.Permissions {
		scopes, err := rawPermissionScopes(permission, nsid)
		if err != nil {
			return nil, err
		}
		out = append(out, scopes...)
	}
	return out, nil
}

func rawPermissionScopes(permission rawPermission, permissionSetNSID string) ([]string, error) {
	if permission.Type != "permission" {
		return nil, fmt.Errorf("permission set %q contains an invalid permission entry", permissionSetNSID)
	}
	switch permission.Resource {
	case "repo":
		var out []string
		for _, collection := range permission.Collection {
			if len(permission.Action) == 0 {
				out = append(out, "repo:"+collection)
				continue
			}
			for _, action := range permission.Action {
				out = append(out, "repo:"+collection+"?action="+action)
			}
		}
		return out, nil
	case "rpc":
		var out []string
		for _, lxm := range permission.LXM {
			audience := permission.Audience
			if audience == "" {
				audience = "*"
			}
			out = append(out, "rpc:"+lxm+"?aud="+audience)
		}
		return out, nil
	case "space":
		if permission.SpaceType == "" || !permissionSetContains(permissionSetNSID, permission.SpaceType) {
			return nil, fmt.Errorf("space permission in %q has invalid space type %q", permissionSetNSID, permission.SpaceType)
		}
		params := url.Values{}
		if permission.Authority != "" {
			params.Set("authority", permission.Authority)
		}
		if permission.SKey != "" {
			params.Set("skey", permission.SKey)
		}
		for _, collection := range permission.Collection {
			params.Add("collection", collection)
		}
		for _, action := range permission.Action {
			params.Add("action", action)
		}
		for _, manage := range permission.Manage {
			params.Add("manage", manage)
		}
		scope := "space:" + permission.SpaceType
		if encoded := params.Encode(); encoded != "" {
			scope += "?" + encoded
		}
		if _, err := Parse(scope); err != nil {
			return nil, fmt.Errorf("space permission in %q is invalid: %w", permissionSetNSID, err)
		}
		return []string{scope}, nil
	default:
		// Permission sets may contain resources that this server does not yet
		// materialize. Match the reference behavior by ignoring those entries.
		return nil, nil
	}
}

func permissionSetContains(permissionSetNSID, target string) bool {
	if target == "" || target == "*" {
		return false
	}
	dot := strings.LastIndexByte(permissionSetNSID, '.')
	if dot < 0 || len(target) <= dot+1 {
		return false
	}
	return strings.HasPrefix(target, permissionSetNSID[:dot+1])
}

func (r *IndigoResolver) resolve(ctx context.Context, nsidStr string) (*lexicon.SchemaPermissionSet, error) {
	nsid, err := syntax.ParseNSID(nsidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid nsid %q: %w", nsidStr, err)
	}

	sf, err := lexicon.ResolveLexiconSchemaFile(ctx, r.dir, nsid)
	if err != nil {
		return nil, fmt.Errorf("could not resolve permission set %q: %w", nsidStr, err)
	}

	main, ok := sf.Defs["main"]
	if !ok {
		return nil, fmt.Errorf("lexicon %q has no main definition", nsidStr)
	}
	ps, ok := main.Inner.(lexicon.SchemaPermissionSet)
	if !ok {
		return nil, fmt.Errorf("lexicon %q main definition is not a permission-set", nsidStr)
	}
	return &ps, nil
}

func (r *IndigoResolver) lookup(nsid string) (cacheEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[nsid]
	if !ok || time.Now().After(entry.expires) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (r *IndigoResolver) store(nsid string, ps *lexicon.SchemaPermissionSet, err error) {
	ttl := r.posTTL
	if err != nil {
		ttl = r.negTTL
	}
	r.mu.Lock()
	r.cache[nsid] = cacheEntry{ps: ps, err: err, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
}

// SpaceTypeSchemaSource returns the raw Lexicon schema for a space type. The
// raw form is intentional: the pinned Indigo version has no SchemaSpace type.
type SpaceTypeSchemaSource func(context.Context, string) ([]byte, error)

// RawSpaceTypeResolver is a bounded, fail-closed resolver for omitted
// collection grants. A declaration is valid only when its main definition is
// the pinned `space` object with a bounded, non-empty collections array.
type RawSpaceTypeResolver struct {
	source SpaceTypeSchemaSource
	posTTL time.Duration
	negTTL time.Duration
	mu     sync.Mutex
	cache  map[string]spaceTypeCacheEntry
}

type spaceTypeCacheEntry struct {
	declaration SpaceTypeDeclaration
	err         error
	expires     time.Time
}

func NewRawSpaceTypeResolver(source SpaceTypeSchemaSource) *RawSpaceTypeResolver {
	return &RawSpaceTypeResolver{source: source, posTTL: time.Hour, negTTL: time.Minute, cache: map[string]spaceTypeCacheEntry{}}
}

// NewIndigoSpaceTypeResolver resolves schemas with Indigo's generic resolver
// and parses the pinned raw declaration shape locally.
func NewIndigoSpaceTypeResolver() *RawSpaceTypeResolver {
	return NewRawSpaceTypeResolver(func(ctx context.Context, nsidString string) ([]byte, error) {
		nsid, err := syntax.ParseNSID(nsidString)
		if err != nil || string(nsid) != nsidString {
			return nil, fmt.Errorf("invalid space type %q", nsidString)
		}
		data, err := lexicon.ResolveLexiconData(ctx, identity.DefaultDirectory(), nsid)
		if err != nil {
			return nil, err
		}
		return json.Marshal(data)
	})
}

func (r *RawSpaceTypeResolver) ResolveSpaceType(spaceType string) (SpaceTypeDeclaration, error) {
	if r == nil || r.source == nil {
		return SpaceTypeDeclaration{}, fmt.Errorf("space type resolver is unavailable")
	}
	if entry, ok := r.lookupSpaceType(spaceType); ok {
		return entry.declaration, entry.err
	}
	declaration, err := r.resolveSpaceType(spaceType)
	ttl := r.posTTL
	if err != nil {
		ttl = r.negTTL
	}
	r.mu.Lock()
	r.cache[spaceType] = spaceTypeCacheEntry{declaration: declaration, err: err, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
	return declaration, err
}

func (r *RawSpaceTypeResolver) resolveSpaceType(spaceType string) (SpaceTypeDeclaration, error) {
	nsid, err := syntax.ParseNSID(spaceType)
	if err != nil || string(nsid) != spaceType {
		return SpaceTypeDeclaration{}, fmt.Errorf("invalid space type %q", spaceType)
	}
	raw, err := r.source(context.Background(), spaceType)
	if err != nil {
		return SpaceTypeDeclaration{}, fmt.Errorf("could not resolve space type %q: %w", spaceType, err)
	}
	var document struct {
		Lexicon int                        `json:"lexicon"`
		ID      string                     `json:"id"`
		Defs    map[string]json.RawMessage `json:"defs"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return SpaceTypeDeclaration{}, fmt.Errorf("invalid space type declaration: %w", err)
	}
	if document.Lexicon != 1 || document.ID != spaceType || document.Defs == nil {
		return SpaceTypeDeclaration{}, fmt.Errorf("invalid space type declaration identity")
	}
	mainRaw, ok := document.Defs["main"]
	if !ok {
		return SpaceTypeDeclaration{}, fmt.Errorf("space type declaration has no main definition")
	}
	var main struct {
		Type        string   `json:"type"`
		Key         string   `json:"key"`
		Name        string   `json:"name"`
		Collections []string `json:"collections"`
	}
	if err := json.Unmarshal(mainRaw, &main); err != nil {
		return SpaceTypeDeclaration{}, fmt.Errorf("invalid space type main definition: %w", err)
	}
	if main.Type != "space" || main.Key == "" || main.Name == "" || len(main.Name) > 64 || main.Collections == nil || len(main.Collections) == 0 || len(main.Collections) > 256 {
		return SpaceTypeDeclaration{}, fmt.Errorf("invalid space type main definition")
	}
	collections := make([]string, len(main.Collections))
	seen := make(map[string]bool, len(main.Collections))
	for i, collection := range main.Collections {
		parsed, parseErr := syntax.ParseNSID(collection)
		if parseErr != nil || string(parsed) != collection || seen[collection] {
			return SpaceTypeDeclaration{}, fmt.Errorf("space type declaration contains invalid collection")
		}
		seen[collection] = true
		collections[i] = collection
	}
	return SpaceTypeDeclaration{Collections: collections}, nil
}

func (r *RawSpaceTypeResolver) lookupSpaceType(spaceType string) (spaceTypeCacheEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[spaceType]
	if !ok || time.Now().After(entry.expires) {
		return spaceTypeCacheEntry{}, false
	}
	return entry, true
}
