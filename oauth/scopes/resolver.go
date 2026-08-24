package scopes

import (
	"context"
	"encoding/json"
	"fmt"
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
