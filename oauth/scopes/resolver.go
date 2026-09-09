package scopes

import (
	"context"
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
