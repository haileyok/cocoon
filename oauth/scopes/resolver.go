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
// lexicon. ResolvePermissionSet returns nil when the NSID resolves to a valid
// permission-set record, or an error otherwise.
type PermissionSetResolver interface {
	ResolvePermissionSet(ctx context.Context, nsid string) error
}

// directory is the subset of indigo's identity.Directory used here.
type directory = identity.Directory

type cacheEntry struct {
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

func (r *IndigoResolver) ResolvePermissionSet(ctx context.Context, nsidStr string) error {
	if cached, ok := r.lookup(nsidStr); ok {
		return cached
	}

	err := r.resolve(ctx, nsidStr)
	r.store(nsidStr, err)
	return err
}

func (r *IndigoResolver) resolve(ctx context.Context, nsidStr string) error {
	nsid, err := syntax.ParseNSID(nsidStr)
	if err != nil {
		return fmt.Errorf("invalid nsid %q: %w", nsidStr, err)
	}

	sf, err := lexicon.ResolveLexiconSchemaFile(ctx, r.dir, nsid)
	if err != nil {
		return fmt.Errorf("could not resolve permission set %q: %w", nsidStr, err)
	}

	main, ok := sf.Defs["main"]
	if !ok {
		return fmt.Errorf("lexicon %q has no main definition", nsidStr)
	}
	if _, ok := main.Inner.(lexicon.SchemaPermissionSet); !ok {
		return fmt.Errorf("lexicon %q main definition is not a permission-set", nsidStr)
	}
	return nil
}

func (r *IndigoResolver) lookup(nsid string) (error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[nsid]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.err, true
}

func (r *IndigoResolver) store(nsid string, err error) {
	ttl := r.posTTL
	if err != nil {
		ttl = r.negTTL
	}
	r.mu.Lock()
	r.cache[nsid] = cacheEntry{err: err, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
}
