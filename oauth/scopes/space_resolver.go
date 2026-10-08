package scopes

import (
	"context"
	"fmt"
	"time"

	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// SpaceTypeResolver resolves a space type NSID to the collections its
// lexicon declaration ({"type": "space", "collections": [...]}) names.
type SpaceTypeResolver interface {
	ResolveSpaceCollections(ctx context.Context, nsid string) ([]string, error)
}

// ResolveSpaceCollections resolves a space type's declared collections.
func (r *IndigoResolver) ResolveSpaceCollections(ctx context.Context, nsidStr string) ([]string, error) {
	key := "space:" + nsidStr
	r.mu.Lock()
	if e, ok := r.spaceCache[key]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.collections, e.err
	}
	r.mu.Unlock()

	cols, err := r.resolveSpace(ctx, nsidStr)
	ttl := r.posTTL
	if err != nil {
		ttl = r.negTTL
	}
	r.mu.Lock()
	if r.spaceCache == nil {
		r.spaceCache = map[string]spaceCacheEntry{}
	}
	r.spaceCache[key] = spaceCacheEntry{collections: cols, err: err, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
	return cols, err
}

type spaceCacheEntry struct {
	collections []string
	permissions []*SpacePermission
	err         error
	expires     time.Time
}

func (r *IndigoResolver) resolveSpace(ctx context.Context, nsidStr string) ([]string, error) {
	nsid, err := syntax.ParseNSID(nsidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid nsid %q: %w", nsidStr, err)
	}
	data, err := lexicon.ResolveLexiconData(ctx, r.dir, nsid)
	if err != nil {
		return nil, fmt.Errorf("could not resolve space type %q: %w", nsidStr, err)
	}
	return SpaceCollectionsFromLexicon(data)
}

// SpaceCollectionsFromLexicon reads the declared collections of a space type
// lexicon document.
func SpaceCollectionsFromLexicon(doc map[string]any) ([]string, error) {
	defs, _ := doc["defs"].(map[string]any)
	main, _ := defs["main"].(map[string]any)
	if main == nil || main["type"] != "space" {
		return nil, fmt.Errorf("lexicon document is not a space type")
	}
	raw, _ := main["collections"].([]any)
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		s, ok := c.(string)
		if !ok {
			return nil, fmt.Errorf("space type collections must be NSIDs")
		}
		if _, err := syntax.ParseNSID(s); err != nil {
			return nil, fmt.Errorf("space type collection %q is not an NSID", s)
		}
		out = append(out, s)
	}
	return out, nil
}

// ExpandSpaceCollections rewrites bare space:<type> grants to carry the
// type's declared collections, as the reference's token issuance does. A
// declaration that can't be resolved leaves the grant as it is: with no
// collections it permits no writes, a narrower grant than consented to.
func ExpandSpaceCollections(ctx context.Context, r SpaceTypeResolver, grants []string) []string {
	out := make([]string, len(grants))
	for i, g := range grants {
		out[i] = g
		p := ParseSpacePermission(g)
		if r == nil || p == nil || p.Type == "*" || p.HasCollections() {
			continue
		}
		cols, err := r.ResolveSpaceCollections(ctx, p.Type)
		if err != nil || len(cols) == 0 {
			continue
		}
		out[i] = p.WithDefaultCollections(cols).String()
	}
	return out
}
