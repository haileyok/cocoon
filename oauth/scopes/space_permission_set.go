package scopes

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// SpacePermissionSetResolver resolves the space permissions an include:
// permission set grants. Permission sets may hold space permissions
// ({"resource": "space", "spaceType": ..., "authority", "skey", "collection",
// "action", "manage"}), which indigo's permission-set schema doesn't model.
type SpacePermissionSetResolver interface {
	ResolveSpacePermissions(ctx context.Context, nsid string) ([]*SpacePermission, error)
}

// ResolveSpacePermissions resolves a permission set's space permissions.
func (r *IndigoResolver) ResolveSpacePermissions(ctx context.Context, nsidStr string) ([]*SpacePermission, error) {
	key := "set:" + nsidStr
	r.mu.Lock()
	if e, ok := r.spaceCache[key]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.permissions, e.err
	}
	r.mu.Unlock()

	perms, err := r.resolveSpacePermissions(ctx, nsidStr)
	ttl := r.posTTL
	if err != nil {
		ttl = r.negTTL
	}
	r.mu.Lock()
	if r.spaceCache == nil {
		r.spaceCache = map[string]spaceCacheEntry{}
	}
	r.spaceCache[key] = spaceCacheEntry{permissions: perms, err: err, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
	return perms, err
}

func (r *IndigoResolver) resolveSpacePermissions(ctx context.Context, nsidStr string) ([]*SpacePermission, error) {
	nsid, err := syntax.ParseNSID(nsidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid nsid %q: %w", nsidStr, err)
	}
	data, err := lexicon.ResolveLexiconData(ctx, r.dir, nsid)
	if err != nil {
		return nil, fmt.Errorf("could not resolve permission set %q: %w", nsidStr, err)
	}
	return SpacePermissionsFromLexicon(nsidStr, data)
}

// SpacePermissionsFromLexicon reads the space permissions of a permission
// set lexicon document, as the reference's IncludeScope does: each becomes a
// space: grant, and only space types under the set's own NSID authority are
// kept. Invalid entries are skipped.
func SpacePermissionsFromLexicon(setNsid string, doc map[string]any) ([]*SpacePermission, error) {
	defs, _ := doc["defs"].(map[string]any)
	main, _ := defs["main"].(map[string]any)
	if main == nil || main["type"] != "permission-set" {
		return nil, fmt.Errorf("lexicon %q is not a permission set", setNsid)
	}
	raw, _ := main["permissions"].([]any)
	var out []*SpacePermission
	for _, item := range raw {
		perm, _ := item.(map[string]any)
		if perm == nil || perm["resource"] != "space" {
			continue
		}
		p := spacePermissionFromLex(perm)
		if p == nil || !isUnderAuthority(setNsid, p.Type) {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func spacePermissionFromLex(perm map[string]any) *SpacePermission {
	typ, _ := perm["spaceType"].(string)
	if typ == "" {
		return nil
	}
	q := url.Values{}
	for _, k := range []string{"authority", "skey"} {
		if v, ok := perm[k]; ok {
			s, ok := v.(string)
			if !ok {
				return nil
			}
			q.Set(k, s)
		}
	}
	for _, k := range []string{"collection", "action", "manage"} {
		v, ok := perm[k]
		if !ok {
			continue
		}
		arr, ok := v.([]any)
		if !ok {
			return nil
		}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok {
				return nil
			}
			q.Add(k, s)
		}
	}
	scope := ResourceSpace + ":" + typ
	if len(q) > 0 {
		scope += "?" + q.Encode()
	}
	return ParseSpacePermission(scope)
}

// isUnderAuthority reports whether nsid shares the authority (everything up
// to the last dot) of setNsid.
func isUnderAuthority(setNsid, nsid string) bool {
	i := strings.LastIndexByte(setNsid, '.')
	if i < 0 || nsid == "*" || len(nsid) <= i+1 {
		return false
	}
	return nsid[:i+1] == setNsid[:i+1]
}
