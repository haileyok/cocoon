package scopes

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
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
	record, err := r.fetchLexicon(ctx, nsid)
	if err != nil {
		return nil, fmt.Errorf("could not resolve space type %q: %w", nsidStr, err)
	}
	data, err := atdata.UnmarshalJSON(record)
	if err != nil {
		return nil, fmt.Errorf("invalid lexicon %q: %w", nsidStr, err)
	}
	return SpaceCollectionsFromLexicon(data)
}

// SpaceDeclaration is a validated space type declaration: the defs.main of a
// lexicon document with "type": "space".
type SpaceDeclaration struct {
	// Key is the recommended space key type: any, nsid, tid or literal:<key>.
	Key string
	// Title is the human-readable title the consent screen shows (1-64
	// bytes), empty when the declaration has none, in which case the consent
	// screen shows the type's NSID.
	Title string
	// TitleLang holds localized titles by language tag.
	TitleLang map[string]string
	// Description is for developers and is never shown to users.
	Description string
	// Collections are the default collections of a bare space: grant.
	Collections []string
}

// maxSpaceTitleLen is the longest a declaration's title may be, in UTF-8 bytes
// (the lexicon string length unit).
const maxSpaceTitleLen = 64

// ParseSpaceDeclaration validates a lexicon document's main definition against
// the space declaration schema the reference PDS applies: key and collections
// are required, title is optional and 1 to 64 bytes, title:lang maps language
// tags to strings, and collections lists NSIDs (never a wildcard).
func ParseSpaceDeclaration(doc map[string]any) (*SpaceDeclaration, error) {
	defs, _ := doc["defs"].(map[string]any)
	main, _ := defs["main"].(map[string]any)
	if main == nil || main["type"] != "space" {
		return nil, fmt.Errorf("lexicon document is not a space type")
	}

	key, ok := main["key"].(string)
	if !ok {
		return nil, fmt.Errorf("space type is missing its key")
	}
	if !validSpaceKeyType(key) {
		return nil, fmt.Errorf("space type key %q must be any, nsid, tid or literal:<key>", key)
	}

	var title string
	if raw, present := main["title"]; present {
		t, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("space type title must be a string")
		}
		if n := len(t); n < 1 || n > maxSpaceTitleLen {
			return nil, fmt.Errorf("space type title must be 1 to %d bytes, got %d", maxSpaceTitleLen, n)
		}
		title = t
	}

	var titleLang map[string]string
	if raw, present := main["title:lang"]; present {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("space type title:lang must map language tags to titles")
		}
		titleLang = make(map[string]string, len(m))
		for lang, v := range m {
			if _, err := syntax.ParseLanguage(lang); err != nil {
				return nil, fmt.Errorf("space type title:lang key %q is not a language tag", lang)
			}
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("space type title:lang value for %q must be a string", lang)
			}
			titleLang[lang] = s
		}
	}

	var description string
	if raw, present := main["description"]; present {
		d, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("space type description must be a string")
		}
		description = d
	}

	rawCols, present := main["collections"]
	if !present {
		return nil, fmt.Errorf("space type is missing its collections")
	}
	list, ok := rawCols.([]any)
	if !ok {
		return nil, fmt.Errorf("space type collections must be an array of NSIDs")
	}
	cols := make([]string, 0, len(list))
	for _, c := range list {
		s, ok := c.(string)
		if !ok {
			return nil, fmt.Errorf("space type collections must be NSIDs")
		}
		if _, err := syntax.ParseNSID(s); err != nil {
			return nil, fmt.Errorf("space type collection %q is not an NSID", s)
		}
		cols = append(cols, s)
	}

	return &SpaceDeclaration{Key: key, Title: title, TitleLang: titleLang, Description: description, Collections: cols}, nil
}

// validSpaceKeyType reports whether key is a lexicon record key type.
func validSpaceKeyType(key string) bool {
	switch key {
	case "any", "nsid", "tid":
		return true
	}
	lit, ok := strings.CutPrefix(key, "literal:")
	if !ok || lit == "" {
		return false
	}
	_, err := syntax.ParseRecordKey(lit)
	return err == nil
}

// SpaceCollectionsFromLexicon reads the declared collections of a space type
// lexicon document, after validating the whole declaration.
func SpaceCollectionsFromLexicon(doc map[string]any) ([]string, error) {
	d, err := ParseSpaceDeclaration(doc)
	if err != nil {
		return nil, err
	}
	return d.Collections, nil
}

// ExpandSpaceCollections rewrites bare space:<type> grants to carry the
// type's declared collections, as the reference's token issuance does.
//
// A bare grant whose declaration can't be resolved is returned as it is, which
// permits no writes, a narrower grant than the user consented to. The reference
// refuses to issue such a token, so the first such failure is returned as an
// error alongside the best-effort result, for callers that only display the
// grants and can ignore it.
func ExpandSpaceCollections(ctx context.Context, r SpaceTypeResolver, grants []string) ([]string, error) {
	var firstErr error
	out := make([]string, len(grants))
	for i, g := range grants {
		out[i] = g
		p := ParseSpacePermission(g)
		if r == nil || p == nil || p.Type == "*" || p.HasCollections() {
			continue
		}
		cols, err := r.ResolveSpaceCollections(ctx, p.Type)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("space type %q: %w", p.Type, err)
			}
			continue
		}
		if len(cols) == 0 {
			continue
		}
		out[i] = p.WithDefaultCollections(cols).String()
	}
	return out, firstErr
}
