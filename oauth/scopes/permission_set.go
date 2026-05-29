package scopes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/haileyok/cocoon/identity"
)

const (
	// lexiconSchemaCollection is the repo collection under which Lexicon schema
	// (and permission-set) records are published.
	lexiconSchemaCollection = "com.atproto.lexicon.schema"

	resolvePositiveTTL = 10 * time.Minute
	resolveNegativeTTL = 30 * time.Second
)

// Resolver resolves `include:<nsid>` scope references into the concrete
// permissions defined by the referenced permission-set Lexicon record. Results
// (and short-lived negatives) are cached so that scope validation and write
// enforcement do not hammer the network.
type Resolver struct {
	cli   *http.Client
	cache cache.Cache[string, cacheEntry]
}

type cacheEntry struct {
	perms  []Permission
	errMsg string
}

// NewResolver constructs a Resolver. The provided HTTP client is reused for DID
// document and record fetches; if nil, http.DefaultClient is used.
func NewResolver(cli *http.Client) *Resolver {
	if cli == nil {
		cli = http.DefaultClient
	}
	return &Resolver{
		cli:   cli,
		cache: cache.NewCache[string, cacheEntry]().WithLRU().WithMaxKeys(500).WithTTL(resolvePositiveTTL),
	}
}

// ValidateInclude reports whether nsid refers to a resolvable permission set.
// A nil return means the include is valid; a non-nil error should be surfaced
// to the client as invalid_scope.
func (r *Resolver) ValidateInclude(ctx context.Context, nsid string, params url.Values) error {
	_, err := r.Resolve(ctx, nsid, params)
	return err
}

// Resolve returns the permissions granted by the permission set referenced by
// nsid, applying include params (such as aud) where the set requests it.
func (r *Resolver) Resolve(ctx context.Context, nsid string, params url.Values) ([]Permission, error) {
	key := nsid + "\x00" + params.Get("aud")
	if entry, ok := r.cache.Get(key); ok {
		if entry.errMsg != "" {
			return nil, errors.New(entry.errMsg)
		}
		return entry.perms, nil
	}

	perms, err := r.resolve(ctx, nsid, params)

	entry := cacheEntry{perms: perms}
	ttl := resolvePositiveTTL
	if err != nil {
		entry.errMsg = err.Error()
		ttl = resolveNegativeTTL
	}
	r.cache.Set(key, entry, ttl)

	return perms, err
}

func (r *Resolver) resolve(ctx context.Context, nsid string, params url.Values) ([]Permission, error) {
	n, err := syntax.ParseNSID(nsid)
	if err != nil {
		return nil, fmt.Errorf("invalid include nsid %q: %w", nsid, err)
	}

	authority := n.Authority()
	if authority == "" {
		return nil, fmt.Errorf("could not determine authority for nsid %q", nsid)
	}

	did, err := identity.ResolveLexiconAuthority(ctx, authority)
	if err != nil {
		return nil, fmt.Errorf("could not resolve lexicon authority for %q: %w", nsid, err)
	}

	pds, err := identity.ResolveService(ctx, r.cli, did)
	if err != nil {
		return nil, fmt.Errorf("could not resolve pds for %s: %w", did, err)
	}

	rec, err := r.fetchRecord(ctx, pds, did, n.String())
	if err != nil {
		return nil, err
	}

	return permissionsFromRecord(rec, params)
}

func (r *Resolver) fetchRecord(ctx context.Context, pds, did, nsid string) (*getRecordResponse, error) {
	u := fmt.Sprintf("%s/xrpc/com.atproto.repo.getRecord?repo=%s&collection=%s&rkey=%s",
		strings.TrimRight(pds, "/"),
		url.QueryEscape(did),
		url.QueryEscape(lexiconSchemaCollection),
		url.QueryEscape(nsid),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build getRecord request: %w", err)
	}

	resp, err := r.cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch permission-set record: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("getRecord for lexicon %q returned status %d", nsid, resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read getRecord response: %w", err)
	}

	return parseRecordJSON(b)
}

// getRecordResponse is the relevant subset of a com.atproto.repo.getRecord
// response for a Lexicon schema record.
type getRecordResponse struct {
	Value lexiconDoc `json:"value"`
}

type lexiconDoc struct {
	Defs struct {
		Main permissionSetDef `json:"main"`
	} `json:"defs"`
}

type permissionSetDef struct {
	Type        string              `json:"type"`
	Permissions []permissionSetItem `json:"permissions"`
}

type permissionSetItem struct {
	Type       string   `json:"type"`
	Resource   string   `json:"resource"`
	Collection []string `json:"collection"`
	Action     []string `json:"action"`
	Accept     []string `json:"accept"`
	Lxm        []string `json:"lxm"`
	Aud        string   `json:"aud"`
	InheritAud bool     `json:"inheritAud"`
}

func parseRecordJSON(b []byte) (*getRecordResponse, error) {
	var rec getRecordResponse
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("could not decode getRecord response: %w", err)
	}
	return &rec, nil
}

// permissionsFromRecord converts a permission-set Lexicon record into the list
// of concrete permissions it grants. Unknown resource types and unknown fields
// are ignored for forward compatibility, per the permission-set spec.
func permissionsFromRecord(rec *getRecordResponse, params url.Values) ([]Permission, error) {
	main := rec.Value.Defs.Main
	if main.Type != "permission-set" {
		return nil, fmt.Errorf("record is not a permission-set (defs.main.type=%q)", main.Type)
	}

	includeAud := ""
	if params != nil {
		includeAud = params.Get("aud")
	}

	var perms []Permission
	for _, item := range main.Permissions {
		switch item.Resource {
		case "repo":
			for _, col := range item.Collection {
				p := Permission{Resource: "repo", Positional: col, Params: url.Values{}}
				for _, a := range item.Action {
					p.Params.Add("action", a)
				}
				perms = append(perms, p)
			}
		case "blob":
			p := Permission{Resource: "blob", Params: url.Values{}}
			for _, a := range item.Accept {
				p.Params.Add("accept", a)
			}
			perms = append(perms, p)
		case "rpc":
			aud := item.Aud
			if item.InheritAud {
				// Per spec: inheritAud with no include aud, or combined with an
				// explicit aud, is invalid and the permission is ignored.
				if includeAud == "" || item.Aud != "" {
					continue
				}
				aud = includeAud
			}
			for _, lxm := range item.Lxm {
				p := Permission{Resource: "rpc", Positional: lxm, Params: url.Values{}}
				if aud != "" {
					p.Params.Set("aud", aud)
				}
				perms = append(perms, p)
			}
		default:
			// Ignore unknown resource types for forward compatibility.
		}
	}

	return perms, nil
}
