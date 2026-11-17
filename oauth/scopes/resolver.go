package scopes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/gttp"
	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
)

// PermissionSetResolver resolves an `include:<nsid>` scope to its permission-set
// lexicon. ResolvePermissionSet returns the parsed permission-set when the NSID
// resolves to a valid permission-set record, or an error otherwise.
type PermissionSetResolver interface {
	ResolvePermissionSet(ctx context.Context, nsid string) (*lexicon.SchemaPermissionSet, error)
}

// LocalLexiconReader reads committed CBOR from a trusted local actor store.
// hosted=false, err=nil is the only result that permits remote resolution.
// Missing/unavailable local records and database failures must return errors.
type LocalLexiconReader func(context.Context, syntax.DID, syntax.NSID) (record []byte, hosted bool, err error)

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
	dir         directory
	dns         identity.BaseDirectory
	httpClient  *http.Client
	localReader LocalLexiconReader

	posTTL time.Duration
	negTTL time.Duration

	mu         sync.Mutex
	cache      map[string]cacheEntry
	spaceCache map[string]spaceCacheEntry
}

// SetLocalLexiconReader installs the local actor-store hook during startup,
// before the resolver is first used. DNS still determines the NSID authority.
func (r *IndigoResolver) SetLocalLexiconReader(reader LocalLexiconReader) {
	r.localReader = reader
}

// NewIndigoResolver builds a resolver with guarded identity and record fetching.
func NewIndigoResolver() *IndigoResolver {
	return NewIndigoResolverWithPLCURL("")
}

// NewIndigoResolverWithPLCURL builds a resolver backed by indigo's default
// identity directory configuration, but resolving did:plc identities against
// plcURL. An empty plcURL uses indigo's default PLC directory. An explicitly
// configured directory is trusted for direct DID-document fetches only.
func NewIndigoResolverWithPLCURL(plcURL string) *IndigoResolver {
	dir := identity.DefaultDirectory().(*identity.CacheDirectory)
	base := dir.Inner.(*identity.BaseDirectory)
	if plcURL != "" {
		base.PLCURL = strings.TrimRight(plcURL, "/")
	}
	base.HTTPClient = *newLexiconHTTPClient(plcURL, gttp.WithNoRedirects())
	return NewIndigoResolverWithDirectory(dir)
}

// NewIndigoResolverWithDirectory uses a caller-controlled identity directory.
// Record fetching remains guarded even when the directory is supplied.
func NewIndigoResolverWithDirectory(dir directory) *IndigoResolver {
	return &IndigoResolver{
		dir:        dir,
		httpClient: newLexiconHTTPClient(""),
		posTTL:     time.Hour,
		negTTL:     time.Minute,
		cache:      map[string]cacheEntry{},
	}
}

func newLexiconHTTPClient(plcURL string, opts ...gttp.Option) *http.Client {
	client := gttp.New(append(opts,
		gttp.WithStrictSSRFProtection(), gttp.WithNoProxy(), gttp.WithNoRetries(),
		gttp.WithTimeout(10*time.Second),
		gttp.WithMaxResponseBodyBytes(helpers.SafeFetchClientMaxBodyBytes),
	)...)
	transport := &lexiconTransport{public: client.Transport, plcURL: strings.TrimRight(plcURL, "/")}
	if plcURL != "" {
		// Only the operator-configured PLC directory may use a private endpoint.
		// Its redirects must never inherit this exception.
		transport.plc = gttp.New(gttp.WithNoRedirects(), gttp.WithNoProxy(), gttp.WithNoRetries(),
			gttp.WithTimeout(10*time.Second), gttp.WithMaxResponseBodyBytes(helpers.SafeFetchClientMaxBodyBytes))
	}
	client.Transport = transport
	return client
}

type lexiconTransport struct {
	public http.RoundTripper
	plcURL string
	plc    *http.Client
}

func (t *lexiconTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.plc != nil {
		if suffix, ok := strings.CutPrefix(req.URL.String(), t.plcURL+"/"); ok && !strings.Contains(suffix, "%") {
			if did, err := syntax.ParseDID(suffix); err == nil && did.Method() == "plc" {
				return t.plc.Do(req)
			}
		}
	}
	// Enforce the reference's public fetch URL policy on every actual request,
	// including redirects. gttp separately binds IP checks to DNS resolution/dial.
	// ParseAddr also recognizes zoned IPv6 literals, unlike net.ParseIP.
	_, ipErr := netip.ParseAddr(req.URL.Hostname())
	if req.URL.Scheme != "https" || (req.URL.Port() != "" && req.URL.Port() != "443") || ipErr == nil {
		return nil, fmt.Errorf("lexicon fetch requires HTTPS on port 443 with a DNS hostname")
	}
	return t.public.RoundTrip(req)
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

	record, err := r.fetchLexicon(ctx, nsid)
	if err != nil {
		return nil, fmt.Errorf("could not resolve permission set %q: %w", nsidStr, err)
	}
	var sf lexicon.SchemaFile
	if err := json.Unmarshal(record, &sf); err != nil {
		return nil, fmt.Errorf("invalid lexicon %q: %w", nsidStr, err)
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

// fetchLexicon keeps the HTTP client under the resolver's control; Indigo's
// ResolveLexiconData/SchemaFile helpers construct an http.DefaultClient caller.
func (r *IndigoResolver) fetchLexicon(ctx context.Context, nsid syntax.NSID) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	did, err := r.dns.ResolveNSID(ctx, nsid)
	if err != nil {
		return nil, err
	}
	if r.localReader != nil {
		record, hosted, err := r.localReader(ctx, did, nsid)
		if err != nil {
			return nil, fmt.Errorf("local lexicon: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if hosted {
			return parseLexiconRecord(record, nsid)
		}
	}
	ident, err := r.dir.LookupDID(ctx, did)
	if err != nil {
		return nil, err
	}
	if ident == nil || ident.DID != did {
		return nil, fmt.Errorf("lexicon authority identity does not match %s", did)
	}
	client := atclient.NewAPIClient(ident.PDSEndpoint())
	client.Client = r.httpClient
	req := atclient.NewAPIRequest(http.MethodGet, "com.atproto.sync.getRecord", nil)
	req.QueryParams.Set("collection", "com.atproto.lexicon.schema")
	req.QueryParams.Set("did", did.String())
	req.QueryParams.Set("rkey", nsid.String())
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Read the guarded body before decoding: json.Decoder can accept a complete
	// value while ignoring a size-limit error returned with its final bytes.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading lexicon response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var failure atclient.ErrorBody
		if err := json.Unmarshal(body, &failure); err != nil {
			return nil, &atclient.APIError{StatusCode: resp.StatusCode}
		}
		return nil, failure.APIError(resp.StatusCode)
	}
	record, err := verifyLexiconProof(ctx, body, ident, nsid)
	if err != nil {
		return nil, fmt.Errorf("invalid lexicon proof: %w", err)
	}
	return record, nil
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
