package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/util"
)

// Handle resolution is a binary question for callers: a handle either resolves
// to a DID or it does not. These sentinels separate the two ways it can fail,
// because only one of them is the caller's problem: a handle nothing claims
// belongs in a 4xx, while a lookup that could not be completed is our fault and
// belongs in a 5xx.
var (
	// ErrHandleNotFound means both resolution methods answered definitively and
	// neither produced a DID: no account claims the handle.
	ErrHandleNotFound = errors.New("handle not found")

	// ErrHandleResolutionFailed means at least one resolution method could not be
	// completed (DNS failure or timeout, connection error, unexpected HTTP
	// status), so whether the handle resolves is unknown.
	ErrHandleResolutionFailed = errors.New("handle resolution failed")
)

// TXTResolver looks up the TXT records for a name. *net.Resolver implements it;
// tests substitute a fake so handle resolution never touches live DNS.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

func ResolveHandleFromTXT(ctx context.Context, handle string) (string, error) {
	return resolveHandleFromTXT(ctx, net.DefaultResolver, handle)
}

func resolveHandleFromTXT(ctx context.Context, resolver TXTResolver, handle string) (string, error) {
	name := fmt.Sprintf("_atproto.%s", handle)
	recs, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", fmt.Errorf("%w: no %s TXT record: %w", ErrHandleNotFound, name, err)
		}
		return "", fmt.Errorf("%w: looking up %s: %w", ErrHandleResolutionFailed, name, err)
	}

	for _, rec := range recs {
		maybeDid, ok := strings.CutPrefix(rec, "did=")
		if !ok {
			continue
		}
		if _, err := syntax.ParseDID(maybeDid); err != nil {
			return "", fmt.Errorf("%w: invalid DID in %s TXT record: %w", ErrHandleResolutionFailed, name, err)
		}
		return maybeDid, nil
	}

	return "", fmt.Errorf("%w: no did= value in %s TXT records", ErrHandleNotFound, name)
}

func ResolveHandleFromWellKnown(ctx context.Context, cli *http.Client, handle string) (string, error) {
	ustr := fmt.Sprintf("https://%s/.well-known/atproto-did", handle)
	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		ustr,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("%w: building request for %s: %w", ErrHandleResolutionFailed, ustr, err)
	}

	resp, err := cli.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: fetching %s: %w", ErrHandleResolutionFailed, ustr, err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: reading %s: %w", ErrHandleResolutionFailed, ustr, err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return "", fmt.Errorf("%w: %s returned %d", ErrHandleNotFound, ustr, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("%w: %s returned %d", ErrHandleResolutionFailed, ustr, resp.StatusCode)
	}

	// A host that answers every path with a page (an SPA, a stock nginx
	// response) does not publish a DID for this handle, so an unparseable body is
	// a "no" rather than a resolution failure.
	maybeDid := strings.TrimSpace(string(b))
	if _, err := syntax.ParseDID(maybeDid); err != nil {
		return "", fmt.Errorf("%w: %s did not return a DID", ErrHandleNotFound, ustr)
	}

	return maybeDid, nil
}

// ResolveHandle resolves a handle to a DID, trying the _atproto DNS TXT record
// and then the well-known endpoint. Errors wrap ErrHandleNotFound when both
// methods answered without a DID, and ErrHandleResolutionFailed when either
// could not be completed; both carry the underlying causes for the log.
func ResolveHandle(ctx context.Context, cli *http.Client, handle string) (string, error) {
	return resolveHandle(ctx, net.DefaultResolver, cli, handle)
}

func resolveHandle(ctx context.Context, resolver TXTResolver, cli *http.Client, handle string) (string, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	_, err := syntax.ParseHandle(handle)
	if err != nil {
		return "", err
	}

	maybeDidFromTxt, txtErr := resolveHandleFromTXT(ctx, resolver, handle)
	if txtErr == nil {
		return maybeDidFromTxt, nil
	}

	maybeDidFromWeb, webErr := ResolveHandleFromWellKnown(ctx, cli, handle)
	if webErr == nil {
		return maybeDidFromWeb, nil
	}

	// Only report "not found" when both methods looked and came back empty. If
	// either one broke, the handle may well exist, and the caller should keep
	// treating the request as retryable.
	if errors.Is(txtErr, ErrHandleResolutionFailed) || errors.Is(webErr, ErrHandleResolutionFailed) {
		return "", fmt.Errorf("%w: txt: %v; well-known: %v", ErrHandleResolutionFailed, txtErr, webErr)
	}

	return "", fmt.Errorf("%w: txt: %v; well-known: %v", ErrHandleNotFound, txtErr, webErr)
}

// DefaultPlcURL is the public PLC directory used when no override is configured.
const DefaultPlcURL = "https://plc.directory"

// NormalizePlcURL validates a PLC directory base URL and returns it without a
// trailing slash. An empty value yields DefaultPlcURL. Plain http is accepted
// so a local PLC directory can be used for testing.
func NormalizePlcURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultPlcURL, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid plc url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid plc url %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid plc url %q: missing host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid plc url %q: must not include a query or fragment", raw)
	}

	return strings.TrimRight(raw, "/"), nil
}

// plcBase returns plcURL without a trailing slash, or DefaultPlcURL if empty.
func plcBase(plcURL string) string {
	if plcURL == "" {
		return DefaultPlcURL
	}
	return strings.TrimRight(plcURL, "/")
}

// DidToDocUrl returns the URL of the DID document for did. did:plc documents
// are fetched from plcURL (DefaultPlcURL when empty).
func DidToDocUrl(plcURL, did string) (string, error) {
	if strings.HasPrefix(did, "did:plc:") {
		return fmt.Sprintf("%s/%s", plcBase(plcURL), did), nil
	} else if after, ok := strings.CutPrefix(did, "did:web:"); ok {
		return fmt.Sprintf("https://%s/.well-known/did.json", after), nil
	} else {
		return "", fmt.Errorf("did was not a supported did type")
	}
}

func FetchDidDoc(ctx context.Context, cli *http.Client, plcURL, did string) (*DidDoc, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	ustr, err := DidToDocUrl(plcURL, did)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", ustr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("unable to find did doc at url. did: %s. url: %s", did, ustr)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var diddoc DidDoc
	if err := json.Unmarshal(body, &diddoc); err != nil {
		return nil, err
	}

	return &diddoc, nil
}

func FetchDidData(ctx context.Context, cli *http.Client, plcURL, did string) (*DidData, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	ustr := fmt.Sprintf("%s/%s/data", plcBase(plcURL), did)

	req, err := http.NewRequestWithContext(ctx, "GET", ustr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("could not find identity in plc registry")
	}

	var diddata DidData
	if err := json.NewDecoder(resp.Body).Decode(&diddata); err != nil {
		return nil, err
	}

	return &diddata, nil
}

func FetchDidAuditLog(ctx context.Context, cli *http.Client, plcURL, did string) (DidAuditLog, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	ustr := fmt.Sprintf("%s/%s/log/audit", plcBase(plcURL), did)

	req, err := http.NewRequestWithContext(ctx, "GET", ustr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("could not find identity in plc registry")
	}

	var didlog DidAuditLog
	if err := json.NewDecoder(resp.Body).Decode(&didlog); err != nil {
		return nil, err
	}

	return didlog, nil
}

func ResolveService(ctx context.Context, cli *http.Client, plcURL, did string) (string, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	diddoc, err := FetchDidDoc(ctx, cli, plcURL, did)
	if err != nil {
		return "", err
	}

	var service string
	for _, svc := range diddoc.Service {
		if svc.Id == "#atproto_pds" {
			service = svc.ServiceEndpoint
		}
	}

	if service == "" {
		return "", fmt.Errorf("could not find atproto_pds service in identity services")
	}

	return service, nil
}
