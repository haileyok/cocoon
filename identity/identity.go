package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/util"
)

func ResolveHandleFromTXT(ctx context.Context, handle string) (string, error) {
	name := fmt.Sprintf("_atproto.%s", handle)
	recs, err := net.LookupTXT(name)
	if err != nil {
		return "", fmt.Errorf("handle could not be resolved via txt: %w", err)
	}

	for _, rec := range recs {
		if strings.HasPrefix(rec, "did=") {
			maybeDid := strings.Split(rec, "did=")[1]
			if _, err := syntax.ParseDID(maybeDid); err == nil {
				return maybeDid, nil
			}
		}
	}

	return "", fmt.Errorf("handle could not be resolved via txt: no record found")
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
		return "", fmt.Errorf("handle could not be resolved via web: %w", err)
	}

	resp, err := cli.Do(req)
	if err != nil {
		return "", fmt.Errorf("handle could not be resolved via web: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("handle could not be resolved via web: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("handle could not be resolved via web: invalid status code %d", resp.StatusCode)
	}

	maybeDid := string(b)

	if _, err := syntax.ParseDID(maybeDid); err != nil {
		return "", fmt.Errorf("handle could not be resolved via web: invalid did in document")
	}

	return maybeDid, nil
}

func ResolveHandle(ctx context.Context, cli *http.Client, handle string) (string, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	_, err := syntax.ParseHandle(handle)
	if err != nil {
		return "", err
	}

	if maybeDidFromTxt, err := ResolveHandleFromTXT(ctx, handle); err == nil {
		return maybeDidFromTxt, nil
	}

	if maybeDidFromWeb, err := ResolveHandleFromWellKnown(ctx, cli, handle); err == nil {
		return maybeDidFromWeb, nil
	}

	return "", fmt.Errorf("handle could not be resolved")
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

	var diddoc DidDoc
	if err := json.NewDecoder(resp.Body).Decode(&diddoc); err != nil {
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
