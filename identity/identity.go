package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	ustr := fmt.Sprintf("https://%s/.well=known/atproto-did", handle)
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

func DidToDocUrl(did string) (string, error) {
	if strings.HasPrefix(did, "did:plc:") {
		return fmt.Sprintf("https://plc.directory/%s", did), nil
	} else if strings.HasPrefix(did, "did:web:") {
		return fmt.Sprintf("https://%s/.well-known/did.json", strings.TrimPrefix(did, "did:web:")), nil
	} else {
		return "", fmt.Errorf("did was not a supported did type")
	}
}

func FetchDidDoc(ctx context.Context, cli *http.Client, did string) (*DidDoc, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	ustr, err := DidToDocUrl(did)
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

func FetchDidData(ctx context.Context, cli *http.Client, did string) (*DidData, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	var ustr string
	ustr = fmt.Sprintf("https://plc.directory/%s/data", did)

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

func FetchDidAuditLog(ctx context.Context, cli *http.Client, did string) (DidAuditLog, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	var ustr string
	ustr = fmt.Sprintf("https://plc.directory/%s/log/audit", did)

	req, err := http.NewRequestWithContext(ctx, "GET", ustr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
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

func ResolveService(ctx context.Context, cli *http.Client, did string) (string, error) {
	if cli == nil {
		cli = util.RobustHTTPClient()
	}

	diddoc, err := FetchDidDoc(ctx, cli, did)
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
