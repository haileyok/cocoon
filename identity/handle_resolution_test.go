package identity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// cannedTXT answers _atproto TXT lookups from fixed data so these tests never
// touch DNS.
type cannedTXT struct {
	recs []string
	err  error
	name string
}

func (c *cannedTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	c.name = name
	return c.recs, c.err
}

// cannedHTTP answers well-known requests with a fixed status and body.
type cannedHTTP struct {
	status int
	body   string
	err    error
}

func (c cannedHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestResolveHandleFromTXTClassifiesFailures(t *testing.T) {
	dnsNotFound := &net.DNSError{Err: "no such host", Name: "_atproto.example.com", IsNotFound: true}
	dnsBroken := &net.DNSError{Err: "server misbehaving", Name: "_atproto.example.com"}

	cases := []struct {
		name    string
		recs    []string
		err     error
		wantDid string
		wantErr error
	}{
		{
			name:    "did record",
			recs:    []string{"v=spf1 -all", "did=did:plc:z72i7hdynmk6r22z27h6tvur"},
			wantDid: "did:plc:z72i7hdynmk6r22z27h6tvur",
		},
		{
			name:    "no records",
			wantErr: ErrHandleNotFound,
		},
		{
			name:    "records without a did",
			recs:    []string{"v=spf1 -all"},
			wantErr: ErrHandleNotFound,
		},
		{
			name:    "nxdomain",
			err:     dnsNotFound,
			wantErr: ErrHandleNotFound,
		},
		{
			name:    "resolver failure",
			err:     dnsBroken,
			wantErr: ErrHandleResolutionFailed,
		},
		{
			name:    "invalid did in record",
			recs:    []string{"did=not-a-did"},
			wantErr: ErrHandleResolutionFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &cannedTXT{recs: tc.recs, err: tc.err}
			did, err := resolveHandleFromTXT(context.Background(), resolver, "example.com")

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if did != tc.wantDid {
				t.Fatalf("did = %q, want %q", did, tc.wantDid)
			}
		})
	}

	t.Run("queries the _atproto name", func(t *testing.T) {
		resolver := &cannedTXT{recs: []string{"did=did:plc:z72i7hdynmk6r22z27h6tvur"}}
		if _, err := resolveHandleFromTXT(context.Background(), resolver, "example.com"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "_atproto.example.com"; resolver.name != want {
			t.Fatalf("looked up %q, want %q", resolver.name, want)
		}
	})
}

func TestResolveHandleFromWellKnownClassifiesFailures(t *testing.T) {
	const did = "did:plc:z72i7hdynmk6r22z27h6tvur"

	cases := []struct {
		name    string
		resp    cannedHTTP
		wantDid string
		wantErr error
	}{
		{name: "did document", resp: cannedHTTP{status: 200, body: did + "\n"}, wantDid: did},
		{name: "not found", resp: cannedHTTP{status: 404, body: "nope"}, wantErr: ErrHandleNotFound},
		{name: "gone", resp: cannedHTTP{status: 410, body: "gone"}, wantErr: ErrHandleNotFound},
		{name: "html page", resp: cannedHTTP{status: 200, body: "<html>hi</html>"}, wantErr: ErrHandleNotFound},
		{name: "server error", resp: cannedHTTP{status: 500, body: "boom"}, wantErr: ErrHandleResolutionFailed},
		{name: "transport error", resp: cannedHTTP{err: errors.New("connection refused")}, wantErr: ErrHandleResolutionFailed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := &http.Client{Transport: tc.resp}
			got, err := ResolveHandleFromWellKnown(context.Background(), cli, "example.com")

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantDid {
				t.Fatalf("did = %q, want %q", got, tc.wantDid)
			}
		})
	}
}

func TestResolveHandleCombinesMethods(t *testing.T) {
	const did = "did:plc:z72i7hdynmk6r22z27h6tvur"

	cases := []struct {
		name    string
		txt     cannedTXT
		known   cannedHTTP
		wantDid string
		wantErr error
	}{
		{
			name:    "both methods find nothing",
			txt:     cannedTXT{},
			known:   cannedHTTP{status: 404},
			wantErr: ErrHandleNotFound,
		},
		{
			name:    "website returns a page instead of a did",
			txt:     cannedTXT{},
			known:   cannedHTTP{status: 200, body: "<html>hi</html>"},
			wantErr: ErrHandleNotFound,
		},
		{
			name:    "dns broken and well-known empty",
			txt:     cannedTXT{err: &net.DNSError{Err: "server misbehaving", Name: "_atproto.example.com"}},
			known:   cannedHTTP{status: 404},
			wantErr: ErrHandleResolutionFailed,
		},
		{
			name:    "dns empty and well-known broken",
			txt:     cannedTXT{},
			known:   cannedHTTP{status: 503},
			wantErr: ErrHandleResolutionFailed,
		},
		{
			name:    "well-known saves a broken dns lookup",
			txt:     cannedTXT{err: &net.DNSError{Err: "server misbehaving", Name: "_atproto.example.com"}},
			known:   cannedHTTP{status: 200, body: did},
			wantDid: did,
		},
		{
			name:    "txt wins",
			txt:     cannedTXT{recs: []string{"did=" + did}},
			known:   cannedHTTP{status: 500},
			wantDid: did,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := &http.Client{Transport: tc.known}
			got, err := resolveHandle(context.Background(), &tc.txt, cli, "example.com")

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				// Both methods' reasons have to survive into the log line;
				// otherwise the only thing an operator sees is that resolution
				// failed, with no hint which half broke.
				for _, want := range []string{"txt:", "well-known:"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q does not mention %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantDid {
				t.Fatalf("did = %q, want %q", got, tc.wantDid)
			}
		})
	}
}
