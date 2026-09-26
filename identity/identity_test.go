package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizePlcURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty uses default", in: "", want: DefaultPlcURL},
		{name: "whitespace uses default", in: "   ", want: DefaultPlcURL},
		{name: "https kept", in: "https://plc.example.com", want: "https://plc.example.com"},
		{name: "http allowed for local testing", in: "http://localhost:2582", want: "http://localhost:2582"},
		{name: "trailing slash trimmed", in: "http://localhost:2582/", want: "http://localhost:2582"},
		{name: "path prefix kept", in: "https://example.com/plc/", want: "https://example.com/plc"},
		{name: "missing scheme rejected", in: "localhost:2582", wantErr: true},
		{name: "non-http scheme rejected", in: "ftp://plc.example.com", wantErr: true},
		{name: "missing host rejected", in: "https://", wantErr: true},
		{name: "query rejected", in: "https://plc.example.com?x=1", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePlcURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizePlcURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDidToDocUrlUsesPlcURL(t *testing.T) {
	got, err := DidToDocUrl("http://localhost:2582", "did:plc:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://localhost:2582/did:plc:abc123"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	got, err = DidToDocUrl("", "did:plc:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://plc.directory/did:plc:abc123"; got != want {
		t.Fatalf("empty plc url: got %q, want %q", got, want)
	}

	// did:web resolution never touches the PLC directory.
	got, err = DidToDocUrl("http://localhost:2582", "did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://example.com/.well-known/did.json"; got != want {
		t.Fatalf("did:web: got %q, want %q", got, want)
	}
}

// fakePlc serves a minimal PLC directory and records requested paths.
func fakePlc(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/did:plc:abc123":
			json.NewEncoder(w).Encode(DidDoc{Id: "did:plc:abc123"})
		case "/did:plc:abc123/data":
			json.NewEncoder(w).Encode(DidData{Did: "did:plc:abc123"})
		case "/did:plc:abc123/log/audit":
			json.NewEncoder(w).Encode(DidAuditLog{{Did: "did:plc:abc123"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func TestFetchHelpersUseConfiguredPlcURL(t *testing.T) {
	srv, paths := fakePlc(t)
	ctx := context.Background()

	doc, err := FetchDidDoc(ctx, srv.Client(), srv.URL, "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDidDoc: %v", err)
	}
	if doc.Id != "did:plc:abc123" {
		t.Fatalf("unexpected doc id %q", doc.Id)
	}

	data, err := FetchDidData(ctx, srv.Client(), srv.URL, "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDidData: %v", err)
	}
	if data.Did != "did:plc:abc123" {
		t.Fatalf("unexpected data did %q", data.Did)
	}

	log, err := FetchDidAuditLog(ctx, srv.Client(), srv.URL, "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDidAuditLog: %v", err)
	}
	if len(log) != 1 || log[0].Did != "did:plc:abc123" {
		t.Fatalf("unexpected audit log %+v", log)
	}

	want := []string{"/did:plc:abc123", "/did:plc:abc123/data", "/did:plc:abc123/log/audit"}
	if len(*paths) != len(want) {
		t.Fatalf("paths = %v, want %v", *paths, want)
	}
	for i := range want {
		if (*paths)[i] != want[i] {
			t.Fatalf("paths = %v, want %v", *paths, want)
		}
	}
}

func TestPassportUsesConfiguredPlcURL(t *testing.T) {
	srv, paths := fakePlc(t)

	p := NewPassport(srv.Client(), NewMemCache(10), WithPlcURL(srv.URL))
	doc, err := p.FetchDoc(context.Background(), "did:plc:abc123")
	if err != nil {
		t.Fatalf("FetchDoc: %v", err)
	}
	if doc.Id != "did:plc:abc123" {
		t.Fatalf("unexpected doc id %q", doc.Id)
	}
	if len(*paths) != 1 || (*paths)[0] != "/did:plc:abc123" {
		t.Fatalf("fake PLC was not queried as expected: %v", *paths)
	}
}
