package scopes

import (
	"testing"

	"github.com/bluesky-social/indigo/atproto/identity"
)

func basePLCURL(t *testing.T, r *IndigoResolver) string {
	t.Helper()
	cache, ok := r.dir.(*identity.CacheDirectory)
	if !ok {
		t.Fatalf("expected *identity.CacheDirectory, got %T", r.dir)
	}
	base, ok := cache.Inner.(*identity.BaseDirectory)
	if !ok {
		t.Fatalf("expected *identity.BaseDirectory inner, got %T", cache.Inner)
	}
	return base.PLCURL
}

func TestNewIndigoResolverWithPLCURL(t *testing.T) {
	r := NewIndigoResolverWithPLCURL("http://localhost:2582")
	if got := basePLCURL(t, r); got != "http://localhost:2582" {
		t.Fatalf("PLCURL = %q, want %q", got, "http://localhost:2582")
	}
}

func TestNewIndigoResolverWithPLCURLEmptyUsesDefault(t *testing.T) {
	r := NewIndigoResolverWithPLCURL("")
	if got := basePLCURL(t, r); got != identity.DefaultPLCURL {
		t.Fatalf("PLCURL = %q, want %q", got, identity.DefaultPLCURL)
	}
}
