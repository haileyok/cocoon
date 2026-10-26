package main

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

func TestSQLiteVersionIncludesWALResetUpdate(t *testing.T) {
	version, number, _ := sqlite3.Version()
	// SQLite 3.51.3 addresses the WAL-reset race: https://sqlite.org/wal.html
	if number < 3051003 {
		t.Fatalf("linked SQLite %s predates the WAL-reset update in 3.51.3", version)
	}
	t.Logf("linked SQLite %s", version)
}

// minPatchedGo is the oldest Go release that contains the crypto/x509
// mitigation for CVE-2026-111943, which distrusted the eight eMudhra
// intermediate CAs revoked with reason cACompromise on 2026-10-18.
//
// Go's verifier performs no revocation checking on Linux, and the emSign roots
// that signed the compromised intermediates are still present in the standard
// CA bundles, so rebuilding against a patched toolchain is the only thing that
// stops a forged chain from chaining through to a trusted root. See
// https://go.dev/issue/82345.
const minPatchedGo = "1.26.10"

// TestGoToolchainIsPatchedForDistrustedCA guards the build wiring. The x509
// distrust list is compiled into the toolchain, so a binary only inherits the
// mitigation if it is actually built by a patched Go. Checking the running
// toolchain and the version pins together catches both a lowered go directive
// and a Dockerfile that would produce an unpatched image.
func TestGoToolchainIsPatchedForDistrustedCA(t *testing.T) {
	running := strings.TrimPrefix(runtime.Version(), "go")
	if !strings.HasPrefix(runtime.Version(), "go") {
		t.Skipf("non-release toolchain %q, cannot compare versions", runtime.Version())
	}
	if v, ok := parseGoVersion(running); !ok {
		t.Skipf("unparseable toolchain version %q", running)
	} else if lessThan(v, minPatchedGo) {
		t.Fatalf("toolchain go%s predates the CVE-2026-111943 fix in go%s", running, minPatchedGo)
	}

	checkGoMod(t)
	checkDockerfile(t, "Dockerfile")
	checkDockerfile(t, "Dockerfile.alpine")
}

func checkGoMod(t *testing.T) {
	t.Helper()

	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	m := regexp.MustCompile(`(?m)^go\s+(\S+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}

	got := string(m[1])
	v, ok := parseGoVersion(got)
	if !ok {
		t.Fatalf("unparseable go directive %q", got)
	}
	if lessThan(v, minPatchedGo) {
		t.Fatalf("go.mod requires go%s, below the patched go%s (CVE-2026-111943)", got, minPatchedGo)
	}
}

func checkDockerfile(t *testing.T, path string) {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	// Compile-stage base images are the only place the toolchain is pinned in
	// the Docker builds; the run stages do not compile anything.
	re := regexp.MustCompile(`(?m)^FROM\s+golang:(\S+)`)
	matches := re.FindAllStringSubmatch(string(b), -1)
	if len(matches) == 0 {
		t.Fatalf("%s has no golang build stage", path)
	}

	for _, m := range matches {
		tag := m[1]
		// Tags look like 1.26.10-bookworm or 1.26.10-alpine; the variant suffix
		// is not part of the version.
		if i := strings.Index(tag, "-"); i >= 0 {
			tag = tag[:i]
		}
		v, ok := parseGoVersion(tag)
		if !ok {
			t.Fatalf("%s: unparseable golang image tag %q", path, m[1])
		}
		if lessThan(v, minPatchedGo) {
			t.Fatalf("%s builds on golang:%s, below the patched %s (CVE-2026-111943)", path, m[1], minPatchedGo)
		}
	}
}

// parseGoVersion parses a "1.26.10" style version, tolerating a missing patch
// component ("1.26" means 1.26.0). Pre-release suffixes are rejected so a tag
// like 1.27rc1 cannot pass for a patched release.
func parseGoVersion(s string) ([3]int, bool) {
	var out [3]int

	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}

	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}

	return out, true
}

func lessThan(v [3]int, min string) bool {
	want, ok := parseGoVersion(min)
	if !ok {
		panic(fmt.Sprintf("bad minPatchedGo %q", min))
	}

	for i := range v {
		if v[i] != want[i] {
			return v[i] < want[i]
		}
	}

	return false
}
