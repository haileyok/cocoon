package space

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpacesFixtureManifestMatchesProtocolTypes(t *testing.T) {
	root := filepath.Join("..", "testdata", "spaces-alpha")
	manifest, err := os.Open(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer manifest.Close()

	count := 0
	scanner := bufio.NewScanner(manifest)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			t.Fatalf("invalid manifest line %q", scanner.Text())
		}
		want, err := hex.DecodeString(fields[0])
		if err != nil || len(want) != sha256.Size {
			t.Fatalf("invalid manifest digest %q", fields[0])
		}
		path := fields[1]
		data, err := os.ReadFile(filepath.Join("..", path))
		if err != nil {
			t.Fatalf("read fixture %q: %v", path, err)
		}
		got := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(got[:]), fields[0]) {
			t.Fatalf("fixture %q digest changed: got %x, want %x", path, got, want)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 30 {
		t.Fatalf("manifest has only %d fixtures; expected pinned space and simplespace Lexicons plus references", count)
	}
}

func TestSpacesAlphaReferenceCommitPinned(t *testing.T) {
	if AlphaReferenceCommit != "89deb9faca20e56fa2a262fe9746ed52bc1095ba" {
		t.Fatalf("unexpected Spaces alpha reference commit %q", AlphaReferenceCommit)
	}
	if AlphaCompatibilityVersion != 1 {
		t.Fatalf("unexpected Spaces compatibility version %d", AlphaCompatibilityVersion)
	}
}
