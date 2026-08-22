package space

import (
	"os"
	"strings"
	"testing"
)

// TestSpacesReadmeContract protects the stable safety and compatibility
// warnings without turning README.md into a brittle snapshot fixture.
func TestSpacesReadmeContract(t *testing.T) {
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)
	for _, phrase := range []string{
		"Atproto Spaces is an experimental alpha",
		"COCOON_SPACES_ENABLED=false",
		"89deb9faca20e56fa2a262fe9746ed52bc1095ba",
		"access control, not encryption or confidentiality",
		"unsuitable for sensitive data",
		"not use a relay or a public firehose",
		"permissioned records never enter Cocoon's public event manager",
		"authenticated PDS proxy only",
		"A private CDN is not a permission boundary",
		"notification outbox",
		"no automatic outbound delivery",
		"append-only Space oplog",
		"full current-state CAR recovery path",
		"no complete import API",
		"migration",
	} {
		if !strings.Contains(text, phrase) {
			t.Errorf("README.md is missing stable Spaces contract phrase %q", phrase)
		}
	}
}
