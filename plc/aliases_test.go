package plc

import (
	"strings"
	"testing"
)

func TestValidateExtraAlsoKnownAs(t *testing.T) {
	t.Parallel()

	got, err := ValidateExtraAlsoKnownAs([]string{
		IdentLinkAgentOfPrefix + "did:plc:bob",
		"https://example.com/me",
		IdentLinkAgentOfPrefix + "did:plc:bob",
	})
	if err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}
	if len(got) != 2 || got[0] != IdentLinkAgentOfPrefix+"did:plc:bob" || got[1] != "https://example.com/me" {
		t.Fatalf("want the entries deduplicated in order, got %v", got)
	}

	if got, err := ValidateExtraAlsoKnownAs(nil); err != nil || len(got) != 0 {
		t.Fatalf("no entries: got %v, %v", got, err)
	}

	tooMany := make([]string, MaxExtraAlsoKnownAs+1)
	for i := range tooMany {
		tooMany[i] = "https://example.com/" + strings.Repeat("a", i+1)
	}
	for name, bad := range map[string][]string{
		"handle entry":         {"at://someone.example.com"},
		"http":                 {"http://example.com"},
		"not a uri":            {"not a uri"},
		"no host":              {"https:///path"},
		"empty":                {""},
		"too long":             {"https://example.com/" + strings.Repeat("a", maxAliasLen)},
		"agent-of without did": {IdentLinkAgentOfPrefix},
		"agent-of bad did":     {IdentLinkAgentOfPrefix + "bob"},
		"too many":             tooMany,
	} {
		if _, err := ValidateExtraAlsoKnownAs(bad); err == nil {
			t.Errorf("%s: %v accepted", name, bad)
		}
	}
}
