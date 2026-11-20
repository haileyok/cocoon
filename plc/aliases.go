package plc

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// MaxExtraAlsoKnownAs bounds the alsoKnownAs entries an account may ask for
// at creation, besides its at:// handle.
const MaxExtraAlsoKnownAs = 8

// maxAliasLen bounds one alsoKnownAs entry.
const maxAliasLen = 512

// IdentLinkAgentOfPrefix is the ident.link declaration that an account is an
// agent acting for the principal whose DID follows
// (https://ident.link/#agent-declaration).
const IdentLinkAgentOfPrefix = "https://ident.link/agent-of/"

// ValidateExtraAlsoKnownAs checks the alsoKnownAs entries an account asks for
// besides its handle, and returns them with duplicates removed, in order.
// Entries must be https URIs: the at:// handle entry comes only from the
// handle, so it stays first and single. An ident.link agent-of entry must
// name a valid DID.
func ValidateExtraAlsoKnownAs(extra []string) ([]string, error) {
	if len(extra) > MaxExtraAlsoKnownAs {
		return nil, fmt.Errorf("at most %d alsoKnownAs entries", MaxExtraAlsoKnownAs)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(extra))
	for _, aka := range extra {
		if aka == "" || len(aka) > maxAliasLen {
			return nil, fmt.Errorf("alsoKnownAs entries must be 1 to %d bytes", maxAliasLen)
		}
		u, err := url.Parse(aka)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.String() != aka {
			return nil, fmt.Errorf("alsoKnownAs entry %q is not an https URI", aka)
		}
		if rest, ok := strings.CutPrefix(aka, IdentLinkAgentOfPrefix); ok {
			if _, err := syntax.ParseDID(rest); err != nil {
				return nil, fmt.Errorf("alsoKnownAs entry %q does not name a valid DID: %w", aka, err)
			}
		}
		if seen[aka] {
			continue
		}
		seen[aka] = true
		out = append(out, aka)
	}
	return out, nil
}
