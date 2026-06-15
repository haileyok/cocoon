package server

import (
	"context"
	"fmt"

	"github.com/haileyok/cocoon/oauth/scopes"
)

// validateRequestedScopes parses the requested scope string and rejects any
// syntactically-invalid scope. Each `include:<nsid>` is resolved against the
// permission-set resolver; an include that does not resolve to a real
// permission-set lexicon is rejected. When no resolver is configured, include
// resolution is skipped (parsing/syntactic validation still applies).
func (s *Server) validateRequestedScopes(ctx context.Context, scope string) error {
	parsed, err := scopes.ParseList(scope)
	if err != nil {
		return err
	}

	for _, sc := range parsed {
		if sc.Resource != scopes.ResourceInclude {
			continue
		}
		if s.scopeResolver == nil {
			continue
		}
		if err := s.scopeResolver.ResolvePermissionSet(ctx, sc.Nsid); err != nil {
			return fmt.Errorf("include scope %q could not be resolved: %w", sc.Raw, err)
		}
	}

	return nil
}
