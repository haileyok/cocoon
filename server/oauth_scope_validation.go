package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/haileyok/cocoon/oauth/scopes"
)

// validateRequestedScopes validates an OAuth authorization request's scope
// string. It returns an error (to be surfaced as invalid_scope) when the scope
// cannot be parsed, is missing the required `atproto` scope, or contains an
// `include:` reference to a permission set that cannot be resolved.
//
// Unknown non-include resources are intentionally accepted for forward and
// backward compatibility; this function does not attempt to reject them.
func (s *Server) validateRequestedScopes(ctx context.Context, scope string) error {
	perms, err := scopes.Parse(scope)
	if err != nil {
		return fmt.Errorf("could not parse scope: %w", err)
	}

	if !scopes.Has(perms, "atproto") {
		return errors.New("the `atproto` scope is required")
	}

	for _, p := range perms {
		if p.Resource != "include" {
			continue
		}
		if p.Positional == "" {
			return errors.New("`include` scope requires a permission-set nsid")
		}
		if err := s.scopeResolver.ValidateInclude(ctx, p.Positional, p.Params); err != nil {
			return fmt.Errorf("invalid include `%s`: %w", p.Positional, err)
		}
	}

	return nil
}
