package server

import (
	"context"
	"fmt"
	"sort"

	"github.com/haileyok/cocoon/oauth/scopes"
)

// validateRequestedScopes parses the requested scope string and rejects any
// syntactically-invalid scope. Each `include:<nsid>` is resolved against the
// permission-set resolver; an include that does not resolve to a real
// permission-set lexicon is rejected. When no resolver is configured, include
// resolution is skipped (parsing/syntactic validation still applies).
//
// Every concrete space type a scope names, directly or through an include:
// set, must resolve to a valid space type declaration, as the reference
// requires before it shows the consent screen: the declaration's name is what
// the user is asked to approve, and a bare grant takes its collections from it.
func (s *Server) validateRequestedScopes(ctx context.Context, scope string) error {
	parsed, err := scopes.ParseList(scope)
	if err != nil {
		return err
	}

	spaceTypes := map[string]bool{}
	for _, sc := range parsed {
		switch sc.Resource {
		case scopes.ResourceSpace:
			if sc.Space != nil {
				spaceTypes[sc.Space.Type] = true
			}
		case scopes.ResourceInclude:
			if s.scopeResolver == nil {
				continue
			}
			if _, err := s.scopeResolver.ResolvePermissionSet(ctx, sc.Nsid); err != nil {
				return fmt.Errorf("include scope %q could not be resolved: %w", sc.Raw, err)
			}
			if sr, ok := s.scopeResolver.(scopes.SpacePermissionSetResolver); ok {
				// A failure here is not this check's to report: the set itself
				// resolved above, and issuance resolves it again.
				if perms, err := sr.ResolveSpacePermissions(ctx, sc.Nsid); err == nil {
					for _, p := range perms {
						spaceTypes[p.Type] = true
					}
				}
			}
		}
	}

	return s.validateSpaceTypes(ctx, spaceTypes)
}

// validateSpaceTypes checks that each concrete space type resolves to a valid
// declaration. A wildcard type has no declaration to resolve. When no
// resolver is configured there is nothing to check against.
func (s *Server) validateSpaceTypes(ctx context.Context, types map[string]bool) error {
	r := s.spaceTypeResolver()
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(types))
	for t := range types {
		if t != "*" {
			names = append(names, t)
		}
	}
	sort.Strings(names)
	for _, t := range names {
		if _, err := r.ResolveSpaceCollections(ctx, t); err != nil {
			return fmt.Errorf("space type %q declaration could not be retrieved: %w", t, err)
		}
	}
	return nil
}
