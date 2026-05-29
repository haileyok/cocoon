package server

import (
	"context"
	"strings"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
)

// requestScopes returns the parsed permissions for the current request and
// whether granular scope enforcement applies to it. Enforcement only applies
// when the OAuth/DPoP session middleware set "scopes" on the context; legacy
// bearer JWTs and inter-service auth leave it unset and are unaffected. If the
// stored scope string somehow fails to parse, enforcement still applies with an
// empty permission set (fail closed) — the scope was already validated at
// authorization time, so this should not happen for legitimate tokens.
func (s *Server) requestScopes(e echo.Context) ([]scopes.Permission, bool) {
	raw := e.Get("scopes")
	if raw == nil {
		return nil, false
	}
	rawScopes, ok := raw.([]string)
	if !ok {
		return nil, false
	}
	perms, err := scopes.Parse(strings.Join(rawScopes, " "))
	if err != nil {
		return nil, true
	}
	return perms, true
}

// expandIncludes appends the permissions granted by any include: references to
// the supplied set. Resolution failures are logged and treated as granting
// nothing (so they neither 500 nor silently widen access).
func (s *Server) expandIncludes(ctx context.Context, perms []scopes.Permission) []scopes.Permission {
	expanded := perms
	for _, p := range perms {
		if p.Resource != "include" || p.Positional == "" {
			continue
		}
		resolved, err := s.scopeResolver.Resolve(ctx, p.Positional, p.Params)
		if err != nil {
			s.logger.Warn("could not resolve include scope for write enforcement", "nsid", p.Positional, "error", err)
			continue
		}
		expanded = append(expanded, resolved...)
	}
	return expanded
}

// enforceRepoWrite ensures the current request's granted scopes permit every
// listed action on the given collection. It is a no-op for non-OAuth sessions
// and for the legacy transition:generic scope. On failure it returns a 403
// insufficient_scope error.
func (s *Server) enforceRepoWrite(e echo.Context, ctx context.Context, collection string, actions ...string) error {
	perms, enforce := s.requestScopes(e)
	if !enforce || scopes.GrantsAllRepoWrites(perms) {
		return nil
	}

	perms = s.expandIncludes(ctx, perms)

	for _, action := range actions {
		if !scopes.RepoWriteAllowed(perms, collection, action) {
			return helpers.InsufficientScopeError(e)
		}
	}

	return nil
}

// enforceBlobUpload ensures the current request's granted scopes permit blob
// uploads. It is a no-op for non-OAuth sessions and for transition:generic.
func (s *Server) enforceBlobUpload(e echo.Context, ctx context.Context) error {
	perms, enforce := s.requestScopes(e)
	if !enforce || scopes.GrantsAllRepoWrites(perms) {
		return nil
	}

	perms = s.expandIncludes(ctx, perms)

	if !scopes.BlobAllowed(perms) {
		return helpers.InsufficientScopeError(e)
	}

	return nil
}

// applyWriteAction maps a com.atproto.repo.applyWrites item $type to the repo
// action it performs. Returns "" for unrecognized types.
func applyWriteAction(t string) string {
	switch t {
	case "com.atproto.repo.applyWrites#create":
		return "create"
	case "com.atproto.repo.applyWrites#update":
		return "update"
	case "com.atproto.repo.applyWrites#delete":
		return "delete"
	default:
		return ""
	}
}
