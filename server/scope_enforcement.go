package server

import (
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
)

// actionForOpType maps a repo OpType to its scope action verb.
func actionForOpType(t OpType) string {
	switch t {
	case OpTypeCreate:
		return "create"
	case OpTypeUpdate:
		return "update"
	case OpTypeDelete:
		return "delete"
	default:
		return ""
	}
}

// hasRepoScope reports whether the current session is permitted to perform a
// repo write of action on collection.
//
// Sessions without OAuth scopes (password/legacy access tokens, which never set
// "scopes") are unrestricted, as is the legacy broad-write transition:generic
// scope. Otherwise the granted scopes must include a repo: scope covering the
// collection and action.
func (s *Server) hasRepoScope(e echo.Context, collection, action string) bool {
	raw := e.Get("scopes")
	if raw == nil {
		return true
	}
	granted, ok := raw.([]string)
	if !ok {
		return true
	}

	for _, tok := range granted {
		if tok == "transition:generic" {
			return true
		}
	}

	for _, tok := range granted {
		sc, err := scopes.Parse(tok)
		if err != nil {
			continue
		}
		if sc.AllowsRepoWrite(collection, action) {
			return true
		}
	}

	return false
}
