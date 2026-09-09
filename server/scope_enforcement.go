package server

import (
	"strings"

	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
)

// hasRPCScope checks the exact method and audience before delegating authority.
// An omitted method requests an unrestricted token and requires lxm=*.
func (s *Server) hasRPCScope(e echo.Context, aud, lxm string) bool {
	raw := e.Get("scopes")
	if raw == nil {
		// Only authenticated legacy bearer requests may omit OAuth scope state.
		scheme, _, _ := strings.Cut(e.Request().Header.Get("Authorization"), " ")
		return strings.EqualFold(scheme, "Bearer")
	}
	granted, ok := raw.([]string)
	if !ok {
		return false
	}
	if lxm == "" {
		lxm = "*"
	}
	for _, tok := range granted {
		sc, err := scopes.Parse(tok)
		if err != nil {
			continue
		}
		if sc.Resource == scopes.ResourceTransition {
			chat := strings.HasPrefix(lxm, "chat.bsky.")
			if (sc.Transition == "generic" && !chat) || (sc.Transition == "chat.bsky" && chat) {
				return true
			}
		}
		if sc.Resource == scopes.ResourceRPC && (sc.Aud == aud || sc.Aud == "*") {
			for _, method := range sc.Lxm {
				if method == lxm || method == "*" {
					return true
				}
			}
		}
	}
	return false
}

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
