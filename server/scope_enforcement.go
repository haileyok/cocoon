package server

import (
	"fmt"
	"strings"

	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
)

type repoScopeError string

func (e repoScopeError) Error() string { return string(e) }

func (s *Server) repoWriteAuthorization(e echo.Context) func(string, string) error {
	return func(collection, action string) error {
		if !s.hasRepoScope(e, collection, action) {
			return repoScopeError(fmt.Sprintf("repo:%s?action=%s", collection, action))
		}
		return nil
	}
}

// hasRPCScope checks the exact method and audience before delegating authority.
// An omitted method requests an unrestricted token and requires lxm=*.
func (s *Server) hasRPCScope(e echo.Context, aud, lxm string) bool {
	kind := e.Get("credentialKind")
	if kind == credentialLegacyAccess || kind == credentialService {
		return true
	}
	if kind != credentialOAuth {
		return false
	}
	granted, ok := e.Get("scopes").([]string)
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

// hasRepoScope checks write permission for a collection and action.
func (s *Server) hasRepoScope(e echo.Context, collection, action string) bool {
	kind := e.Get("credentialKind")
	if kind == credentialLegacyAccess || kind == credentialService {
		return true
	}
	if kind != credentialOAuth {
		return false
	}
	granted, ok := e.Get("scopes").([]string)
	if !ok {
		return false
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
