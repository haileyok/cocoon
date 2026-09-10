package server

import (
	"mime"
	"net/url"
	"strings"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
)

// credentialKind is set only after credential verification.
type credentialKind uint8

const (
	credentialLegacyAccess credentialKind = iota + 1
	credentialLegacyRefresh
	credentialOAuth
	credentialService
)

// authorizeEndpoint applies endpoint policy after authentication, before handler execution.
func (s *Server) authorizeEndpoint(e echo.Context, next echo.HandlerFunc) error {
	kind, ok := e.Get("credentialKind").(credentialKind)
	if !ok {
		return helpers.InvalidTokenError(e)
	}
	if kind == credentialOAuth {
		if _, ok := e.Get("scopes").([]string); !ok {
			return helpers.InvalidTokenError(e)
		}
	}
	nsid := strings.TrimPrefix(e.Request().URL.Path, "/xrpc/")
	required := ""
	switch nsid {
	case "com.atproto.server.requestEmailUpdate", "com.atproto.server.updateEmail",
		"com.atproto.server.requestAccountDelete", "com.atproto.server.activateAccount", "com.atproto.server.deactivateAccount":
		if kind != credentialLegacyAccess {
			return e.JSON(403, map[string]string{"error": "Forbidden", "message": "This endpoint requires a legacy access session"})
		}
	case "com.atproto.identity.updateHandle":
		required = "identity:handle"
	case "com.atproto.identity.requestPlcOperationSignature", "com.atproto.identity.signPlcOperation", "com.atproto.identity.submitPlcOperation":
		required = "identity:*"
	case "com.atproto.repo.importRepo":
		required = "account:repo?action=manage"
	case "com.atproto.server.confirmEmail", "com.atproto.server.requestEmailConfirmation":
		required = "account:email?action=manage"
	case "com.atproto.repo.uploadBlob":
		if kind == credentialService {
			return next(e)
		}
		contentType := e.Request().Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || strings.Count(mediaType, "/") != 1 || strings.Contains(mediaType, "*") {
			return helpers.InputError(e, nil)
		}
		required = "blob:" + strings.ToLower(mediaType)
	case "app.bsky.actor.getPreferences", "app.bsky.actor.putPreferences":
		// Local preferences belong to the configured AppView, not the proxy audience.
		aud := s.config.FallbackProxy
		selected := e.Request().Header.Get("atproto-proxy")
		if (kind != credentialLegacyAccess && kind != credentialOAuth) ||
			(selected != "" && selected != aud) || !s.hasRPCScope(e, aud, nsid) {
			return helpers.InsufficientScopeError(e, "rpc:"+nsid+"?aud="+url.QueryEscape(aud))
		}
	}
	if required != "" && !s.hasEndpointScope(e, required) {
		return helpers.InsufficientScopeError(e, required)
	}
	return next(e)
}

func (s *Server) hasEndpointScope(e echo.Context, required string) bool {
	if e.Get("credentialKind") == credentialLegacyAccess {
		return true
	}
	if e.Get("credentialKind") != credentialOAuth {
		return false
	}
	granted, ok := e.Get("scopes").([]string)
	if !ok {
		return false
	}
	want, err := scopes.Parse(required)
	if err != nil {
		return false
	}
	for _, token := range granted {
		scope, err := scopes.Parse(token)
		if err != nil {
			continue
		}
		switch want.Resource {
		case scopes.ResourceAccount:
			if scope.AllowsAccount(want.Attr, want.Action) ||
				(token == "transition:email" && want.Attr == "email" && want.Action == "read") {
				return true
			}
		case scopes.ResourceIdentity:
			if scope.AllowsIdentity(want.Attr) {
				return true
			}
		case scopes.ResourceBlob:
			if token == "transition:generic" || scope.AllowsBlob(want.Accept[0]) {
				return true
			}
		}
	}
	return false
}
