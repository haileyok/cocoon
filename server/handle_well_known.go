package server

import (
	"github.com/labstack/echo/v4"
)

func (s *Server) handleWellKnown(e echo.Context) error {
	return e.JSON(200, map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
		},
		"id": s.config.Did,
		"service": []map[string]string{
			{
				"id":              "#atproto_pds",
				"type":            "AtprotoPersonalDataServer",
				"serviceEndpoint": "https://" + s.config.Hostname,
			},
		},
	})
}

func (s *Server) handleProtectedResource(e echo.Context) error {
	return e.JSON(200, map[string]any{
		"resource": "https://" + s.config.Hostname,
		"authorization_servers": []string{
			"https://" + s.config.Hostname,
		},
		"scopes_supported": []string{},
		"bearer_methods_supported": []string{
			"header",
		},
		"resource_documentation": "https://atproto.com",
	})
}
