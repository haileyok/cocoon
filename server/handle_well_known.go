package server

import (
	"fmt"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

var (
	CocoonSupportedScopes = []string{
		"atproto",
		"transition:email",
		"transition:generic",
		"transition:chat.bsky",
	}
)

type OauthAuthorizationMetadata struct {
	Issuer                                     string   `json:"issuer"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestUriParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequireRequestUriRegistration              *bool    `json:"require_request_uri_registration,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	UILocalesSupported                         []string `json:"ui_locales_supported"`
	DisplayValuesSupported                     []string `json:"display_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	AuthorizationResponseISSParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported"`
	JwksUri                                    string   `json:"jwks_uri"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`
	DpopSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported"`
	ProtectedResources                         []string `json:"protected_resources"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
}

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

func (s *Server) handleAtprotoDid(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAtprotoDid")

	host := e.Request().Host
	if host == "" {
		return helpers.InputError(e, to.StringPtr("Invalid handle."))
	}

	host = strings.Split(host, ":")[0]
	host = strings.ToLower(strings.TrimSpace(host))

	if host == s.config.Hostname {
		return e.String(200, s.config.Did)
	}

	suffix := "." + s.config.Hostname
	if !strings.HasSuffix(host, suffix) {
		return e.NoContent(404)
	}

	actor, err := s.getActorByHandle(ctx, host)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return e.NoContent(404)
		}
		logger.Error("error looking up actor by handle", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.String(200, actor.Did)
}

func (s *Server) handleOauthProtectedResource(e echo.Context) error {
	return e.JSON(200, map[string]any{
		"resource": "https://" + s.config.Hostname,
		"authorization_servers": []string{
			"https://" + s.config.Hostname,
		},
		"scopes_supported":         []string{},
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   "https://atproto.com",
	})
}

func (s *Server) handleOauthAuthorizationServer(e echo.Context) error {
	return e.JSON(200, OauthAuthorizationMetadata{
		Issuer:                                     "https://" + s.config.Hostname,
		RequestParameterSupported:                  true,
		RequestUriParameterSupported:               true,
		RequireRequestUriRegistration:              to.BoolPtr(true),
		ScopesSupported:                            CocoonSupportedScopes,
		SubjectTypesSupported:                      []string{"public"},
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query", "fragment", "form_post"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		UILocalesSupported:                         []string{"en-US"},
		DisplayValuesSupported:                     []string{"page", "popup", "touch"},
		RequestObjectSigningAlgValuesSupported:     []string{"ES256"}, // only es256 for now...
		AuthorizationResponseISSParameterSupported: true,
		RequestObjectEncryptionAlgValuesSupported:  []string{},
		RequestObjectEncryptionEncValuesSupported:  []string{},
		JwksUri:                           fmt.Sprintf("https://%s/oauth/jwks", s.config.Hostname),
		AuthorizationEndpoint:             fmt.Sprintf("https://%s/oauth/authorize", s.config.Hostname),
		TokenEndpoint:                     fmt.Sprintf("https://%s/oauth/token", s.config.Hostname),
		TokenEndpointAuthMethodsSupported: []string{"none", "private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"ES256"}, // Same as above, just es256
		RevocationEndpoint:                         fmt.Sprintf("https://%s/oauth/revoke", s.config.Hostname),
		IntrospectionEndpoint:                      fmt.Sprintf("https://%s/oauth/introspect", s.config.Hostname),
		PushedAuthorizationRequestEndpoint:         fmt.Sprintf("https://%s/oauth/par", s.config.Hostname),
		RequirePushedAuthorizationRequests:         true,
		DpopSigningAlgValuesSupported:              []string{"ES256"}, // again same as above
		ProtectedResources:                         []string{"https://" + s.config.Hostname},
		ClientIDMetadataDocumentSupported:          true,
	})
}
