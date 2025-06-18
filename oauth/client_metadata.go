package oauth

type ClientMetadata struct {
	ClientID                    string    `json:"client_id"`
	ClientName                  string    `json:"client_name"`
	ClientURI                   string    `json:"client_uri"`
	LogoURI                     string    `json:"logo_uri"`
	TOSURI                      string    `json:"tos_uri"`
	PolicyURI                   string    `json:"policy_uri"`
	RedirectURIs                []string  `json:"redirect_uris"`
	GrantTypes                  []string  `json:"grant_types"`
	ResponseTypes               []string  `json:"response_types"`
	ApplicationType             string    `json:"application_type"`
	DpopBoundAccessTokens       bool      `json:"dpop_bound_access_tokens"`
	JWKSURI                     *string   `json:"jwks_uri,omitempty"`
	JWKS                        *[][]byte `json:"jwks,omitempty"`
	Scope                       string    `json:"scope"`
	TokenEndpointAuthMethod     string    `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg string    `json:"token_endpoint_auth_signing_alg"`
}
