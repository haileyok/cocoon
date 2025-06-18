package oauth

import "github.com/lestrrat-go/jwx/v2/jwk"

type Client struct {
	Metadata *ClientMetadata
	JWKS     jwk.Key
}
