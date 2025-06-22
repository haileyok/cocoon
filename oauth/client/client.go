package client

import "github.com/lestrrat-go/jwx/v2/jwk"

type Client struct {
	Metadata *Metadata
	JWKS     jwk.Key
}
