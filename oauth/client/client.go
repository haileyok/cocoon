package client

import (
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Client struct {
	Metadata          *Metadata
	JWKS              jwk.Set
	IsLocalhostClient bool
}

func (c *Client) IsRedirectURIAllowed(requestedURI string) bool {
	if c.IsLocalhostClient {
		ru, err := url.Parse(requestedURI)
		if err != nil || ru.Scheme != "http" || !isLoopbackHost(ru.Hostname()) {
			return false
		}
		for _, registered := range c.Metadata.RedirectURIs {
			reg, err := url.Parse(registered)
			if err != nil {
				continue
			}
			if reg.Hostname() == ru.Hostname() && reg.Path == ru.Path {
				return true
			}
		}
		return false
	}
	for _, uri := range c.Metadata.RedirectURIs {
		if uri == requestedURI {
			return true
		}
	}
	return false
}
