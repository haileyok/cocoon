package helpers

import (
	"net/http"
	"time"

	"github.com/bluesky-social/gttp"
)

// SafeFetchClientMaxBodyBytes caps response bodies for request-controlled
// fetches (OAuth client metadata / JWKS documents). 2 MiB is orders of
// magnitude beyond any legitimate OAuth metadata document while bounding
// memory use on hostile servers.
const SafeFetchClientMaxBodyBytes = 2 << 20

// NewSafeFetchClient returns the HTTP client used for fetches where the URL
// (or the host it resolves to) is influenced by an external party — notably
// OAuth client_id / jwks_uri lookups, whose targets are chosen by the
// registering client.
//
// It uses gttp with strict SSRF protection: the IP policy (loopback, private,
// link-local, CGNAT, NAT64, IMDS ranges) applies to the initial request URL
// and to every redirect, validation is bound to the actual dial (a hostname
// resolving to a blocked address cannot be fetched), https->http downgrades
// are refused, and response bodies are size-capped.
//
// Note for local development: strict SSRF protection intentionally blocks
// loopback targets. The OAuth "http://localhost" client_id is exempt because
// its metadata is built virtually and never fetched; a loopback-hosted client
// instance must be registered through a non-loopback origin.
func NewSafeFetchClient() *http.Client {
	return gttp.New(
		gttp.WithStrictSSRFProtection(),
		gttp.WithNoProxy(),
		gttp.WithMaxResponseBodyBytes(SafeFetchClientMaxBodyBytes),
		gttp.WithTimeout(10*time.Second),
		gttp.WithNoRetries(),
	)
}
