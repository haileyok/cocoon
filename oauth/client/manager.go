package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Manager struct {
	cli           *http.Client
	logger        *slog.Logger
	jwksCache     cache.Cache[string, jwk.Key]
	metadataCache cache.Cache[string, Metadata]
}

type ManagerArgs struct {
	Cli    *http.Client
	Logger *slog.Logger
}

func NewManager(args ManagerArgs) *Manager {
	if args.Logger == nil {
		args.Logger = slog.Default()
	}

	if args.Cli == nil {
		args.Cli = http.DefaultClient
	}

	jwksCache := cache.NewCache[string, jwk.Key]().WithLRU().WithMaxKeys(500).WithTTL(5 * time.Minute)
	metadataCache := cache.NewCache[string, Metadata]().WithLRU().WithMaxKeys(500).WithTTL(5 * time.Minute)

	return &Manager{
		cli:           args.Cli,
		logger:        args.Logger,
		jwksCache:     jwksCache,
		metadataCache: metadataCache,
	}
}

func (cm *Manager) GetClient(ctx context.Context, clientId string) (*Client, error) {
	metadata, err := cm.getClientMetadata(ctx, clientId)
	if err != nil {
		return nil, err
	}

	var jwks jwk.Key
	if metadata.TokenEndpointAuthMethod == "private_key_jwt" {
		if metadata.JWKS != nil && len(metadata.JWKS.Keys) > 0 {
			// TODO: this is kinda bad but whatever for now. there could obviously be more than one jwk, and we need to
			// make sure we use the right one
			b, err := json.Marshal(metadata.JWKS.Keys[0])
			if err != nil {
				return nil, err
			}

			k, err := helpers.ParseJWKFromBytes(b)
			if err != nil {
				return nil, err
			}

			jwks = k
		} else if metadata.JWKS != nil {
		} else if metadata.JWKSURI != nil {
			maybeJwks, err := cm.getClientJwks(ctx, clientId, *metadata.JWKSURI)
			if err != nil {
				return nil, err
			}

			jwks = maybeJwks
		} else {
			return nil, fmt.Errorf("no valid jwks found in oauth client metadata")
		}
	}

	return &Client{
		Metadata: metadata,
		JWKS:     jwks,
	}, nil
}

func (cm *Manager) getClientMetadata(ctx context.Context, clientId string) (*Metadata, error) {
	metadataCached, ok := cm.metadataCache.Get(clientId)
	if !ok {
		req, err := http.NewRequestWithContext(ctx, "GET", clientId, nil)
		if err != nil {
			return nil, err
		}

		resp, err := cm.cli.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			return nil, fmt.Errorf("fetching client metadata returned response code %d", resp.StatusCode)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading bytes from client response: %w", err)
		}

		validated, err := validateAndParseMetadata(clientId, b)
		if err != nil {
			return nil, err
		}

		return validated, nil
	} else {
		return &metadataCached, nil
	}
}

func (cm *Manager) getClientJwks(ctx context.Context, clientId, jwksUri string) (jwk.Key, error) {
	jwks, ok := cm.jwksCache.Get(clientId)
	if !ok {
		req, err := http.NewRequestWithContext(ctx, "GET", jwksUri, nil)
		if err != nil {
			return nil, err
		}

		resp, err := cm.cli.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			return nil, fmt.Errorf("fetching client jwks returned response code %d", resp.StatusCode)
		}

		type Keys struct {
			Keys []map[string]any `json:"keys"`
		}

		var keys Keys
		if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
			return nil, fmt.Errorf("error unmarshaling keys response: %w", err)
		}

		if len(keys.Keys) == 0 {
			return nil, errors.New("no keys in jwks response")
		}

		// TODO: this is again bad, we should be figuring out which one we need to use...
		b, err := json.Marshal(keys.Keys[0])
		if err != nil {
			return nil, fmt.Errorf("could not marshal key: %w", err)
		}

		k, err := helpers.ParseJWKFromBytes(b)
		if err != nil {
			return nil, err
		}

		jwks = k
	}

	return jwks, nil
}

func validateAndParseMetadata(clientId string, b []byte) (*Metadata, error) {
	var metadataMap map[string]any
	if err := json.Unmarshal(b, &metadataMap); err != nil {
		return nil, fmt.Errorf("error unmarshaling metadata: %w", err)
	}

	_, jwksOk := metadataMap["jwks"].(string)
	_, jwksUriOk := metadataMap["jwks_uri"].(string)
	if jwksOk && jwksUriOk {
		return nil, errors.New("jwks_uri and jwks are mutually exclusive")
	}

	for _, k := range []string{
		"default_max_age",
		"userinfo_signed_response_alg",
		"id_token_signed_response_alg",
		"userinfo_encryhpted_response_alg",
		"authorization_encrypted_response_enc",
		"authorization_encrypted_response_alg",
		"tls_client_certificate_bound_access_tokens",
	} {
		_, kOk := metadataMap[k]
		if kOk {
			return nil, fmt.Errorf("unsupported `%s` parameter", k)
		}
	}

	var metadata Metadata
	if err := json.Unmarshal(b, &metadata); err != nil {
		return nil, fmt.Errorf("error unmarshaling metadata: %w", err)
	}

	u, err := url.Parse(metadata.ClientURI)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client uri: %w", err)
	}

	if isLocalHostname(u.Hostname()) {
		return nil, fmt.Errorf("`client_uri` hostname is invalid: %s", u.Hostname())
	}

	if metadata.Scope == "" {
		return nil, errors.New("missing `scopes` scope")
	}

	scopes := strings.Split(metadata.Scope, " ")
	if !slices.Contains(scopes, "atproto") {
		return nil, errors.New("missing `atproto` scope")
	}

	scopesMap := map[string]bool{}
	for _, scope := range scopes {
		if scopesMap[scope] {
			return nil, fmt.Errorf("duplicate scope `%s`", scope)
		}

		// TODO: check for unsupported scopes

		scopesMap[scope] = true
	}

	grantTypesMap := map[string]bool{}
	for _, gt := range metadata.GrantTypes {
		if grantTypesMap[gt] {
			return nil, fmt.Errorf("duplicate grant type `%s`", gt)
		}

		switch gt {
		case "implicit":
			return nil, errors.New("grantg type `implicit` is not allowed")
		case "authorization_code", "refresh_token":
			// TODO check if this grant type is supported
		default:
			return nil, fmt.Errorf("grant tyhpe `%s` is not supported", gt)
		}

		grantTypesMap[gt] = true
	}

	if metadata.ClientID != clientId {
		return nil, errors.New("`client_id` does not match")
	}

	subjectType, subjectTypeOk := metadataMap["subject_type"].(string)
	if subjectTypeOk && subjectType != "public" {
		return nil, errors.New("only public `subject_type` is supported")
	}

	switch metadata.TokenEndpointAuthMethod {
	case "none":
		if metadata.TokenEndpointAuthSigningAlg != "" {
			return nil, errors.New("token_endpoint_auth_method `none` must not have token_endpoint_auth_signing_alg")
		}
	case "private_key_jwt":
		if metadata.JWKS == nil && metadata.JWKSURI == nil {
			return nil, errors.New("private_key_jwt auth method requires jwks or jwks_uri")
		}

		if metadata.JWKS != nil && len(metadata.JWKS.Keys) == 0 {
			return nil, errors.New("private_key_jwt auth method requires atleast one key in jwks")
		}

		if metadata.TokenEndpointAuthSigningAlg == "" {
			return nil, errors.New("missing token_endpoint_auth_signing_alg in client metadata")
		}
	default:
		return nil, fmt.Errorf("unsupported client authentication method `%s`", metadata.TokenEndpointAuthMethod)
	}

	if !metadata.DpopBoundAccessTokens {
		return nil, errors.New("dpop_bound_access_tokens must be true")
	}

	if !slices.Contains(metadata.ResponseTypes, "code") {
		return nil, errors.New("response_types must inclue `code`")
	}

	if !slices.Contains(metadata.GrantTypes, "authorization_code") {
		return nil, errors.New("the `code` response type requires that `grant_types` contains `authorization_code`")
	}

	if len(metadata.RedirectURIs) == 0 {
		return nil, errors.New("at least one `redirect_uri` is required")
	}

	if metadata.ApplicationType == "native" && metadata.TokenEndpointAuthMethod != "none" {
		return nil, errors.New("native clients must authenticate using `none` method")
	}

	if metadata.ApplicationType == "web" && slices.Contains(metadata.GrantTypes, "implicit") {
		for _, ruri := range metadata.RedirectURIs {
			u, err := url.Parse(ruri)
			if err != nil {
				return nil, fmt.Errorf("error parsing redirect uri: %w", err)
			}

			if u.Scheme != "https" {
				return nil, errors.New("web clients must use https redirect uris")
			}

			if u.Hostname() == "localhost" {
				return nil, errors.New("web clients must not use localhost as the hostname")
			}
		}
	}

	for _, ruri := range metadata.RedirectURIs {
		u, err := url.Parse(ruri)
		if err != nil {
			return nil, fmt.Errorf("error parsing redirect uri: %w", err)
		}

		if u.User != nil {
			if u.User.Username() != "" {
				return nil, fmt.Errorf("redirect uri %s must not contain credentials", ruri)
			}

			if _, hasPass := u.User.Password(); hasPass {
				return nil, fmt.Errorf("redirect uri %s must not contain credentials", ruri)
			}
		}

		switch true {
		case u.Hostname() == "localhost":
			return nil, errors.New("loopback redirect uri is not allowed (use explicit ips instead)")
		case u.Hostname() == "127.0.0.1", u.Hostname() == "[::1]":
			if metadata.ApplicationType != "native" {
				return nil, errors.New("loopback redirect uris are only allowed for native apps")
			}

			if u.Port() != "" {
				// reference impl doesn't do anything with this?
			}

			if u.Scheme != "http" {
				return nil, fmt.Errorf("loopback redirect uri %s must use http", ruri)
			}
		case u.Scheme == "http":
			return nil, errors.New("only loopbvack redirect uris are allowed to use the `http` scheme")
		case u.Scheme == "https":
			if isLocalHostname(u.Hostname()) {
				return nil, fmt.Errorf("redirect uri %s's domain must not be a local hostname", ruri)
			}
		case strings.Contains(u.Scheme, "."):
			if metadata.ApplicationType != "native" {
				return nil, errors.New("private-use uri scheme redirect uris are only allowed for native apps")
			}

			revdomain := reverseDomain(u.Scheme)

			if isLocalHostname(revdomain) {
				return nil, errors.New("private use uri scheme redirect uris must not be local hostnames")
			}

			if strings.HasPrefix(u.String(), fmt.Sprintf("%s://", u.Scheme)) || u.Hostname() != "" || u.Port() != "" {
				return nil, fmt.Errorf("private use uri scheme must be in the form ")
			}
		default:
			return nil, fmt.Errorf("invalid redirect uri scheme `%s`", u.Scheme)
		}
	}

	return &metadata, nil
}

func isLocalHostname(hostname string) bool {
	pts := strings.Split(hostname, ".")
	if len(pts) < 2 {
		return true
	}

	tld := strings.ToLower(pts[len(pts)-1])
	return tld == "test" || tld == "local" || tld == "localhost" || tld == "invalid" || tld == "example"
}

func reverseDomain(domain string) string {
	pts := strings.Split(domain, ".")
	slices.Reverse(pts)
	return strings.Join(pts, ".")
}
