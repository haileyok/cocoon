package provider

import (
	"context"
	"crypto"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/dpop"
)

type ClientAuth struct {
	Method string
	Alg    string
	Kid    string
	Jkt    string
	Jti    string
	Exp    *float64
}

func (ca *ClientAuth) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal OauthParRequest value")
	}
	return json.Unmarshal(b, ca)
}

func (ca ClientAuth) Value() (driver.Value, error) {
	return json.Marshal(ca)
}

type AuthenticateClientOptions struct {
	AllowMissingDpopProof bool
}

type AuthenticateClientRequestBase struct {
	ClientID            string  `form:"client_id" json:"client_id" validate:"required"`
	ClientAssertionType *string `form:"client_assertion_type" json:"client_assertion_type,omitempty"`
	ClientAssertion     *string `form:"client_assertion" json:"client_assertion,omitempty"`
}

func (p *Provider) AuthenticateClient(ctx context.Context, req AuthenticateClientRequestBase, proof *dpop.Proof, opts *AuthenticateClientOptions) (*oauth.Client, *ClientAuth, error) {
	client, err := p.ClientManager.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get client: %w", err)
	}

	if client.Metadata.DpopBoundAccessTokens && proof == nil && (opts == nil || !opts.AllowMissingDpopProof) {
		return nil, nil, errors.New("dpop proof required")
	}

	if proof != nil && !client.Metadata.DpopBoundAccessTokens {
		return nil, nil, errors.New("dpop proof not allowed for this client")
	}

	clientAuth, err := p.Authenticate(ctx, req, client)
	if err != nil {
		return nil, nil, err
	}

	return client, clientAuth, nil
}

func (p *Provider) Authenticate(_ context.Context, req AuthenticateClientRequestBase, client *oauth.Client) (*ClientAuth, error) {
	metadata := client.Metadata

	if metadata.TokenEndpointAuthMethod == "none" {
		return &ClientAuth{
			Method: "none",
		}, nil
	}

	if metadata.TokenEndpointAuthMethod == "private_key_jwt" {
		if req.ClientAssertion == nil {
			return nil, errors.New(`client authentication method "private_key_jwt" requires a "client_assertion`)
		}

		if req.ClientAssertionType == nil || *req.ClientAssertionType != constants.ClientAssertionTypeJwtBearer {
			return nil, fmt.Errorf("unsupported client_assertion_type %s", *req.ClientAssertionType)
		}

		token, _, err := jwt.NewParser().ParseUnverified(*req.ClientAssertion, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("error parsing client assertion: %w", err)
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New(`"kid" required in client_assertion`)
		}

		var rawKey any
		if err := client.JWKS.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to extract raw key: %w", err)
		}

		token, err = jwt.Parse(*req.ClientAssertion, func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return rawKey, nil
		})
		if err != nil {
			return nil, fmt.Errorf(`unable to verify "client_assertion" jwt: %w`, err)
		}

		if !token.Valid {
			return nil, errors.New("client_assertion jwt is invalid")
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("no claims in client_assertion jwt")
		}

		sub, _ := claims["sub"].(string)
		if sub != metadata.ClientID {
			return nil, errors.New("subject must be client_id")
		}

		aud, _ := claims["aud"].(string)
		if aud != "" && aud != "https://"+p.hostname {
			return nil, fmt.Errorf("audience must be %s, got %s", "https://"+p.hostname, aud)
		}

		iat, iatOk := claims["iat"].(float64)
		if !iatOk {
			return nil, errors.New(`invalid client_assertion jwt: "iat" is missing`)
		}

		iatTime := time.Unix(int64(iat), 0)
		if time.Since(iatTime) > constants.ClientAssertionMaxAge {
			return nil, errors.New("client_assertion jwt too old")
		}

		jti, _ := claims["jti"].(string)
		if jti == "" {
			return nil, errors.New(`invalid client_assertion jwt: "jti" is missing`)
		}

		var exp *float64
		if maybeExp, ok := claims["exp"].(float64); ok {
			exp = &maybeExp
		}

		alg := token.Header["alg"].(string)

		thumbBytes, err := client.JWKS.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate thumbprint: %w", err)
		}

		thumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

		return &ClientAuth{
			Method: "private_key_jwt",
			Jti:    jti,
			Exp:    exp,
			Jkt:    thumb,
			Alg:    alg,
			Kid:    kid,
		}, nil
	}

	return nil, fmt.Errorf("auth method %s is not implemented in this pds", metadata.TokenEndpointAuthMethod)
}
