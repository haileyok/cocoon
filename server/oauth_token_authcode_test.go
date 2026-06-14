package server

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/oauth/client"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
)

func attachOauthProvider(t *testing.T, s *Server) {
	t.Helper()
	s.oauthProvider = provider.NewProvider(provider.Args{
		Hostname: testHostname,
		ClientManagerArgs: client.ManagerArgs{
			Cli:    http.DefaultClient,
			Logger: s.logger,
		},
		DpopManagerArgs: dpop.ManagerArgs{
			NonceSecret:           []byte("test-nonce-secret"),
			NonceRotationInterval: time.Hour,
			Logger:                s.logger,
			Hostname:              testHostname,
		},
	})
}

// TestOauthTokenAuthorizationCodeMissingActor drives the authorization_code
// grant with an authorization request whose subject has no repo (e.g. the
// account was deleted between consent and token exchange). The handler must
// return an error response, not dereference a nil repo and panic.
func TestOauthTokenAuthorizationCodeMissingActor(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	attachOauthProvider(t, s)

	const (
		clientID    = "http://localhost"
		redirectURI = "http://127.0.0.1/"
		code        = "test-auth-code"
	)

	authReq := provider.OauthAuthorizationRequest{
		RequestId: "req-1",
		ClientId:  clientID,
		Parameters: provider.ParRequest{
			AuthenticateClientRequestBase: provider.AuthenticateClientRequestBase{ClientID: clientID},
			ResponseType:                  "code",
			RedirectURI:                   redirectURI,
			State:                         "state-1",
			Scope:                         "atproto",
		},
		ExpiresAt: time.Now().Add(time.Hour),
		Sub:       to.StringPtr("did:plc:doesnotexistxxxxxxxxxxxx"),
		Code:      to.StringPtr(code),
	}
	if err := s.db.Create(ctx, &authReq, nil).Error; err != nil {
		t.Fatalf("seed authorization request: %v", err)
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {clientID},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	c, rec := newRequestContext(http.MethodPost, "/oauth/token", form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})

	// Must not panic, and must surface an error response (not a token).
	if err := s.handleOauthToken(c); err != nil {
		c.Error(err)
	}
	if rec.Code/100 == 2 {
		t.Fatalf("expected an error response for a missing actor, got %d", rec.Code)
	}
}
