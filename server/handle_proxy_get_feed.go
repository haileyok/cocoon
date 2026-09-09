package server

import (
	"net/url"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleProxyBskyFeedGetFeed(e echo.Context) error {
	feedUri, err := syntax.ParseATURI(e.QueryParam("feed"))
	if err != nil {
		return helpers.InputError(e, to.StringPtr("invalid feed uri"))
	}

	appViewEndpoint, _, audience, err := s.getAtprotoProxyEndpointFromRequest(e)
	if err != nil {
		e.Logger().Error("could not get atproto proxy", "error", err)
		return helpers.ServerError(e, nil)
	}
	// Both operations are authorized against the selected AppView, before
	// looking up the generator whose DID is used in the outgoing service token.
	for _, method := range []string{"app.bsky.feed.getFeed", "app.bsky.feed.getFeedSkeleton"} {
		if !s.hasRPCScope(e, audience, method) {
			return helpers.InsufficientScopeError(e, "rpc:"+method+"?aud="+url.QueryEscape(audience))
		}
	}

	appViewClient := xrpc.Client{
		Host:   appViewEndpoint,
		Client: s.proxyHTTPClient,
	}
	feedRecord, err := atproto.RepoGetRecord(e.Request().Context(), &appViewClient, "", feedUri.Collection().String(), feedUri.Authority().String(), feedUri.RecordKey().String())
	feedGeneratorDid := feedRecord.Value.Val.(*bsky.FeedGenerator).Did

	e.Set("proxyTokenLxm", "app.bsky.feed.getFeedSkeleton")
	e.Set("proxyTokenAud", feedGeneratorDid)

	return s.handleProxy(e)
}
