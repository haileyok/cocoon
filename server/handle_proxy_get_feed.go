package server

import (
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

	appViewEndpoint, _, err := s.getAtprotoProxyEndpointFromRequest(e)
	if err != nil {
		e.Logger().Error("could not get atproto proxy", "error", err)
		return helpers.ServerError(e, nil)
	}

	appViewClient := xrpc.Client{
		Host: appViewEndpoint,
	}
	feedRecord, err := atproto.RepoGetRecord(e.Request().Context(), &appViewClient, "", feedUri.Collection().String(), feedUri.Authority().String(), feedUri.RecordKey().String())
	feedGeneratorDid := feedRecord.Value.Val.(*bsky.FeedGenerator).Did

	e.Set("proxyTokenLxm", "app.bsky.feed.getFeedSkeleton")
	e.Set("proxyTokenAud", feedGeneratorDid)

	return s.handleProxy(e)
}
