package server

import (
	"context"
	"time"

	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/btcsuite/websocket"
	"github.com/haileyok/cocoon/metrics"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleSyncSubscribeRepos(e echo.Context) error {
	ctx, cancel := context.WithCancel(e.Request().Context())
	defer cancel()

	logger := s.logger.With("component", "subscribe-repos-websocket")

	conn, err := websocket.Upgrade(e.Response().Writer, e.Request(), e.Response().Header(), 1<<10, 1<<10)
	if err != nil {
		logger.Error("unable to establish websocket with relay", "err", err)
		return err
	}

	ident := e.RealIP() + "-" + e.Request().UserAgent()
	logger = logger.With("ident", ident)
	logger.Info("new connection established")

	metrics.RelaysConnected.WithLabelValues(ident).Inc()
	defer func() {
		metrics.RelaysConnected.WithLabelValues(ident).Dec()
	}()

	evts, evtManCancel, err := s.evtman.Subscribe(ctx, ident, func(evt *events.XRPCStreamEvent) bool {
		return true
	}, nil)
	if err != nil {
		return err
	}
	defer evtManCancel()

	// drop the connection whenever a subscriber disconnects from the socket, we should get errors
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if _, _, err := conn.ReadMessage(); err != nil {
					logger.Warn("websocket error", "err", err)
					cancel()
					return
				}
			}
		}
	}()

	header := events.EventHeader{Op: events.EvtKindMessage}
	for evt := range evts {
		func() {
			defer func() {
				metrics.RelaySends.WithLabelValues(ident, header.MsgType).Inc()
			}()

			wc, err := conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				logger.Error("error writing message to relay", "err", err)
				return
			}

			if ctx.Err() != nil {
				logger.Error("context error", "err", err)
				return
			}

			var obj util.CBOR
			switch {
			case evt.Error != nil:
				header.Op = events.EvtKindErrorFrame
				obj = evt.Error
			case evt.RepoCommit != nil:
				header.MsgType = "#commit"
				obj = evt.RepoCommit
			case evt.RepoIdentity != nil:
				header.MsgType = "#identity"
				obj = evt.RepoIdentity
			case evt.RepoAccount != nil:
				header.MsgType = "#account"
				obj = evt.RepoAccount
			case evt.RepoInfo != nil:
				header.MsgType = "#info"
				obj = evt.RepoInfo
			default:
				logger.Warn("unrecognized event kind")
				return
			}

			if err := header.MarshalCBOR(wc); err != nil {
				logger.Error("failed to write header to relay", "err", err)
				return
			}

			if err := obj.MarshalCBOR(wc); err != nil {
				logger.Error("failed to write event to relay", "err", err)
				return
			}

			if err := wc.Close(); err != nil {
				logger.Error("failed to flush-close our event write", "err", err)
				return
			}
		}()
	}

	// we should tell the relay to request a new crawl at this point if we got disconnected
	// use a new context since the old one might be cancelled at this point
	go func() {
		retryCtx, retryCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer retryCancel()
		if err := s.requestCrawl(retryCtx); err != nil {
			logger.Error("error requesting crawls", "err", err)
		}
	}()

	return nil
}
