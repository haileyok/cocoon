package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/btcsuite/websocket"
	"github.com/haileyok/cocoon/metrics"
	"github.com/labstack/echo/v4"
)

// errSkipEvent marks an event that cannot be represented as a subscribeRepos
// frame. It is not fatal to the connection: the caller logs it and moves on.
var errSkipEvent = errors.New("event has no subscribeRepos frame type")

// wsWriteTimeout bounds how long a single frame write may block.
//
// The websocket write path is synchronous, and Upgrade clears the deadlines
// net/http had set on the connection, so nothing bounds a write by default. A
// relay that stays connected but stops reading fills the socket buffers and
// blocks that write indefinitely — and a blocked write cannot be interrupted by
// cancelling the context, so the handler would never reach its deferred
// teardown. This is a var so tests can lower it.
var wsWriteTimeout = 30 * time.Second

// Keepalive settings.
//
// A subscribeRepos stream can be silent for a long time — an idle PDS emits
// nothing at all — and while it is silent nothing on the wire holds the
// connection open. Middleboxes drop idle websockets, and a consumer's liveness
// check only resets when it hears a pong, so a quiet host looks dead to both.
// The handler therefore pings on an interval, and treats a peer that has
// stopped answering as gone.
//
// These are vars so tests can lower them.
var (
	wsPingInterval = 30 * time.Second
	wsPongTimeout  = 90 * time.Second
)

// subscribeReposMsgType maps a stream event to its com.atproto.sync.subscribeRepos
// message frame type and the object to serialize. The bool is false for events
// that are not message frames (e.g. error frames, handled separately).
func subscribeReposMsgType(evt *events.XRPCStreamEvent) (string, util.CBOR, bool) {
	switch {
	case evt.RepoCommit != nil:
		return "#commit", evt.RepoCommit, true
	case evt.RepoSync != nil:
		return "#sync", evt.RepoSync, true
	case evt.RepoIdentity != nil:
		return "#identity", evt.RepoIdentity, true
	case evt.RepoAccount != nil:
		return "#account", evt.RepoAccount, true
	case evt.RepoInfo != nil:
		return "#info", evt.RepoInfo, true
	default:
		return "", nil, false
	}
}

// writeEventFrame writes a single subscribeRepos frame — the CBOR event header
// followed by the event body — to the relay connection, returning the message
// type that was written (empty for error frames).
//
// btcsuite/websocket buffers each frame inside the connection and flushes it
// only when the writer is closed. A writer abandoned without Close is flushed
// by the *next* NextWriter call rather than discarded, so a partial frame would
// reach the relay and be read as a malformed event. Every error path here
// returns before Close and leaves the buffer untouched; the caller tears the
// connection down so nothing stale is ever written.
func writeEventFrame(conn *websocket.Conn, header *events.EventHeader, evt *events.XRPCStreamEvent) (string, error) {
	var obj util.CBOR

	if evt.Error != nil {
		header.Op = events.EvtKindErrorFrame
		header.MsgType = ""
		obj = evt.Error
	} else {
		msgType, o, ok := subscribeReposMsgType(evt)
		if !ok {
			return "", errSkipEvent
		}
		header.Op = events.EvtKindMessage
		header.MsgType = msgType
		obj = o
	}

	// Bound the whole frame: NextWriter, the CBOR writes below and Close all
	// flush through the same socket, and any of them can block on a stalled peer.
	if err := conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		return "", fmt.Errorf("setting websocket write deadline: %w", err)
	}

	wc, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return "", fmt.Errorf("opening websocket writer: %w", err)
	}

	if err := header.MarshalCBOR(wc); err != nil {
		return "", fmt.Errorf("writing event header: %w", err)
	}
	if err := obj.MarshalCBOR(wc); err != nil {
		return "", fmt.Errorf("writing event body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return "", fmt.Errorf("flushing event frame: %w", err)
	}

	return header.MsgType, nil
}

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

	// Upgrade hijacks the connection, so net/http will never close it for us.
	// Send a close frame first: a bare TCP close is indistinguishable from a
	// crash on the peer's side — the relay logs it as "close 1006 (abnormal
	// closure)" — which turns a routine teardown into an apparent outage.
	defer func() {
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, ""),
			time.Now().Add(wsWriteTimeout)); err != nil && !errors.Is(err, websocket.ErrCloseSent) {
			logger.Warn("error sending websocket close frame", "err", err)
		}
		if err := conn.Close(); err != nil {
			logger.Warn("error closing websocket", "err", err)
		}
	}()

	// A subscribeRepos stream can be silent for minutes: an idle PDS emits
	// nothing at all. Two things follow, and both are handled here.
	//
	// First, the handler must keep the connection observably alive. A websocket
	// carrying no traffic in either direction gets dropped by middleboxes, and a
	// consumer reads the silence as a dead host. The send loop pings on
	// wsPingInterval below.
	//
	// Second, the handler must notice a peer that has stopped answering. The
	// read deadline is refreshed by anything the peer sends — pong, ping or data
	// — and our own pings guarantee a live peer answers within one interval, so
	// silence for wsPongTimeout means the peer is gone even though TCP has not
	// noticed. A half-open connection (no FIN) produces no read error of its own,
	// so without this the handler would sit on a dead socket indefinitely.
	if err := conn.SetReadDeadline(time.Now().Add(wsPongTimeout)); err != nil {
		return err
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongTimeout))
	})
	// Mirrors the ping handler indigo's own relay uses downstream: keep
	// answering pings, and treat transient write failures as survivable rather
	// than tearing the stream down on a moment's contention.
	conn.SetPingHandler(func(message string) error {
		if err := conn.SetReadDeadline(time.Now().Add(wsPongTimeout)); err != nil {
			return err
		}
		err := conn.WriteControl(websocket.PongMessage, []byte(message),
			time.Now().Add(wsWriteTimeout))
		if errors.Is(err, websocket.ErrCloseSent) {
			return nil
		}
		if e, ok := err.(net.Error); ok && e.Temporary() {
			return nil
		}
		return err
	})

	var since *int64
	if cursorStr := e.QueryParam("cursor"); cursorStr != "" {
		cursor, err := strconv.ParseInt(cursorStr, 10, 64)
		if err != nil {
			logger.Warn("invalid cursor parameter", "cursor", cursorStr, "err", err)
		} else {
			since = &cursor
			logger.Info("subscribing with cursor", "cursor", cursor)
		}
	}

	metrics.RelaysConnected.WithLabelValues(ident).Inc()
	defer func() {
		metrics.RelaysConnected.WithLabelValues(ident).Dec()
	}()

	evts, evtManCancel, err := s.evtman.Subscribe(ctx, ident, func(evt *events.XRPCStreamEvent) bool {
		return true
	}, since)
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

	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()

forward:
	for {
		select {
		case <-ctx.Done():
			// The relay went away. The send loop cannot wait on the event
			// channel alone: cancelling this context closes nothing, so
			// evtManCancel — whose defer runs below, in this goroutine — would
			// never run and the subscription would never be retired.
			break forward
		case <-ping.C:
			// Keep the stream observably alive; see the keepalive comment above.
			// A failed ping is not itself fatal — the read deadline is what
			// reaps a peer that has stopped answering, and a momentary write
			// failure should not tear down an otherwise healthy stream.
			if err := conn.WriteControl(websocket.PingMessage, nil,
				time.Now().Add(wsWriteTimeout)); err != nil {
				logger.Warn("error pinging relay", "err", err)
			}
		case evt, ok := <-evts:
			if !ok {
				// The event manager retired this subscription (e.g. a slow
				// consumer); no further events will arrive.
				break forward
			}

			msgType, err := writeEventFrame(conn, &header, evt)
			if err != nil {
				if errors.Is(err, errSkipEvent) {
					logger.Warn("unrecognized event kind")
					continue
				}

				logger.Error("error writing message to relay", "err", err)
				break forward
			}

			metrics.RelaySends.WithLabelValues(ident, msgType).Inc()
		}
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
