package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/events/schedulers/parallel"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/repo"
	"github.com/bluesky-social/indigo/repomgr"
	"github.com/gorilla/websocket"
)

func main() {
	runFirehoseConsumer("ws://localhost:8080")
}

func runFirehoseConsumer(relayHost string) error {
	dialer := websocket.DefaultDialer
	u, err := url.Parse("wss://cocoon.hailey.at")
	if err != nil {
		return fmt.Errorf("invalid relayHost: %w", err)
	}

	u.Path = "xrpc/com.atproto.sync.subscribeRepos"
	conn, _, err := dialer.Dial(u.String(), http.Header{
		"User-Agent": []string{"cocoon-test/0.0.0"},
	})
	if err != nil {
		return fmt.Errorf("subscribing to firehose failed (dialing): %w", err)
	}

	rsc := &events.RepoStreamCallbacks{
		RepoCommit: func(evt *atproto.SyncSubscribeRepos_Commit) error {
			fmt.Println(evt.Repo)
			return handleRepoCommit(evt)
		},
		RepoIdentity: func(evt *atproto.SyncSubscribeRepos_Identity) error {
			fmt.Println(evt.Did, evt.Handle)
			return nil
		},
	}

	var scheduler events.Scheduler
	parallelism := 700
	scheduler = parallel.NewScheduler(parallelism, 1000, relayHost, rsc.EventHandler)

	return events.HandleRepoStream(context.TODO(), conn, scheduler, slog.Default())
}

func splitRepoPath(path string) (syntax.NSID, syntax.RecordKey, error) {
	parts := strings.SplitN(path, "/", 3)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid record path: %s", path)
	}
	collection, err := syntax.ParseNSID(parts[0])
	if err != nil {
		return "", "", err
	}
	rkey, err := syntax.ParseRecordKey(parts[1])
	if err != nil {
		return "", "", err
	}
	return collection, rkey, nil
}

func handleRepoCommit(evt *atproto.SyncSubscribeRepos_Commit) error {
	if evt.TooBig {
		return nil
	}

	did, err := syntax.ParseDID(evt.Repo)
	if err != nil {
		panic(err)
	}

	rr, err := repo.ReadRepoFromCar(context.TODO(), bytes.NewReader(evt.Blocks))
	if err != nil {
		panic(err)
	}

	for _, op := range evt.Ops {
		collection, rkey, err := splitRepoPath(op.Path)
		if err != nil {
			panic(err)
		}

		ek := repomgr.EventKind(op.Action)

		go func() {
			switch ek {
			case repomgr.EvtKindCreateRecord, repomgr.EvtKindUpdateRecord:
				rc, recordCBOR, err := rr.GetRecordBytes(context.TODO(), op.Path)
				if err != nil {
					panic(err)
				}

				if op.Cid == nil || lexutil.LexLink(rc) != *op.Cid {
					panic("nocid")
				}

				_ = collection
				_ = rkey
				_ = recordCBOR
				_ = did

			}
		}()
	}

	return nil
}
