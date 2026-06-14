package server

import (
	"bytes"
	"context"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/carstore"
	"github.com/bluesky-social/indigo/events"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
)

// buildSyncCar serializes a single-block CAR containing the signed commit at
// root. The CAR header lists the commit CID as its first root, as required by
// the com.atproto.sync.subscribeRepos #sync event.
func (s *Server) buildSyncCar(ctx context.Context, did string, root cid.Cid) ([]byte, error) {
	bs := s.getBlockstore(did)

	buf := new(bytes.Buffer)
	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{root},
		Version: 1,
	})
	if err != nil {
		return nil, err
	}
	if _, err := carstore.LdWrite(buf, hb); err != nil {
		return nil, err
	}

	blk, err := bs.Get(ctx, root)
	if err != nil {
		return nil, err
	}
	if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// emitRepoSync broadcasts a #sync event announcing the repo's current head. Per
// Sync v1.1 this authoritatively advertises the repo's latest commit so relays
// can recover state without replaying the commit stream.
func (s *Server) emitRepoSync(ctx context.Context, did, rev string, root cid.Cid) error {
	blocks, err := s.buildSyncCar(ctx, did, root)
	if err != nil {
		return err
	}

	s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
		RepoSync: &atproto.SyncSubscribeRepos_Sync{
			Did:    did,
			Rev:    rev,
			Blocks: blocks,
			Time:   time.Now().Format(time.RFC3339Nano),
		},
	})

	return nil
}
