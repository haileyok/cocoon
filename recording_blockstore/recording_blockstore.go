package recording_blockstore

import (
	"context"
	"fmt"

	blockformat "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
)

type RecordingBlockstore struct {
	base blockstore.Blockstore

	inserts map[cid.Cid]blockformat.Block
	reads   map[cid.Cid]blockformat.Block
	// deletions recorded by CID, so they can be filtered out of any derived
	// views of this session's writes
	deleted map[cid.Cid]struct{}
}

func New(base blockstore.Blockstore) *RecordingBlockstore {
	return &RecordingBlockstore{
		base:    base,
		inserts: make(map[cid.Cid]blockformat.Block),
		reads:   make(map[cid.Cid]blockformat.Block),
		deleted: make(map[cid.Cid]struct{}),
	}
}

func (bs *RecordingBlockstore) Has(ctx context.Context, c cid.Cid) (bool, error) {
	return bs.base.Has(ctx, c)
}

func (bs *RecordingBlockstore) Get(ctx context.Context, c cid.Cid) (blockformat.Block, error) {
	b, err := bs.base.Get(ctx, c)
	if err != nil {
		return nil, err
	}
	bs.reads[c] = b
	return b, nil
}

func (bs *RecordingBlockstore) GetSize(ctx context.Context, c cid.Cid) (int, error) {
	return bs.base.GetSize(ctx, c)
}

func (bs *RecordingBlockstore) DeleteBlock(ctx context.Context, c cid.Cid) error {
	if err := bs.base.DeleteBlock(ctx, c); err != nil {
		return err
	}
	bs.deleted[c] = struct{}{}
	delete(bs.inserts, c)
	return nil
}

// DeleteMany removes several blocks at once from the base store, recording
// the deletions so they are excluded from GetWriteLog.
func (bs *RecordingBlockstore) DeleteMany(ctx context.Context, cids []cid.Cid) error {
	for _, c := range cids {
		if err := bs.DeleteBlock(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func (bs *RecordingBlockstore) Put(ctx context.Context, block blockformat.Block) error {
	if err := bs.base.Put(ctx, block); err != nil {
		return err
	}
	bs.inserts[block.Cid()] = block
	return nil
}

func (bs *RecordingBlockstore) PutMany(ctx context.Context, blocks []blockformat.Block) error {
	if err := bs.base.PutMany(ctx, blocks); err != nil {
		return err
	}

	for _, b := range blocks {
		bs.inserts[b.Cid()] = b
	}

	return nil
}

func (bs *RecordingBlockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	return nil, fmt.Errorf("iteration not allowed on recording blockstore")
}

func (bs *RecordingBlockstore) HashOnRead(enabled bool) {
}

func (bs *RecordingBlockstore) GetWriteLog() map[cid.Cid]blockformat.Block {
	return bs.inserts
}

func (bs *RecordingBlockstore) GetReadLog() []blockformat.Block {
	var blocks []blockformat.Block
	for _, b := range bs.reads {
		blocks = append(blocks, b)
	}
	return blocks
}
