package sqlite_blockstore

import (
	"context"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	"gorm.io/gorm/clause"
)

type SqliteBlockstore struct {
	db       *db.DB
	did      string
	readonly bool
	inserts  map[cid.Cid]blocks.Block
}

func New(did string, db *db.DB) *SqliteBlockstore {
	return &SqliteBlockstore{
		did:      did,
		db:       db,
		readonly: false,
		inserts:  map[cid.Cid]blocks.Block{},
	}
}

func NewReadOnly(did string, db *db.DB) *SqliteBlockstore {
	return &SqliteBlockstore{
		did:      did,
		db:       db,
		readonly: true,
		inserts:  map[cid.Cid]blocks.Block{},
	}
}

func (bs *SqliteBlockstore) Get(ctx context.Context, cid cid.Cid) (blocks.Block, error) {
	var block models.Block

	maybeBlock, ok := bs.inserts[cid]
	if ok {
		return maybeBlock, nil
	}

	if err := bs.db.Raw(ctx, "SELECT * FROM blocks WHERE did = ? AND cid = ?", nil, bs.did, cid.Bytes()).Scan(&block).Error; err != nil {
		return nil, err
	}

	// GORM's Scan does not error when no rows match; treat a missing row as a
	// not-found error so callers (eg partial MST loads) see proper semantics.
	if len(block.Value) == 0 {
		return nil, ipld.ErrNotFound{
			Cid: cid,
		}
	}

	b, err := blocks.NewBlockWithCid(block.Value, cid)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (bs *SqliteBlockstore) Put(ctx context.Context, block blocks.Block) error {
	bs.inserts[block.Cid()] = block

	if bs.readonly {
		return nil
	}

	b := models.Block{
		Did:   bs.did,
		Cid:   block.Cid().Bytes(),
		Rev:   syntax.NewTIDNow(0).String(), // TODO: WARN, this is bad. don't do this
		Value: block.RawData(),
	}

	if err := bs.db.Create(ctx, &b, []clause.Expression{clause.OnConflict{
		Columns:   []clause.Column{{Name: "did"}, {Name: "cid"}},
		UpdateAll: true,
	}}).Error; err != nil {
		return err
	}

	return nil
}

func (bs *SqliteBlockstore) DeleteBlock(ctx context.Context, c cid.Cid) error {
	return bs.DeleteMany(ctx, []cid.Cid{c})
}

// DeleteMany removes the given blocks from the underlying storage. Blocks
// that are not present are ignored (delete is idempotent), matching the
// reference PDS behavior for removedCids.
func (bs *SqliteBlockstore) DeleteMany(ctx context.Context, cids []cid.Cid) error {
	if len(cids) == 0 {
		return nil
	}

	if bs.readonly {
		return fmt.Errorf("cannot delete from readonly blockstore")
	}

	did := bs.did
	if err := bs.db.Transaction(ctx, func(tx *db.DB) error {
		for _, c := range cids {
			if err := tx.Exec(ctx, "DELETE FROM blocks WHERE did = ? AND cid = ?", nil, did, c.Bytes()).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	for _, c := range cids {
		delete(bs.inserts, c)
	}

	return nil
}

func (bs *SqliteBlockstore) Has(context.Context, cid.Cid) (bool, error) {
	panic("not implemented")
}

func (bs *SqliteBlockstore) GetSize(context.Context, cid.Cid) (int, error) {
	panic("not implemented")
}

func (bs *SqliteBlockstore) PutMany(ctx context.Context, blocks []blocks.Block) error {
	tx := bs.db.Begin(ctx)

	for _, block := range blocks {
		bs.inserts[block.Cid()] = block

		if bs.readonly {
			continue
		}

		b := models.Block{
			Did:   bs.did,
			Cid:   block.Cid().Bytes(),
			Rev:   syntax.NewTIDNow(0).String(), // TODO: WARN, this is bad. don't do this
			Value: block.RawData(),
		}

		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "did"}, {Name: "cid"}},
			UpdateAll: true,
		}).Create(&b).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	if bs.readonly {
		return nil
	}

	tx.Commit()

	return nil
}

func (bs *SqliteBlockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	return nil, fmt.Errorf("iteration not allowed on sqlite blockstore")
}

func (bs *SqliteBlockstore) HashOnRead(enabled bool) {
	panic("not implemented")
}
