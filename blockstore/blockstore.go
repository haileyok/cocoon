package blockstore

import (
	"context"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm/clause"
)

type SqliteBlockstore struct {
	db       *db.DB
	did      string
	readonly bool
	inserts  []blocks.Block
}

func New(did string, db *db.DB) *SqliteBlockstore {
	return &SqliteBlockstore{
		did:      did,
		db:       db,
		readonly: false,
		inserts:  []blocks.Block{},
	}
}

func NewReadOnly(did string, db *db.DB) *SqliteBlockstore {
	return &SqliteBlockstore{
		did:      did,
		db:       db,
		readonly: true,
		inserts:  []blocks.Block{},
	}
}

func (bs *SqliteBlockstore) Get(ctx context.Context, cid cid.Cid) (blocks.Block, error) {
	var block models.Block
	if err := bs.db.Raw("SELECT * FROM blocks WHERE did = ? AND cid = ?", nil, bs.did, cid.Bytes()).Scan(&block).Error; err != nil {
		return nil, err
	}

	b, err := blocks.NewBlockWithCid(block.Value, cid)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (bs *SqliteBlockstore) Put(ctx context.Context, block blocks.Block) error {
	bs.inserts = append(bs.inserts, block)

	if bs.readonly {
		return nil
	}

	b := models.Block{
		Did:   bs.did,
		Cid:   block.Cid().Bytes(),
		Rev:   syntax.NewTIDNow(0).String(), // TODO: WARN, this is bad. don't do this
		Value: block.RawData(),
	}

	if err := bs.db.Create(&b, []clause.Expression{clause.OnConflict{
		Columns:   []clause.Column{{Name: "did"}, {Name: "cid"}},
		UpdateAll: true,
	}}).Error; err != nil {
		return err
	}

	return nil
}

func (bs *SqliteBlockstore) DeleteBlock(context.Context, cid.Cid) error {
	panic("not implemented")
}

func (bs *SqliteBlockstore) Has(context.Context, cid.Cid) (bool, error) {
	panic("not implemented")
}

func (bs *SqliteBlockstore) GetSize(context.Context, cid.Cid) (int, error) {
	panic("not implemented")
}

func (bs *SqliteBlockstore) PutMany(context.Context, []blocks.Block) error {
	panic("not implemented")
}

func (bs *SqliteBlockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	panic("not implemented")
}

func (bs *SqliteBlockstore) HashOnRead(enabled bool) {
	panic("not implemented")
}

func (bs *SqliteBlockstore) UpdateRepo(ctx context.Context, root cid.Cid, rev string) error {
	if err := bs.db.Exec("UPDATE repos SET root = ?, rev = ? WHERE did = ?", nil, root.Bytes(), rev, bs.did).Error; err != nil {
		return err
	}

	return nil
}

func (bs *SqliteBlockstore) Execute(ctx context.Context) error {
	if !bs.readonly {
		return fmt.Errorf("blockstore was not readonly")
	}

	bs.readonly = false
	for _, b := range bs.inserts {
		bs.Put(ctx, b)
	}
	bs.readonly = true

	return nil
}

func (bs *SqliteBlockstore) GetLog() []blocks.Block {
	return bs.inserts
}
