package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/sqlite_blockstore"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm"
)

// readLocalLexicon classifies hosting by the account database, never the PDS
// endpoint hostname. Only an absent account permits network fallback. Inactive
// accounts fail closed, like this PDS's unauthenticated repository reads.
//
// Read the durable record index and current committed MST from one snapshot;
// PostgreSQL's default READ COMMITTED can lose old blocks between queries
// when a concurrent write commits. Do not use RepoMan's mutable/staged cache
// or trust an orphan index entry.
// The resolver applies bounded CBOR and document validation to the result.
func (s *Server) readLocalLexicon(ctx context.Context, did syntax.DID, nsid syntax.NSID) ([]byte, bool, error) {
	var record []byte
	var hosted bool
	err := s.db.Client().WithContext(ctx).Transaction(func(cli *gorm.DB) error {
		tx := db.NewDB(cli)
		var account models.Repo
		if err := tx.First(ctx, &account, "did = ?", did.String()).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		hosted = true
		if !account.Active() || account.TakenDown() {
			return fmt.Errorf("local lexicon repo is unavailable")
		}
		var indexed models.Record
		if err := tx.First(ctx, &indexed, "did = ? AND nsid = ? AND rkey = ?", did.String(), "com.atproto.lexicon.schema", nsid.String()).Error; err != nil {
			return fmt.Errorf("local lexicon record: %w", err)
		}
		root, err := cid.Cast(account.Root)
		if err != nil {
			return fmt.Errorf("local lexicon repo root: %w", err)
		}
		bs := sqlite_blockstore.NewReadOnly(did.String(), tx)
		repository, err := openRepo(ctx, bs, root, did.String())
		if err != nil {
			return err
		}
		raw, recordCID, err := repository.GetRecordBytes(ctx, "com.atproto.lexicon.schema", syntax.RecordKey(nsid))
		if err != nil {
			return err
		}
		if recordCID.String() != indexed.Cid {
			return fmt.Errorf("local lexicon index does not match committed record")
		}
		actual, err := recordCID.Prefix().Sum(raw)
		if err != nil {
			return err
		}
		if !actual.Equals(*recordCID) {
			return fmt.Errorf("local lexicon record does not match committed CID")
		}
		record = raw
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, hosted, err
	}
	return record, hosted, nil
}
