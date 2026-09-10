package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm"
)

// RepoGcOptions configures RunRepoGcMigration.
type RepoGcOptions struct {
	// Dids is the set of repos to process.
	Dids []string
	// DryRun reports planned deletions without removing any blocks.
	DryRun bool
	// BlockstoreVariant selects the block store (mirrors the server flag).
	BlockstoreVariant string
	Logger            *slog.Logger
}

// RepoGcResult is the per-repo outcome of the migration.
type RepoGcResult struct {
	Did           string
	Head          string
	TotalBlocks   int64
	LiveBlocks    int64
	RemovedBlocks int64
	Err           error
}

// RunRepoGcMigration removes blocks that are unreachable from a repo's
// current head commit: superseded MST nodes, blocks of deleted or
// overwritten records, and historical commit objects — the strata
// accumulated before commits started deleting their removedCids.
//
// For each did it walks the MST at the current root, collecting every
// reachable block CID (the commit block, all MST nodes, all record blocks),
// then deletes every other block row for that did.
//
// The repo itself is never mutated: no new commit, no re-signing, no
// firehose events. It is still safest to run with the PDS stopped (a
// concurrent write would race this pass), and a VACUUM may be needed
// afterwards to return SQLite file space to the OS.
func RunRepoGcMigration(ctx context.Context, gdb *gorm.DB, opts RepoGcOptions) ([]RepoGcResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	dbw := db.NewDB(gdb)

	var bsv BlockstoreVariant = BlockstoreVariantSqlite
	if opts.BlockstoreVariant != "" {
		bsv = MustReturnBlockstoreVariant(opts.BlockstoreVariant)
	}

	s := &Server{
		db:     dbw,
		logger: logger,
		config: &config{BlockstoreVariant: bsv},
	}
	s.repoman = NewRepoMan(s)

	results := make([]RepoGcResult, 0, len(opts.Dids))
	for _, did := range opts.Dids {
		results = append(results, s.repoGcOne(ctx, did, opts.DryRun))
	}
	return results, nil
}

func (s *Server) repoGcOne(ctx context.Context, did string, dryRun bool) RepoGcResult {
	res := RepoGcResult{Did: did}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		res.Err = err
		return res
	}

	head, err := cid.Cast(urepo.Repo.Root)
	if err != nil {
		res.Err = fmt.Errorf("stored root is not a valid cid: %w", err)
		return res
	}
	res.Head = head.String()

	// Collect every block CID reachable from the head commit: the commit
	// block itself, all MST node blocks, and all record blocks.
	live := map[cid.Cid]struct{}{head: {}}
	r, err := openRepo(ctx, s.getBlockstore(did), head, did)
	if err != nil {
		res.Err = fmt.Errorf("open repo at head: %w", err)
		return res
	}
	collectTreeBlocks(r.MST.Root, live, live) // nodes and leaves into one set

	res.LiveBlocks = int64(len(live))

	// Count current rows and find the unreachable ones in one query.
	var total int64
	if err := s.db.Client().Table("blocks").Where("did = ?", did).Count(&total).Error; err != nil {
		res.Err = fmt.Errorf("count blocks: %w", err)
		return res
	}
	res.TotalBlocks = total
	res.RemovedBlocks = total - res.LiveBlocks

	if dryRun {
		return res
	}

	if res.RemovedBlocks > 0 {
		// Delete in batches over the live set rather than building a giant
		// NOT IN clause: fetch candidate cids, filter against live, delete.
		var rows []models.Block
		if err := s.db.Client().Table("blocks").Where("did = ?", did).Find(&rows).Error; err != nil {
			res.Err = fmt.Errorf("load blocks: %w", err)
			return res
		}
		var dead []cid.Cid
		for _, row := range rows {
			c, err := cid.Cast(row.Cid)
			if err != nil {
				// A row whose cid column cannot even be parsed signals real
				// corruption; fail this repo's pass rather than guessing at a
				// deletion key (cid.Undef would not match the stored bytes).
				res.Err = fmt.Errorf("unparseable block cid row for did %s: %w", did, err)
				return res
			}
			if _, ok := live[c]; !ok {
				dead = append(dead, c)
			}
		}
		if len(dead) > 0 {
			dm, ok := s.getBlockstore(did).(interface {
				DeleteMany(context.Context, []cid.Cid) error
			})
			if !ok {
				res.Err = fmt.Errorf("blockstore does not support deleting blocks")
				return res
			}
			if err := dm.DeleteMany(ctx, dead); err != nil {
				res.Err = fmt.Errorf("delete garbage blocks: %w", err)
				return res
			}
			res.RemovedBlocks = int64(len(dead))
		} else {
			res.RemovedBlocks = 0
		}
	}

	return res
}
