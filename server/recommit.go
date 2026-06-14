package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm"
)

// RecommitOptions configures RunRecommitMigration.
type RecommitOptions struct {
	// Dids is the set of repos to process.
	Dids []string
	// DryRun reports planned actions without mutating repos or emitting events.
	DryRun bool
	// BlockstoreVariant selects the block store (mirrors the server flag).
	BlockstoreVariant string
	Logger            *slog.Logger
}

// RecommitResult is the per-repo outcome of the migration.
type RecommitResult struct {
	Did         string
	OldRev      string
	NewRev      string
	OldHead     string
	NewHead     string
	Recommitted bool
	Err         error
}

// isValidRev reports whether rev is a syntactically valid TID (13 chars).
func isValidRev(rev string) bool {
	_, err := syntax.ParseTID(rev)
	return err == nil
}

// RunRecommitMigration re-mints valid revs for repos whose stored rev is not a
// valid TID, and announces each repo's current head to the firehose.
//
// For every did it re-commits when the rev is invalid (a fresh signed commit
// with a current 13-char TID rev and new head), then emits #sync (head
// announcement), #identity (handle refresh), and #account (active) so relays
// observe the repo's authoritative state. Re-committing is silent on the commit
// stream; #sync is the spec's frame for out-of-band state changes.
//
// IMPORTANT: events carry an in-memory sequence number, so this must run with
// the PDS stopped to avoid colliding with the live server's sequence.
func RunRecommitMigration(ctx context.Context, gdb *gorm.DB, opts RecommitOptions) ([]RecommitResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	dbw := db.NewDB(gdb)
	persister, err := NewDbPersister(gdb, 0)
	if err != nil {
		return nil, fmt.Errorf("init event persister: %w", err)
	}

	var bsv BlockstoreVariant = BlockstoreVariantSqlite
	if opts.BlockstoreVariant != "" {
		bsv = MustReturnBlockstoreVariant(opts.BlockstoreVariant)
	}

	s := &Server{
		db:     dbw,
		logger: logger,
		evtman: events.NewEventManager(persister),
		config: &config{BlockstoreVariant: bsv},
	}
	s.repoman = NewRepoMan(s)

	results := make([]RecommitResult, 0, len(opts.Dids))
	for _, did := range opts.Dids {
		results = append(results, s.recommitOne(ctx, did, opts.DryRun))
	}
	return results, nil
}

func (s *Server) recommitOne(ctx context.Context, did string, dryRun bool) RecommitResult {
	res := RecommitResult{Did: did}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		res.Err = err
		return res
	}
	res.OldRev = urepo.Repo.Rev
	res.NewRev = urepo.Repo.Rev

	head, err := cid.Cast(urepo.Repo.Root)
	if err != nil {
		res.Err = fmt.Errorf("stored root is not a valid cid: %w", err)
		return res
	}
	res.OldHead = head.String()
	res.NewHead = head.String()

	needsRecommit := !isValidRev(urepo.Repo.Rev)

	if dryRun {
		res.Recommitted = needsRecommit
		return res
	}

	if needsRecommit {
		newHead, newRev, err := s.recommitRepo(ctx, urepo.Repo, head)
		if err != nil {
			res.Err = err
			return res
		}
		head = newHead
		res.NewHead = newHead.String()
		res.NewRev = newRev
		res.Recommitted = true
	}

	if err := s.emitRepoSync(ctx, did, res.NewRev, head); err != nil {
		res.Err = fmt.Errorf("emit #sync: %w", err)
		return res
	}

	now := time.Now().Format(util.ISO8601)
	handle := urepo.Actor.Handle
	s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:    did,
			Handle: &handle,
			Time:   now,
		},
	})
	s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: true,
			Did:    did,
			Time:   now,
		},
	})

	return res
}

// recommitRepo re-signs a repo's current MST under a fresh TID rev, persists the
// new head, and returns it. The block store and signing key are unchanged; only
// the commit (and therefore the rev and head CID) is new.
func (s *Server) recommitRepo(ctx context.Context, repo models.Repo, head cid.Cid) (cid.Cid, string, error) {
	bs := s.getBlockstore(repo.Did)

	r, err := openRepo(ctx, bs, head, repo.Did)
	if err != nil {
		return cid.Undef, "", fmt.Errorf("open repo: %w", err)
	}
	// Reset the clock so the next rev is minted from the current wall clock,
	// independent of the (invalid) stored rev.
	r.Clock = syntax.NewTIDClock(0)

	newHead, newRev, err := commitRepo(ctx, bs, r, repo.SigningKey)
	if err != nil {
		return cid.Undef, "", fmt.Errorf("commit repo: %w", err)
	}
	if !isValidRev(newRev) {
		return cid.Undef, "", fmt.Errorf("minted rev %q is not a valid TID", newRev)
	}

	if err := s.UpdateRepo(ctx, repo.Did, newHead, newRev); err != nil {
		return cid.Undef, "", fmt.Errorf("update repo head: %w", err)
	}

	return newHead, newRev, nil
}
