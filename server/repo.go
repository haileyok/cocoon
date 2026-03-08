package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/carstore"
	"github.com/bluesky-social/indigo/events"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/metrics"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/recording_blockstore"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"github.com/multiformats/go-multihash"
	"gorm.io/gorm/clause"
)

type cachedRepo struct {
	mu   sync.Mutex
	repo *atp.Repo
	root cid.Cid
}

type RepoMan struct {
	db    *db.DB
	s     *Server
	clock *syntax.TIDClock

	cacheMu sync.Mutex
	cache   map[string]*cachedRepo
}

func NewRepoMan(s *Server) *RepoMan {
	clock := syntax.NewTIDClock(0)

	return &RepoMan{
		s:     s,
		db:    s.db,
		clock: clock,
		cache: make(map[string]*cachedRepo),
	}
}

func (rm *RepoMan) withRepo(ctx context.Context, did string, rootCid cid.Cid, fn func(r *atp.Repo) (newRoot cid.Cid, err error)) error {
	rm.cacheMu.Lock()
	cr, ok := rm.cache[did]
	if !ok {
		cr = &cachedRepo{}
		rm.cache[did] = cr
	}
	rm.cacheMu.Unlock()

	cr.mu.Lock()
	defer cr.mu.Unlock()

	if cr.repo == nil || cr.root != rootCid {
		bs := rm.s.getBlockstore(did)
		r, err := openRepo(ctx, bs, rootCid, did)
		if err != nil {
			return err
		}
		cr.repo = r
		cr.root = rootCid
	}

	newRoot, err := fn(cr.repo)
	if err != nil {
		// invalidate on error since the tree may be partially mutated
		cr.repo = nil
		cr.root = cid.Undef
		return err
	}

	cr.root = newRoot
	return nil
}

type OpType string

var (
	OpTypeCreate = OpType("com.atproto.repo.applyWrites#create")
	OpTypeUpdate = OpType("com.atproto.repo.applyWrites#update")
	OpTypeDelete = OpType("com.atproto.repo.applyWrites#delete")
)

func (ot OpType) String() string {
	return string(ot)
}

type Op struct {
	Type       OpType          `json:"$type"`
	Collection string          `json:"collection"`
	Rkey       *string         `json:"rkey,omitempty"`
	Validate   *bool           `json:"validate,omitempty"`
	SwapRecord *string         `json:"swapRecord,omitempty"`
	Record     *MarshalableMap `json:"record,omitempty"`
}

type MarshalableMap map[string]any

type FirehoseOp struct {
	Cid    cid.Cid
	Path   string
	Action string
}

func (mm *MarshalableMap) MarshalCBOR(w io.Writer) error {
	data, err := atdata.MarshalCBOR(*mm)
	if err != nil {
		return err
	}

	w.Write(data)

	return nil
}

type ApplyWriteResult struct {
	Type             *string     `json:"$type,omitempty"`
	Uri              *string     `json:"uri,omitempty"`
	Cid              *string     `json:"cid,omitempty"`
	Commit           *RepoCommit `json:"commit,omitempty"`
	ValidationStatus *string     `json:"validationStatus,omitempty"`
}

type RepoCommit struct {
	Cid string `json:"cid"`
	Rev string `json:"rev"`
}

func openRepo(ctx context.Context, bs blockstore.Blockstore, rootCid cid.Cid, did string) (*atp.Repo, error) {
	commitBlock, err := bs.Get(ctx, rootCid)
	if err != nil {
		return nil, fmt.Errorf("reading commit block: %w", err)
	}

	var commit atp.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(commitBlock.RawData())); err != nil {
		return nil, fmt.Errorf("parsing commit block: %w", err)
	}

	tree, err := mst.LoadTreeFromStore(ctx, bs, commit.Data)
	if err != nil {
		return nil, fmt.Errorf("loading MST: %w", err)
	}

	clk := syntax.ClockFromTID(syntax.TID(commit.Rev))
	return &atp.Repo{
		DID:         syntax.DID(did),
		Clock:       &clk,
		MST:         *tree,
		RecordStore: bs,
	}, nil
}

func commitRepo(ctx context.Context, bs blockstore.Blockstore, r *atp.Repo, signingKey []byte) (cid.Cid, string, error) {
	if _, err := r.MST.WriteDiffBlocks(ctx, bs); err != nil {
		return cid.Undef, "", fmt.Errorf("writing MST blocks: %w", err)
	}

	commit, err := r.Commit()
	if err != nil {
		return cid.Undef, "", fmt.Errorf("creating commit: %w", err)
	}

	privkey, err := atcrypto.ParsePrivateBytesK256(signingKey)
	if err != nil {
		return cid.Undef, "", fmt.Errorf("parsing signing key: %w", err)
	}
	if err := commit.Sign(privkey); err != nil {
		return cid.Undef, "", fmt.Errorf("signing commit: %w", err)
	}

	buf := new(bytes.Buffer)
	if err := commit.MarshalCBOR(buf); err != nil {
		return cid.Undef, "", fmt.Errorf("marshaling commit: %w", err)
	}

	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	commitCid, err := pref.Sum(buf.Bytes())
	if err != nil {
		return cid.Undef, "", fmt.Errorf("computing commit CID: %w", err)
	}

	blk, err := blocks.NewBlockWithCid(buf.Bytes(), commitCid)
	if err != nil {
		return cid.Undef, "", fmt.Errorf("creating commit block: %w", err)
	}
	if err := bs.Put(ctx, blk); err != nil {
		return cid.Undef, "", fmt.Errorf("writing commit block: %w", err)
	}

	return commitCid, commit.Rev, nil
}

func putRecordBlock(ctx context.Context, bs blockstore.Blockstore, rec *MarshalableMap) (cid.Cid, error) {
	buf := new(bytes.Buffer)
	if err := rec.MarshalCBOR(buf); err != nil {
		return cid.Undef, err
	}

	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	c, err := pref.Sum(buf.Bytes())
	if err != nil {
		return cid.Undef, err
	}

	blk, err := blocks.NewBlockWithCid(buf.Bytes(), c)
	if err != nil {
		return cid.Undef, err
	}
	if err := bs.Put(ctx, blk); err != nil {
		return cid.Undef, err
	}

	return c, nil
}

// TODO make use of swap commit
func (rm *RepoMan) applyWrites(ctx context.Context, urepo models.Repo, writes []Op, swapCommit *string) ([]ApplyWriteResult, error) {
	rootcid, err := cid.Cast(urepo.Root)
	if err != nil {
		return nil, err
	}

	dbs := rm.s.getBlockstore(urepo.Did)
	bs := recording_blockstore.New(dbs)

	var results []ApplyWriteResult
	var ops []*atp.Operation
	var entries []models.Record
	var newroot cid.Cid
	var rev string

	if err := rm.withRepo(ctx, urepo.Did, rootcid, func(r *atp.Repo) (cid.Cid, error) {
		entries = make([]models.Record, 0, len(writes))
		for i, op := range writes {
			// updates or deletes must supply an rkey
			if op.Type != OpTypeCreate && op.Rkey == nil {
				return cid.Undef, fmt.Errorf("invalid rkey")
			} else if op.Type == OpTypeCreate && op.Rkey != nil {
				// we should convert this op to an update if the rkey already exists
				path := fmt.Sprintf("%s/%s", op.Collection, *op.Rkey)
				existing, _ := r.MST.Get([]byte(path))
				if existing != nil {
					op.Type = OpTypeUpdate
				}
			} else if op.Rkey == nil {
				// creates that don't supply an rkey will have one generated for them
				op.Rkey = to.StringPtr(rm.clock.Next().String())
				writes[i].Rkey = op.Rkey
			}

			path := fmt.Sprintf("%s/%s", op.Collection, *op.Rkey)

			// validate the record key is actually valid
			_, err := syntax.ParseRecordKey(*op.Rkey)
			if err != nil {
				return cid.Undef, err
			}

			switch op.Type {
			case OpTypeCreate:
				// HACK: this fixes some type conversions, mainly around integers
				b, err := json.Marshal(*op.Record)
				if err != nil {
					return cid.Undef, err
				}
				out, err := atdata.UnmarshalJSON(b)
				if err != nil {
					return cid.Undef, err
				}
				mm := MarshalableMap(out)

				// HACK: if a record doesn't contain a $type, we can manually set it here based on the op's collection
				if mm["$type"] == "" {
					mm["$type"] = op.Collection
				}

				nc, err := putRecordBlock(ctx, bs, &mm)
				if err != nil {
					return cid.Undef, err
				}

				atpOp, err := atp.ApplyOp(&r.MST, path, &nc)
				if err != nil {
					return cid.Undef, err
				}
				ops = append(ops, atpOp)

				d, err := atdata.MarshalCBOR(mm)
				if err != nil {
					return cid.Undef, err
				}

				entries = append(entries, models.Record{
					Did:       urepo.Did,
					CreatedAt: rm.clock.Next().String(),
					Nsid:      op.Collection,
					Rkey:      *op.Rkey,
					Cid:       nc.String(),
					Value:     d,
				})

				results = append(results, ApplyWriteResult{
					Type:             to.StringPtr(OpTypeCreate.String()),
					Uri:              to.StringPtr("at://" + urepo.Did + "/" + op.Collection + "/" + *op.Rkey),
					Cid:              to.StringPtr(nc.String()),
					ValidationStatus: to.StringPtr("valid"), // TODO: obviously this might not be true atm lol
				})
			case OpTypeDelete:
				// try to find the old record in the database
				var old models.Record
				if err := rm.db.Raw(ctx, "SELECT value FROM records WHERE did = ? AND nsid = ? AND rkey = ?", nil, urepo.Did, op.Collection, op.Rkey).Scan(&old).Error; err != nil {
					return cid.Undef, err
				}

				// TODO: this is really confusing, and looking at it i have no idea why i did this. below when we are doing deletes, we
				// check if `cid` here is nil to indicate if we should delete. that really doesn't make much sense and its super illogical
				// when reading this code. i dont feel like fixing right now though so
				entries = append(entries, models.Record{
					Did:   urepo.Did,
					Nsid:  op.Collection,
					Rkey:  *op.Rkey,
					Value: old.Value,
				})

				atpOp, err := atp.ApplyOp(&r.MST, path, nil)
				if err != nil {
					return cid.Undef, err
				}
				ops = append(ops, atpOp)

				results = append(results, ApplyWriteResult{
					Type: to.StringPtr(OpTypeDelete.String()),
				})
			case OpTypeUpdate:
				// HACK: same hack as above for type fixes
				b, err := json.Marshal(*op.Record)
				if err != nil {
					return cid.Undef, err
				}
				out, err := atdata.UnmarshalJSON(b)
				if err != nil {
					return cid.Undef, err
				}
				mm := MarshalableMap(out)

				nc, err := putRecordBlock(ctx, bs, &mm)
				if err != nil {
					return cid.Undef, err
				}

				atpOp, err := atp.ApplyOp(&r.MST, path, &nc)
				if err != nil {
					return cid.Undef, err
				}
				ops = append(ops, atpOp)

				d, err := atdata.MarshalCBOR(mm)
				if err != nil {
					return cid.Undef, err
				}

				entries = append(entries, models.Record{
					Did:       urepo.Did,
					CreatedAt: rm.clock.Next().String(),
					Nsid:      op.Collection,
					Rkey:      *op.Rkey,
					Cid:       nc.String(),
					Value:     d,
				})

				results = append(results, ApplyWriteResult{
					Type:             to.StringPtr(OpTypeUpdate.String()),
					Uri:              to.StringPtr("at://" + urepo.Did + "/" + op.Collection + "/" + *op.Rkey),
					Cid:              to.StringPtr(nc.String()),
					ValidationStatus: to.StringPtr("valid"), // TODO: obviously this might not be true atm lol
				})
			}
		}

		// commit and get the new root
		var commitErr error
		newroot, rev, commitErr = commitRepo(ctx, bs, r, urepo.SigningKey)
		if commitErr != nil {
			return cid.Undef, commitErr
		}

		return newroot, nil
	}); err != nil {
		return nil, err
	}

	for _, result := range results {
		if result.Type != nil {
			metrics.RepoOperations.WithLabelValues(*result.Type).Inc()
		}
	}

	// create a buffer for dumping our new cbor into
	buf := new(bytes.Buffer)

	// first write the car header to the buffer
	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{newroot},
		Version: 1,
	})
	if _, err := carstore.LdWrite(buf, hb); err != nil {
		return nil, err
	}

	// create the repo ops for the firehose from the tracked operations
	repoOps := make([]*atproto.SyncSubscribeRepos_RepoOp, 0, len(ops))
	for _, op := range ops {
		if op.IsCreate() || op.IsUpdate() {
			kind := "create"
			if op.IsUpdate() {
				kind = "update"
			}

			ll := lexutil.LexLink(*op.Value)
			repoOps = append(repoOps, &atproto.SyncSubscribeRepos_RepoOp{
				Action: kind,
				Path:   op.Path,
				Cid:    &ll,
			})

			blk, err := dbs.Get(ctx, *op.Value)
			if err != nil {
				return nil, err
			}
			if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
				return nil, err
			}
		} else if op.IsDelete() {
			ll := lexutil.LexLink(*op.Prev)
			repoOps = append(repoOps, &atproto.SyncSubscribeRepos_RepoOp{
				Action: "delete",
				Path:   op.Path,
				Cid:    nil,
				Prev:   &ll,
			})

			blk, err := dbs.Get(ctx, *op.Prev)
			if err != nil {
				return nil, err
			}
			if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
				return nil, err
			}
		}
	}

	// write the writelog to the buffer
	for _, blk := range bs.GetWriteLog() {
		if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
			return nil, err
		}
	}

	// blob blob blob blob blob :3
	var blobs []lexutil.LexLink
	for _, entry := range entries {
		var cids []cid.Cid
		// whenever there is cid present, we know it's a create (dumb)
		if entry.Cid != "" {
			if err := rm.s.db.Create(ctx, &entry, []clause.Expression{clause.OnConflict{
				Columns:   []clause.Column{{Name: "did"}, {Name: "nsid"}, {Name: "rkey"}},
				UpdateAll: true,
			}}).Error; err != nil {
				return nil, err
			}

			// increment the given blob refs, yay
			cids, err = rm.incrementBlobRefs(ctx, urepo, entry.Value)
			if err != nil {
				return nil, err
			}
		} else {
			// as i noted above this is dumb. but we delete whenever the cid is nil. it works solely becaue the pkey
			// is did + collection + rkey. i still really want to separate that out, or use a different type to make
			// this less confusing/easy to read. alas, its 2 am and yea no
			if err := rm.s.db.Delete(ctx, &entry, nil).Error; err != nil {
				return nil, err
			}

			// TODO:
			cids, err = rm.decrementBlobRefs(ctx, urepo, entry.Value)
			if err != nil {
				return nil, err
			}
		}

		// add all the relevant blobs to the blobs list of blobs. blob ^.^
		for _, c := range cids {
			blobs = append(blobs, lexutil.LexLink(c))
		}
	}

	// NOTE: using the request ctx seems a bit suss here, so using a background context. i'm not sure if this
	// runs sync or not
	rm.s.evtman.AddEvent(context.Background(), &events.XRPCStreamEvent{
		RepoCommit: &atproto.SyncSubscribeRepos_Commit{
			Repo:   urepo.Did,
			Blocks: buf.Bytes(),
			Blobs:  blobs,
			Rev:    rev,
			Since:  &urepo.Rev,
			Commit: lexutil.LexLink(newroot),
			Time:   time.Now().Format(time.RFC3339Nano),
			Ops:    repoOps,
			TooBig: false,
		},
	})

	if err := rm.s.UpdateRepo(ctx, urepo.Did, newroot, rev); err != nil {
		return nil, err
	}

	for i := range results {
		results[i].Type = to.StringPtr(*results[i].Type + "Result")
		results[i].Commit = &RepoCommit{
			Cid: newroot.String(),
			Rev: rev,
		}
	}

	return results, nil
}

func (rm *RepoMan) getRecordProof(ctx context.Context, urepo models.Repo, collection, rkey string) (cid.Cid, []blocks.Block, error) {
	commitCid, err := cid.Cast(urepo.Root)
	if err != nil {
		return cid.Undef, nil, err
	}

	dbs := rm.s.getBlockstore(urepo.Did)

	var proofBlocks []blocks.Block
	var recordCid *cid.Cid

	if err := rm.withRepo(ctx, urepo.Did, commitCid, func(r *atp.Repo) (cid.Cid, error) {
		path := collection + "/" + rkey

		// walk the cached in-memory tree to find the record and collect MST node CIDs on the path
		nodeCIDs := collectPathNodeCIDs(r.MST.Root, []byte(path))

		rc, getErr := r.MST.Get([]byte(path))
		if getErr != nil {
			return cid.Undef, getErr
		}
		if rc == nil {
			return cid.Undef, fmt.Errorf("record not found: %s", path)
		}
		recordCid = rc

		// read the commit block
		commitBlk, err := dbs.Get(ctx, commitCid)
		if err != nil {
			return cid.Undef, fmt.Errorf("reading commit block for proof: %w", err)
		}
		proofBlocks = append(proofBlocks, commitBlk)

		// read the MST nodes on the path
		for _, nc := range nodeCIDs {
			blk, err := dbs.Get(ctx, nc)
			if err != nil {
				return cid.Undef, fmt.Errorf("reading MST node for proof: %w", err)
			}
			proofBlocks = append(proofBlocks, blk)
		}

		// read the record block
		recordBlk, err := dbs.Get(ctx, *recordCid)
		if err != nil {
			return cid.Undef, fmt.Errorf("reading record block for proof: %w", err)
		}
		proofBlocks = append(proofBlocks, recordBlk)

		// read-only, return same root
		return commitCid, nil
	}); err != nil {
		return cid.Undef, nil, err
	}

	return commitCid, proofBlocks, nil
}

func collectPathNodeCIDs(n *mst.Node, key []byte) []cid.Cid {
	if n == nil {
		return nil
	}

	var cids []cid.Cid
	if n.CID != nil {
		cids = append(cids, *n.CID)
	}

	height := mst.HeightForKey(key)
	if height >= n.Height {
		// key is at or above this level, no need to descend
		return cids
	}

	// find the child node that covers this key
	childIdx := -1
	for i, e := range n.Entries {
		if e.IsChild() {
			childIdx = i
			continue
		}
		if e.IsValue() {
			if bytes.Compare(key, e.Key) <= 0 {
				break
			}
			childIdx = -1
		}
	}

	if childIdx >= 0 && n.Entries[childIdx].Child != nil {
		cids = append(cids, collectPathNodeCIDs(n.Entries[childIdx].Child, key)...)
	}

	return cids
}

func (rm *RepoMan) incrementBlobRefs(ctx context.Context, urepo models.Repo, cbor []byte) ([]cid.Cid, error) {
	cids, err := getBlobCidsFromCbor(cbor)
	if err != nil {
		return nil, err
	}

	for _, c := range cids {
		if err := rm.db.Exec(ctx, "UPDATE blobs SET ref_count = ref_count + 1 WHERE did = ? AND cid = ?", nil, urepo.Did, c.Bytes()).Error; err != nil {
			return nil, err
		}
	}

	return cids, nil
}

func (rm *RepoMan) decrementBlobRefs(ctx context.Context, urepo models.Repo, cbor []byte) ([]cid.Cid, error) {
	cids, err := getBlobCidsFromCbor(cbor)
	if err != nil {
		return nil, err
	}

	for _, c := range cids {
		var res struct {
			ID    uint
			Count int
		}
		if err := rm.db.Raw(ctx, "UPDATE blobs SET ref_count = ref_count - 1 WHERE did = ? AND cid = ? RETURNING id, ref_count", nil, urepo.Did, c.Bytes()).Scan(&res).Error; err != nil {
			return nil, err
		}

		// TODO: this does _not_ handle deletions of blobs that are on s3 storage!!!! we need to get the blob, see what
		// storage it is in, and clean up s3!!!!
		if res.Count == 0 {
			if err := rm.db.Exec(ctx, "DELETE FROM blobs WHERE id = ?", nil, res.ID).Error; err != nil {
				return nil, err
			}
			if err := rm.db.Exec(ctx, "DELETE FROM blob_parts WHERE blob_id = ?", nil, res.ID).Error; err != nil {
				return nil, err
			}
		}
	}

	return cids, nil
}

// to be honest, we could just store both the cbor and non-cbor in []entries above to avoid an additional
// unmarshal here. this will work for now though
func getBlobCidsFromCbor(cbor []byte) ([]cid.Cid, error) {
	var cids []cid.Cid

	decoded, err := atdata.UnmarshalCBOR(cbor)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling cbor: %w", err)
	}

	var deepiter func(any) error
	deepiter = func(item any) error {
		switch val := item.(type) {
		case map[string]any:
			if val["$type"] == "blob" {
				if ref, ok := val["ref"].(string); ok {
					c, err := cid.Parse(ref)
					if err != nil {
						return err
					}
					cids = append(cids, c)
				}
				for _, v := range val {
					return deepiter(v)
				}
			}
		case []any:
			for _, v := range val {
				deepiter(v)
			}
		}

		return nil
	}

	if err := deepiter(decoded); err != nil {
		return nil, err
	}

	return cids, nil
}
