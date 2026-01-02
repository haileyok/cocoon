package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/carstore"
	"github.com/bluesky-social/indigo/events"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/repo"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/metrics"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/recording_blockstore"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"gorm.io/gorm/clause"
)

type RepoMan struct {
	db    *db.DB
	s     *Server
	clock *syntax.TIDClock
}

func NewRepoMan(s *Server) *RepoMan {
	clock := syntax.NewTIDClock(0)

	return &RepoMan{
		s:     s,
		db:    s.db,
		clock: &clock,
	}
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

// TODO make use of swap commit
func (rm *RepoMan) applyWrites(ctx context.Context, urepo models.Repo, writes []Op, swapCommit *string) ([]ApplyWriteResult, error) {
	rootcid, err := cid.Cast(urepo.Root)
	if err != nil {
		return nil, err
	}

	dbs := rm.s.getBlockstore(urepo.Did)
	bs := recording_blockstore.New(dbs)
	r, err := repo.OpenRepo(ctx, bs, rootcid)

	var results []ApplyWriteResult

	entries := make([]models.Record, 0, len(writes))
	for i, op := range writes {
		// updates or deletes must supply an rkey
		if op.Type != OpTypeCreate && op.Rkey == nil {
			return nil, fmt.Errorf("invalid rkey")
		} else if op.Type == OpTypeCreate && op.Rkey != nil {
			// we should conver this op to an update if the rkey already exists
			_, _, err := r.GetRecord(ctx, fmt.Sprintf("%s/%s", op.Collection, *op.Rkey))
			if err == nil {
				op.Type = OpTypeUpdate
			}
		} else if op.Rkey == nil {
			// creates that don't supply an rkey will have one generated for them
			op.Rkey = to.StringPtr(rm.clock.Next().String())
			writes[i].Rkey = op.Rkey
		}

		// validate the record key is actually valid
		_, err := syntax.ParseRecordKey(*op.Rkey)
		if err != nil {
			return nil, err
		}

		switch op.Type {
		case OpTypeCreate:
			// HACK: this fixes some type conversions, mainly around integers
			// first we convert to json bytes
			b, err := json.Marshal(*op.Record)
			if err != nil {
				return nil, err
			}
			// then we use atdata.UnmarshalJSON to convert it back to a map
			out, err := atdata.UnmarshalJSON(b)
			if err != nil {
				return nil, err
			}
			// finally we can cast to a MarshalableMap
			mm := MarshalableMap(out)

			// HACK: if a record doesn't contain a $type, we can manually set it here based on the op's collection
			// i forget why this is actually necessary?
			if mm["$type"] == "" {
				mm["$type"] = op.Collection
			}

			nc, err := r.PutRecord(ctx, fmt.Sprintf("%s/%s", op.Collection, *op.Rkey), &mm)
			if err != nil {
				return nil, err
			}

			d, err := atdata.MarshalCBOR(mm)
			if err != nil {
				return nil, err
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
				return nil, err
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

			// delete the record from the repo
			err := r.DeleteRecord(ctx, fmt.Sprintf("%s/%s", op.Collection, *op.Rkey))
			if err != nil {
				return nil, err
			}

			// add a result for the delete
			results = append(results, ApplyWriteResult{
				Type: to.StringPtr(OpTypeDelete.String()),
			})
		case OpTypeUpdate:
			// HACK: same hack as above for type fixes
			b, err := json.Marshal(*op.Record)
			if err != nil {
				return nil, err
			}
			out, err := atdata.UnmarshalJSON(b)
			if err != nil {
				return nil, err
			}
			mm := MarshalableMap(out)

			nc, err := r.UpdateRecord(ctx, fmt.Sprintf("%s/%s", op.Collection, *op.Rkey), &mm)
			if err != nil {
				return nil, err
			}

			d, err := atdata.MarshalCBOR(mm)
			if err != nil {
				return nil, err
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
	newroot, rev, err := r.Commit(ctx, urepo.SignFor)
	if err != nil {
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

	// get a diff of the changes to the repo
	diffops, err := r.DiffSince(ctx, rootcid)
	if err != nil {
		return nil, err
	}

	// create the repo ops for the given diff
	ops := make([]*atproto.SyncSubscribeRepos_RepoOp, 0, len(diffops))
	for _, op := range diffops {
		var c cid.Cid
		switch op.Op {
		case "add", "mut":
			kind := "create"
			if op.Op == "mut" {
				kind = "update"
			}

			c = op.NewCid
			ll := lexutil.LexLink(op.NewCid)
			ops = append(ops, &atproto.SyncSubscribeRepos_RepoOp{
				Action: kind,
				Path:   op.Rpath,
				Cid:    &ll,
			})

		case "del":
			c = op.OldCid
			ll := lexutil.LexLink(op.OldCid)
			ops = append(ops, &atproto.SyncSubscribeRepos_RepoOp{
				Action: "delete",
				Path:   op.Rpath,
				Cid:    nil,
				Prev:   &ll,
			})
		}

		blk, err := dbs.Get(ctx, c)
		if err != nil {
			return nil, err
		}

		// write the block to the buffer
		if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
			return nil, err
		}
	}

	// write the writelog to the buffer
	for _, op := range bs.GetWriteLog() {
		if _, err := carstore.LdWrite(buf, op.Cid().Bytes(), op.RawData()); err != nil {
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
			Ops:    ops,
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

// this is a fun little guy. to get a proof, we need to read the record out of the blockstore and record how we actually
// got to the guy. we'll wrap a new blockstore in a recording blockstore, then return the log for proof
func (rm *RepoMan) getRecordProof(ctx context.Context, urepo models.Repo, collection, rkey string) (cid.Cid, []blocks.Block, error) {
	c, err := cid.Cast(urepo.Root)
	if err != nil {
		return cid.Undef, nil, err
	}

	dbs := rm.s.getBlockstore(urepo.Did)
	bs := recording_blockstore.New(dbs)

	r, err := repo.OpenRepo(ctx, bs, c)
	if err != nil {
		return cid.Undef, nil, err
	}

	_, _, err = r.GetRecordBytes(ctx, fmt.Sprintf("%s/%s", collection, rkey))
	if err != nil {
		return cid.Undef, nil, err
	}

	return c, bs.GetReadLog(), nil
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
