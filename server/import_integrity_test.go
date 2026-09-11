package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/carstore"
	"github.com/haileyok/cocoon/models"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	"github.com/ipld/go-car"
	"gorm.io/gorm"
)

func importFixture(t *testing.T, did string, paths []string) (cid.Cid, []blocks.Block, *atp.Repo) {
	t.Helper()
	ctx := context.Background()
	bs := blockstore.NewBlockstore(datastore.NewMapDatastore())
	r := &atp.Repo{DID: syntax.DID(did), Clock: syntax.NewTIDClock(0), MST: mst.NewEmptyTree(), RecordStore: bs}
	for i, path := range paths {
		rec := MarshalableMap{"$type": "app.bsky.feed.post", "text": fmt.Sprintf("imported record %d", i)}
		c, err := putRecordBlock(ctx, bs, &rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.MST.Insert([]byte(path), c); err != nil {
			t.Fatal(err)
		}
	}
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := commitRepo(ctx, bs, r, key.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := bs.AllKeysChan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var all []blocks.Block
	for c := range keys {
		c = cid.NewCidV1(cid.DagCBOR, c.Hash())
		b, err := bs.Get(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b)
	}
	return root, all, r
}

func importCAR(t *testing.T, roots []cid.Cid, all []blocks.Block) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := car.WriteHeader(&car.CarHeader{Roots: roots, Version: 1}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, b := range all {
		if _, err := carstore.LdWrite(&buf, b.Cid().Bytes(), b.RawData()); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func importState(t *testing.T, s *Server, did string) any {
	t.Helper()
	state := struct {
		Repo    *models.RepoActor
		Blocks  []models.Block
		Records []models.Record
	}{}
	var err error
	state.Repo, err = s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Where("did = ?", did).Order("cid").Find(&state.Blocks).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Where("did = ?", did).Order("nsid, rkey").Find(&state.Records).Error; err != nil {
		t.Fatal(err)
	}
	return state
}

func TestImportRejectsIncompleteCAR(t *testing.T) {
	for _, mode := range []string{"truncated", "missing-section", "empty-section", "bad-hash", "no-root", "multiple-roots", "missing-record", "partial-tree", "wrong-did", "invalid-path", "invalid-rev", "invalid-version"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t)
			account := s.createTestAccount(t, "import.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			before := importState(t, s, account.Did)
			did := account.Did
			if mode == "wrong-did" {
				did = "did:web:someone-else.test"
			}
			paths := []string{"app.bsky.feed.post/one"}
			if mode == "invalid-path" {
				paths = []string{"no-slash"}
			}
			if mode == "partial-tree" {
				for i := range 40 {
					paths = append(paths, fmt.Sprintf("app.bsky.feed.post/item%d", i))
				}
			}
			root, all, r := importFixture(t, did, paths)
			if mode == "invalid-rev" || mode == "invalid-version" {
				b, err := r.RecordStore.Get(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				var commit atp.Commit
				if err := commit.UnmarshalCBOR(bytes.NewReader(b.RawData())); err != nil {
					t.Fatal(err)
				}
				if mode == "invalid-rev" {
					commit.Rev = "invalid"
				} else {
					commit.Version = 2
				}
				var buf bytes.Buffer
				if err := commit.MarshalCBOR(&buf); err != nil {
					t.Fatal(err)
				}
				root, err = root.Prefix().Sum(buf.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				block, err := blocks.NewBlockWithCid(buf.Bytes(), root)
				if err != nil {
					t.Fatal(err)
				}
				all = append(all, block)
			}
			roots := []cid.Cid{root}
			if mode == "no-root" {
				roots = nil
			}
			if mode == "multiple-roots" {
				roots = append(roots, root)
			}
			if mode == "missing-record" || mode == "partial-tree" {
				status, _ := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, roots, all)))
				if status != 200 {
					t.Fatalf("complete fixture rejected: %d", status)
				}
				before = importState(t, s, account.Did)
				nodes, leaves := map[cid.Cid]struct{}{}, map[cid.Cid]struct{}{}
				collectTreeBlocks(r.MST.Root, nodes, leaves)
				omit := leaves
				if mode == "partial-tree" {
					omit = nodes
					delete(omit, *r.MST.Root.CID)
					if len(omit) == 0 {
						t.Fatal("fixture has no child nodes")
					}
				}
				var kept []blocks.Block
				for _, b := range all {
					if _, drop := omit[b.Cid()]; !drop {
						kept = append(kept, b)
					}
				}
				all = kept
			}
			body := importCAR(t, roots, all)
			if mode == "truncated" {
				body = append(body, 0x80)
			}
			if mode == "missing-section" {
				body = append(body, 0x01)
			}
			if mode == "empty-section" {
				body = append(body, 0x00, 0xff)
			}
			if mode == "bad-hash" {
				body[len(body)-1] ^= 1
			}
			status, _ := callImportRepo(t, s, account, bytes.NewReader(body))
			if status != 400 {
				t.Fatalf("status = %d, want 400", status)
			}
			if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
				t.Fatal("invalid import changed persistent state")
			}
		})
	}
}

func TestImportRollback(t *testing.T) {
	for _, table := range []string{"blocks", "records", "repos", "commit"} {
		t.Run(table, func(t *testing.T) {
			s := newTestServer(t)
			account := s.createTestAccount(t, "rollback-import.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			before := importState(t, s, account.Did)
			operation := "INSERT"
			if table == "repos" {
				operation = "UPDATE"
			}
			if table == "commit" {
				pool, err := s.db.Client().DB()
				if err != nil {
					t.Fatal(err)
				}
				pool.SetMaxOpenConns(1)
				for _, query := range []string{
					"PRAGMA foreign_keys = ON",
					"CREATE TABLE import_parent (id INTEGER PRIMARY KEY)",
					"CREATE TABLE import_guard (id INTEGER REFERENCES import_parent(id) DEFERRABLE INITIALLY DEFERRED)",
					"CREATE TRIGGER fail_import AFTER INSERT ON records BEGIN INSERT INTO import_guard VALUES (1); END",
				} {
					if err := s.db.Exec(context.Background(), query, nil).Error; err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if err := s.db.Exec(context.Background(), "CREATE TRIGGER fail_import BEFORE "+operation+" ON "+table+" BEGIN SELECT RAISE(ABORT, 'test failure'); END", nil).Error; err != nil {
					t.Fatal(err)
				}
			}
			root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/new"})
			status, _ := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all)))
			if status != 500 {
				t.Fatalf("status = %d, want 500", status)
			}
			if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
				t.Fatal("failed import left partial writes")
			}
		})
	}
}

func TestImportReplacesRecords(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "replace-import.pds.test")
	other := s.createTestAccount(t, "other-import.pds.test")
	s.seedGenesisRepo(t, other.Did, other.SigningKey)
	otherState := importState(t, s, other.Did)
	for _, paths := range [][]string{{"app.bsky.feed.post/old", "app.bsky.feed.post/keep"}, {"app.bsky.feed.post/keep"}, {}} {
		root, all, original := importFixture(t, account.Did, paths)
		status, body := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all)))
		if status != 200 {
			t.Fatalf("import: %d %s", status, body)
		}
		if !reflect.DeepEqual(otherState, importState(t, s, other.Did)) {
			t.Fatal("import changed another account")
		}
		var records []models.Record
		if err := s.db.Client().Where("did = ?", account.Did).Find(&records).Error; err != nil {
			t.Fatal(err)
		}
		if len(records) != len(paths) {
			t.Fatalf("got %d records, want %d", len(records), len(paths))
		}
		repo, err := s.getRepoActorByDid(context.Background(), account.Did)
		if err != nil {
			t.Fatal(err)
		}
		newRoot, err := cid.Cast(repo.Root)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := openRepo(context.Background(), s.getBlockstore(account.Did), newRoot, account.Did)
		if err != nil {
			t.Fatal(err)
		}
		block, err := loaded.RecordStore.Get(context.Background(), newRoot)
		if err != nil {
			t.Fatal(err)
		}
		var commit atp.Commit
		if err := commit.UnmarshalCBOR(bytes.NewReader(block.RawData())); err != nil {
			t.Fatal(err)
		}
		key, err := atcrypto.ParsePrivateBytesK256(account.SigningKey)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := key.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := commit.VerifySignature(pub); err != nil {
			t.Fatal(err)
		}
		if commit.Rev != repo.Rev || commit.DID != account.Did {
			t.Fatal("commit metadata differs from account")
		}
		expectedData, err := original.MST.RootCID()
		if err != nil {
			t.Fatal(err)
		}
		if expectedData == nil || commit.Data != *expectedData {
			t.Fatal("import changed the source tree")
		}
		for _, record := range records {
			c, err := loaded.MST.Get([]byte(record.Nsid + "/" + record.Rkey))
			if err != nil || c == nil || c.String() != record.Cid {
				t.Fatal("record index differs from committed tree")
			}
			block, err := loaded.RecordStore.Get(context.Background(), *c)
			if err != nil || !bytes.Equal(block.RawData(), record.Value) {
				t.Fatal("record bytes differ from blockstore")
			}
		}
	}
}

func TestImportStaleHeadAndCancellation(t *testing.T) {
	for _, mode := range []string{"stale-head", "cancel-before", "cancel-during"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t)
			account := s.createTestAccount(t, "interrupted-import.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/new"})
			body := importCAR(t, []cid.Cid{root}, all)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := 400
			switch mode {
			case "stale-head":
				status, _ := callImportRepo(t, s, account, bytes.NewReader(body))
				if status != 200 {
					t.Fatalf("first import: %d", status)
				}
				want = 409
			case "cancel-before":
				cancel()
			case "cancel-during":
				if err := s.db.Client().Callback().Create().After("gorm:create").Register("cancel-import", func(tx *gorm.DB) {
					if tx.Statement.Table == "records" {
						cancel()
					}
				}); err != nil {
					t.Fatal(err)
				}
				want = 500
			}
			before := importState(t, s, account.Did)
			c, w := newRequestContext("POST", "/xrpc/com.atproto.repo.importRepo", "", nil)
			c.Request().Body = io.NopCloser(bytes.NewReader(body))
			c.SetRequest(c.Request().WithContext(ctx))
			c.Set("repo", repo)
			if err := s.handleRepoImportRepo(c); err != nil {
				t.Fatal(err)
			}
			if w.Code != want {
				t.Fatalf("status = %d, want %d", w.Code, want)
			}
			if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
				t.Fatal("interrupted import changed state")
			}
		})
	}
}

func TestImportRejectsMisorderedTree(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "misordered.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	before := importState(t, s, account.Did)
	var a, b string
	for i := 0; b == ""; i++ {
		path := fmt.Sprintf("app.bsky.feed.post/%06d", i)
		if a == "" && mst.HeightForKey([]byte(path)) == 1 {
			a = path
		} else if a != "" && mst.HeightForKey([]byte(path)) == 0 {
			b = path
		}
	}
	root, all, r := importFixture(t, account.Did, []string{a, b})
	value, err := r.MST.Get([]byte(a))
	if err != nil || value == nil {
		t.Fatal("missing fixture record", err)
	}
	addNode := func(node mst.NodeData) cid.Cid {
		t.Helper()
		raw, c, err := node.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		block, err := blocks.NewBlockWithCid(raw, *c)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, block)
		return *c
	}
	left := addNode(mst.NodeData{Entries: []mst.EntryData{{KeySuffix: []byte(b), Value: *value}}})
	data := addNode(mst.NodeData{Left: &left, Entries: []mst.EntryData{{KeySuffix: []byte(a), Value: *value}}})
	block, err := r.RecordStore.Get(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var commit atp.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(block.RawData())); err != nil {
		t.Fatal(err)
	}
	commit.Data = data
	var buf bytes.Buffer
	if err := commit.MarshalCBOR(&buf); err != nil {
		t.Fatal(err)
	}
	root, err = root.Prefix().Sum(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	block, err = blocks.NewBlockWithCid(buf.Bytes(), root)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, block)
	status, _ := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all)))
	if status != 400 {
		t.Fatalf("status = %d, want 400", status)
	}
	if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
		t.Fatal("misordered tree changed persistent state")
	}
}

func TestImportSerializesWithWrites(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = newTestEvtman(t)
	account := s.createTestAccount(t, "overlap.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/imported"})
	c, response := newRequestContext("POST", "/xrpc/com.atproto.repo.importRepo", "", nil)
	c.Request().Body = io.NopCloser(bytes.NewReader(importCAR(t, []cid.Cid{root}, all)))
	c.Set("repo", repo)
	paused, resume := make(chan struct{}), make(chan struct{})
	if err := s.db.Client().Callback().Raw().Before("gorm:raw").Register("pause-head", func(tx *gorm.DB) {
		if tx.Statement.SQL.String() == "UPDATE repos SET root = ?, rev = ? WHERE did = ?" {
			close(paused)
			<-resume
		}
	}); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := s.repoman.applyWrites(context.Background(), repo.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("written"), Record: rmPostRecord("written")}}, nil)
		writeDone <- err
	}()
	select {
	case <-paused:
	case err := <-writeDone:
		t.Fatalf("write did not reach head update: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("write did not reach head update")
	}
	importDone := make(chan error, 1)
	go func() { importDone <- s.handleRepoImportRepo(c) }()
	select {
	case err := <-importDone:
		close(resume)
		<-writeDone
		t.Fatalf("import completed during unpublished write: status %d, error %v", response.Code, err)
	case <-time.After(100 * time.Millisecond):
	}
	close(resume)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-importDone; err != nil {
		t.Fatal(err)
	}
	if response.Code != 409 {
		t.Fatalf("stale import status = %d, want 409", response.Code)
	}
	if leaves := walkMstLeaves(t, s, account.Did); len(leaves) != 1 || !leaves["app.bsky.feed.post/written"].Defined() {
		t.Fatalf("lost completed write: %v", leaves)
	}
}

func TestWriteAfterImportRefreshesHead(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = newTestEvtman(t)
	account := s.createTestAccount(t, "cached-import.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	mustApply(t, s, account.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("old"), Record: rmPostRecord("old")})
	stale, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/imported"})
	if status, body := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all))); status != 200 {
		t.Fatalf("import: %d %s", status, body)
	}
	if _, err := s.repoman.applyWrites(context.Background(), stale.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("new"), Record: rmPostRecord("new")}}, nil); err != nil {
		t.Fatal(err)
	}
	leaves := walkMstLeaves(t, s, account.Did)
	if len(leaves) != 2 || !leaves["app.bsky.feed.post/imported"].Defined() || !leaves["app.bsky.feed.post/new"].Defined() {
		t.Fatalf("write used pre-import tree: %v", leaves)
	}
	var records []models.Record
	if err := s.db.Client().Where("did = ?", account.Did).Find(&records).Error; err != nil {
		t.Fatal(err)
	}
	if len(records) != len(leaves) {
		t.Fatal("record index differs from tree")
	}
	for _, record := range records {
		path := strings.Join([]string{record.Nsid, record.Rkey}, "/")
		if leaves[path].String() != record.Cid || !blockstoreHas(t, s, account.Did, leaves[path]) {
			t.Fatalf("record or block missing: %s", path)
		}
	}
}
