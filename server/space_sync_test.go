package server

// Ports packages/pds/tests/space/sync.test.ts from bluesky-social/atproto
// d4def6e9 (the November 12, 2026 Spaces alpha): oplog and full-state sync,
// HTTP-signature MACs, the sequenced writer set, space catch-up, and
// notifyRepoUpdate service authentication.
//
// Reference cases which do not apply to Cocoon:
//   - "prunes the oplog on its own, past a retention window" is also only an
//     it.todo upstream; neither implementation has retention or compaction.
//   - "migrates existing writer state" constructs the reference PDS's old SQL
//     schema and runs its numbered migrations. Cocoon uses GORM AutoMigrate,
//     so there is no corresponding old-schema migration to exercise.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
	"github.com/haileyok/cocoon/space"
)

// syncNet matches the reference suite's network: alice (the authority) and dan
// are on pds1, bob is on pds2, and carol (usually the syncer) is on pds3.
type syncNet struct {
	net                    *spaceNet
	pds1, pds2, pds3       *spacePDS
	alice, dan, bob, carol *actor
}

func newSyncNet(t *testing.T) *syncNet {
	t.Helper()
	n := newSpaceNet(t)
	r := &syncNet{net: n, pds1: n.newPDS(), pds2: n.newPDS(), pds3: n.newPDS()}
	r.alice = r.pds1.createActor("alice")
	r.dan = r.pds1.createActor("dan")
	r.bob = r.pds2.createActor("bob")
	r.carol = r.pds3.createActor("carol")
	return r
}

// syncListRepoOpsPages pages as a syncer does, retaining each complete
// response so callers can check its commit and MAC as well as its ops.
func syncListRepoOpsPages(t *testing.T, c *spaceCredential, p *spacePDS, sp, repo string, params map[string]string) []xres {
	t.Helper()
	query := map[string]string{"space": sp, "repo": repo}
	for k, v := range params {
		query[k] = v
	}
	cursor := ""
	var pages []xres
	for i := 0; i < 10; i++ {
		if cursor == "" {
			delete(query, "cursor")
		} else {
			query["cursor"] = cursor
		}
		page := mustOK(t, c.get(t, p, "com.atproto.space.listRepoOps", query))
		pages = append(pages, page)
		cursor = page.str("cursor")
		if cursor == "" {
			return pages
		}
	}
	t.Fatal("listRepoOps did not drain within ten pages")
	return nil
}

// syncOp is the subset of an oplog entry needed to rebuild a RepoCommit.
type syncOp struct {
	rev, collection, rkey string
	cid, prev             *string
}

func syncWireOp(t *testing.T, m map[string]any) syncOp {
	t.Helper()
	op := syncOp{rev: m["rev"].(string), collection: m["collection"].(string), rkey: m["rkey"].(string)}
	if v, ok := m["cid"].(string); ok && v != "" {
		op.cid = &v
	}
	if v, ok := m["prev"].(string); ok && v != "" {
		op.prev = &v
	}
	return op
}

func syncApplyOp(t *testing.T, local *space.RepoCommit, op syncOp) {
	t.Helper()
	ro := space.RepoOp{Collection: op.collection, Rkey: op.rkey}
	if op.cid != nil {
		c := mustCid(t, *op.cid)
		ro.Cid = &c
	}
	if op.prev != nil {
		c := mustCid(t, *op.prev)
		ro.Prev = &c
	}
	local.ApplyOp(ro)
}

func syncApplyWireOps(t *testing.T, local *space.RepoCommit, ops []map[string]any) {
	t.Helper()
	for _, m := range ops {
		syncApplyOp(t, local, syncWireOp(t, m))
	}
}

func syncCommit(t *testing.T, m map[string]any) space.Commit {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c space.Commit
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Ver != space.CommitVersion {
		t.Fatalf("commit version %d, want %d", c.Ver, space.CommitVersion)
	}
	return c
}

func syncResponseCommit(t *testing.T, res xres) space.Commit {
	t.Helper()
	m, ok := res.body["commit"].(map[string]any)
	if !ok {
		t.Fatalf("response has no commit: %s", res.raw)
	}
	return syncCommit(t, m)
}

func syncVerifyResponseCommit(t *testing.T, c *spaceCredential, res xres, sp, repo string) space.Commit {
	t.Helper()
	commit := syncResponseCommit(t, res)
	if err := c.verifyCommit(t, commit, sp, repo); err != nil {
		t.Fatalf("commit MAC does not verify: %v", err)
	}
	return commit
}

func syncFetchRepo(t *testing.T, c *spaceCredential, p *spacePDS, sp, repo string) xres {
	t.Helper()
	return c.get(t, p, "com.atproto.space.getRepo", map[string]string{"space": sp, "repo": repo})
}

func syncVerifyRepo(t *testing.T, c *spaceCredential, archive []byte, sp, repo string) *space.VerifiedRepo {
	t.Helper()
	got, err := space.VerifyRepoStarFull(bytes.NewReader(archive), space.VerifyRepoParams{
		Space: sp, Repo: repo, VerifyMacParams: c.macParams(t),
	})
	if err != nil {
		t.Fatalf("STAR repo does not verify: %v", err)
	}
	return got
}

// syncCheckStarFraming checks the wire framing independently of the higher
// level verifier: magic and metadata, one 0x01 before every key/value pair,
// then exactly one 0x00 terminator and no trailing bytes.
func syncCheckStarFraming(t *testing.T, raw []byte, pairs int) {
	t.Helper()
	if !bytes.HasPrefix(raw, space.StarMagic) {
		t.Fatalf("STAR magic %x, want %x", raw, space.StarMagic)
	}
	off := len(space.StarMagic)
	frame := func() {
		t.Helper()
		if off >= len(raw) {
			t.Fatal("truncated STAR frame length")
		}
		n, size := binary.Uvarint(raw[off:])
		if size <= 0 {
			t.Fatal("invalid STAR frame varint")
		}
		off += size
		if n > uint64(len(raw)-off) {
			t.Fatalf("STAR frame of %d bytes exceeds remaining archive", n)
		}
		off += int(n)
	}
	frame() // canonical-DRISL metadata
	for i := 0; i < pairs; i++ {
		if off >= len(raw) {
			t.Fatalf("pair %d: missing control byte", i)
		}
		if raw[off] != 0x01 {
			t.Fatalf("pair %d control byte %x, want 01", i, raw[off])
		}
		off++
		frame() // record path
		frame() // record value
	}
	if off >= len(raw) {
		t.Fatal("missing STAR end control byte")
	}
	if raw[off] != 0x00 {
		t.Fatalf("end control byte %x, want 00", raw[off])
	}
	off++
	if off != len(raw) {
		t.Fatalf("%d trailing bytes after STAR terminator", len(raw)-off)
	}
}

func syncLtHashDigest(t *testing.T, state []byte) []byte {
	t.Helper()
	h, err := space.LtHashFromState(state)
	if err != nil {
		t.Fatal(err)
	}
	d := h.Digest()
	return d[:]
}

func syncEmptyHash() []byte {
	d := space.NewLtHash().Digest()
	return d[:]
}

// syncWriterDids reads the effective (not removed) writer set on the
// authority. This is useful while polling for best-effort notifications.
func syncWriterDids(t *testing.T, n *syncNet, sp string) []string {
	t.Helper()
	ref, err := space.ParseRef(sp)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ WriterDid string }
	if err := n.pds1.s.db.Raw(context.Background(),
		"SELECT writer_did FROM space_writers WHERE did = ? AND space = ? AND removed_at IS NULL ORDER BY space_rev ASC",
		nil, ref.Authority, sp).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.WriterDid)
	}
	return out
}

func syncListWriters(t *testing.T, c *spaceCredential, p *spacePDS, sp string, params map[string]string) xres {
	t.Helper()
	query := map[string]string{"space": sp}
	for k, v := range params {
		query[k] = v
	}
	return mustOK(t, c.get(t, p, "com.atproto.space.listWriters", query))
}

// syncAwaitListedWriter waits for a best-effort remote notifyRepoUpdate to
// publish a writer, optionally requiring a revision after the saved cursor.
func syncAwaitListedWriter(t *testing.T, c *spaceCredential, p *spacePDS, sp, repo, after string, params map[string]string) xres {
	t.Helper()
	var listed xres
	ok := awaitCond(t, func() bool {
		listed = syncListWriters(t, c, p, sp, params)
		for _, entry := range listed.list("repos") {
			if entry["$type"] == "com.atproto.space.defs#repoWrite" && entry["repo"] == repo {
				rev, _ := entry["spaceRev"].(string)
				return after == "" || rev > after
			}
		}
		return false
	})
	if !ok {
		t.Fatalf("writer %s did not advance past %q: %s", repo, after, listed.raw)
	}
	return listed
}

func syncListedWriterDids(res xres) []string {
	var out []string
	for _, entry := range res.list("repos") {
		if repo, ok := entry["repo"].(string); ok {
			out = append(out, repo)
		}
	}
	return out
}

func syncActiveWriterDids(res xres) []string {
	var out []string
	for _, entry := range res.list("repos") {
		if entry["$type"] == "com.atproto.space.defs#repoWrite" {
			out = append(out, entry["repo"].(string))
		}
	}
	sort.Strings(out)
	return out
}

func syncExpectActiveWriters(t *testing.T, c *spaceCredential, p *spacePDS, sp string, want ...string) {
	t.Helper()
	got := syncActiveWriterDids(syncListWriters(t, c, p, sp, nil))
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("active writers %v, want %v", got, want)
	}
}

func syncWriterEntry(t *testing.T, res xres, repo, typ string) map[string]any {
	t.Helper()
	for _, entry := range res.list("repos") {
		if entry["repo"] == repo && (typ == "" || entry["$type"] == typ) {
			return entry
		}
	}
	t.Fatalf("no %s entry for %s in %s", typ, repo, res.raw)
	return nil
}

// syncMockSyncer confirms registrations like the reference MockService does,
// and can reject only subsequent update delivery to exercise catch-up.
func syncMockSyncer(n *syncNet, rejectUpdates bool) *mockService {
	return n.net.newMockService("atproto_space_syncer", func(_ *http.Request, call mockCall) (int, any) {
		if call.lxm == "com.atproto.space.confirmRegistration" {
			return 200, map[string]any{"challenge": call.body["challenge"]}
		}
		if rejectUpdates && call.lxm == "com.atproto.space.notifySpaceUpdate" {
			return 503, map[string]any{}
		}
		return 200, map[string]any{}
	})
}

func syncSpaceUpdates(m *mockService) []map[string]any {
	calls := m.callsTo("com.atproto.space.notifySpaceUpdate")
	out := make([]map[string]any, 0, len(calls))
	for _, call := range calls {
		if update, ok := call.body["update"].(map[string]any); ok {
			out = append(out, update)
		}
	}
	return out
}

type syncNotifyOpts struct {
	aud string
	lxm string
}

// syncNotify sends notifyRepoUpdate as the signer's PDS would, with service
// auth signed by its own repo key. Options deliberately corrupt aud or lxm in
// the authentication tests.
func syncNotify(t *testing.T, n *syncNet, signer *actor, body map[string]any, opts syncNotifyOpts) xres {
	t.Helper()
	if opts.aud == "" {
		opts.aud = space.SpaceHostAud(n.alice.did)
	}
	if opts.lxm == "" {
		opts.lxm = "com.atproto.space.notifyRepoUpdate"
	}
	tok, err := mintServiceAuth(signer.key, signer.did, opts.aud, opts.lxm, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return n.pds1.post("com.atproto.space.notifyRepoUpdate", body, map[string]string{"Authorization": "Bearer " + tok})
}

func syncNotifyBody(sp, repo, repoRev string, hash []byte) map[string]any {
	if hash == nil {
		hash = make([]byte, 32)
	}
	return map[string]any{"space": sp, "repo": repo, "repoRev": repoRev, "data": space.LexBytes(hash)}
}

func syncLexBytes(v any) ([]byte, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not $bytes: %v", v)
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return nil, fmt.Errorf("not $bytes: %v", v)
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

func syncContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func syncAtdataFromJSON(v map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return atdata.UnmarshalJSON(raw)
}

func TestSpaceSyncOplogPaging(t *testing.T) {
	r := newSyncNet(t)
	alice, dan := r.alice, r.dan

	t.Run("pages through a single rev without dropping ops", func(t *testing.T) {
		// Reference: oplog paging / pages through a single rev without dropping ops.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		var writes []any
		for i := 0; i < 5; i++ {
			writes = append(writes, map[string]any{
				"$type": "com.atproto.space.applyWrites#create", "collection": testCollection,
				"rkey": fmt.Sprintf("atomic-%d", i), "value": testRecord(testCollection, fmt.Sprintf("atomic %d", i)),
			})
		}
		mustOK(t, dan.post("com.atproto.space.applyWrites", map[string]any{"space": sp, "repo": dan.did, "writes": writes}))

		cred := credentialFor(t, dan, r.pds1, sp)
		pages := syncListRepoOpsPages(t, cred, r.pds1, sp, dan.did, map[string]string{"limit": "2"})
		var got []string
		for _, page := range pages {
			ops := page.list("ops")
			_, hasCursor := page.body["cursor"]
			if hasCursor != (len(ops) == 2) {
				t.Fatalf("%d-op page has incorrect cursor presence: %s", len(ops), page.raw)
			}
			for _, op := range ops {
				got = append(got, op["rkey"].(string))
			}
		}
		want := []string{"atomic-0", "atomic-1", "atomic-2", "atomic-3", "atomic-4"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("rkeys %v, want %v", got, want)
		}
	})

	t.Run("carries the current commit on every page and cursors only full pages", func(t *testing.T) {
		// Reference: oplog paging / carries the current commit on every page.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		for i := 0; i < 3; i++ {
			mustOK(t, doWrite(dan, sp, writeOpts{rkey: fmt.Sprintf("paged-%d", i)}))
		}
		state := repoState(t, dan, sp)
		cred := credentialFor(t, dan, r.pds1, sp)
		local := space.NewRepoCommit()
		var seen []string
		var pages []xres
		var commits []space.Commit
		query := map[string]string{"space": sp, "repo": dan.did, "limit": "1"}
		cursor := ""
		for i := 0; i < 10; i++ {
			if cursor == "" {
				delete(query, "cursor")
			} else {
				query["cursor"] = cursor
			}
			page := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", query))
			// Verify now: each request has a distinct encapsulation and MAC, and
			// the credential helper retains only the latest request's state.
			commits = append(commits, syncVerifyResponseCommit(t, cred, page, sp, dan.did))
			pages = append(pages, page)
			cursor = page.str("cursor")
			if cursor == "" {
				break
			}
		}
		if len(pages) != 4 {
			t.Fatalf("got %d pages, want three full pages plus the empty drain", len(pages))
		}
		for i, page := range pages {
			commit := commits[i]
			if commit.Rev != *state.Rev || !reflect.DeepEqual(commit, commits[len(commits)-1]) {
				t.Fatalf("page %d commit differs from current head: got %+v, final %+v", i, commit, commits[len(commits)-1])
			}
			ops := page.list("ops")
			syncApplyWireOps(t, local, ops)
			_, hasCursor := page.body["cursor"]
			if hasCursor != (len(ops) == 1) {
				t.Fatalf("page %d has %d ops and cursor presence %v: %s", i, len(ops), hasCursor, page.raw)
			}
			if i == 0 && local.Matches(commit) {
				t.Fatal("one op unexpectedly matched the three-op head")
			}
			if i == len(pages)-1 && !local.Matches(commit) {
				t.Fatal("fully replayed oplog does not match the final page's commit")
			}
			for _, op := range ops {
				seen = append(seen, op["rev"].(string))
			}
		}
		if len(seen) != 3 || len(map[string]bool{seen[0]: true, seen[1]: true, seen[2]: true}) != 3 {
			t.Fatalf("paging repeated or dropped revisions: %v", seen)
		}
	})

	t.Run("pages with since and cursor together", func(t *testing.T) {
		// Reference: oplog paging / pages with since and cursor together.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		for i := 0; i < 4; i++ {
			mustOK(t, doWrite(dan, sp, writeOpts{rkey: fmt.Sprintf("prec-%d", i)}))
		}
		cred := credentialFor(t, dan, r.pds1, sp)
		all := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		if len(all.list("ops")) != 4 {
			t.Fatalf("all ops: %s", all.raw)
		}
		since := all.list("ops")[0]["rev"].(string)
		pages := syncListRepoOpsPages(t, cred, r.pds1, sp, dan.did, map[string]string{"since": since, "limit": "1"})
		var got []string
		for _, page := range pages {
			for _, op := range page.list("ops") {
				got = append(got, op["rkey"].(string))
			}
		}
		want := []string{"prec-1", "prec-2", "prec-3"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("rkeys %v, want %v", got, want)
		}
	})

	t.Run("inlines only a record current value", func(t *testing.T) {
		// Reference: oplog paging / inlines only a record current value.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "inlined", text: "first"}))
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "inlined", text: "second"}))
		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		ops := res.list("ops")
		if len(ops) != 2 {
			t.Fatalf("ops: %s", res.raw)
		}
		if _, ok := ops[0]["value"]; ok {
			t.Fatalf("superseded op inlined a stale value: %v", ops[0])
		}
		value, _ := ops[1]["value"].(map[string]any)
		if value["text"] != "second" {
			t.Fatalf("current op did not inline its value: %v", ops[1])
		}
	})

	t.Run("omits values entirely with excludeValues", func(t *testing.T) {
		// Reference: oplog paging / omits values entirely with excludeValues.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "no-value", text: "body"}))
		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "excludeValues": "true"}))
		ops := res.list("ops")
		if len(ops) != 1 || ops[0]["rkey"] != "no-value" {
			t.Fatalf("ops: %s", res.raw)
		}
		if _, ok := ops[0]["value"]; ok {
			t.Fatalf("excludeValues returned a value: %v", ops[0])
		}
	})

	t.Run("rejects a malformed cursor", func(t *testing.T) {
		// Reference: oplog paging / rejects a malformed cursor.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "cursor-check"}))
		cred := credentialFor(t, dan, r.pds1, sp)
		expectErr(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "cursor": "not-a-cursor"}), 400, "InvalidCursor")
	})
}

func TestSpaceSyncIncrementalCatchUp(t *testing.T) {
	r := newSyncNet(t)
	alice, dan, bob := r.alice, r.dan, r.bob

	t.Run("replays the oplog to the repo commit", func(t *testing.T) {
		// Reference: incremental catch-up / replays the oplog to the repo commit.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "one", text: "one"}))
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "two", text: "two"}))
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "two", text: "two revised"}))
		mustOK(t, doDel(dan, sp, "", "one"))
		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		commit := syncVerifyResponseCommit(t, cred, res, sp, dan.did)
		local := space.NewRepoCommit()
		syncApplyWireOps(t, local, res.list("ops"))
		if !local.Matches(commit) {
			t.Fatal("replayed oplog does not match the authenticated commit")
		}
	})

	t.Run("detects divergence when an op is missed", func(t *testing.T) {
		// Reference: incremental catch-up / detects divergence when an op is missed.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "kept", text: "kept"}))
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "missed", text: "missed"}))
		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		commit := syncResponseCommit(t, res)
		ops := res.list("ops")
		local := space.NewRepoCommit()
		syncApplyWireOps(t, local, ops[:len(ops)-1])
		if local.Matches(commit) {
			t.Fatal("missing an op still matched the repo commit")
		}
	})

	t.Run("prunes the oplog on its own past a retention window", func(t *testing.T) {
		t.Skip("reference it.todo: neither implementation has an oplog retention job")
	})

	t.Run("recovers from a pruned oplog via listRecords", func(t *testing.T) {
		// Reference: incremental catch-up / recovers from a pruned oplog via listRecords.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		for _, text := range []string{"pre 1", "pre 2", "pre 3"} {
			mustOK(t, doWrite(bob, sp, writeOpts{text: text}))
		}
		consumerSince := *repoState(t, bob, sp).Rev
		mustOK(t, doWrite(bob, sp, writeOpts{text: "post 1"}))
		mustOK(t, doWrite(bob, sp, writeOpts{text: "post 2"}))

		// Deliberately reach into storage to simulate the retention gap, as the
		// reference does; no public endpoint prunes oplog rows.
		if err := bob.pds.s.db.Exec(context.Background(), "DELETE FROM space_record_oplogs WHERE space = ? AND rev <= ?", nil, sp, consumerSince).Error; err != nil {
			t.Fatal(err)
		}
		cred := credentialFor(t, bob, r.pds1, sp)
		// Rebuild an empty consumer from whatever history remains. Keeping
		// since=consumerSince here would filter out the pre writes even without
		// pruning, so the mismatch would not exercise the retention gap.
		incremental := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": bob.did, "limit": "100"}))
		if len(incremental.list("ops")) != 2 {
			t.Fatalf("incremental ops: %s", incremental.raw)
		}
		commit := syncResponseCommit(t, incremental)
		applied := space.NewRepoCommit()
		syncApplyWireOps(t, applied, incremental.list("ops"))
		if applied.Matches(commit) {
			t.Fatal("incomplete post-prune diff unexpectedly matched the commit")
		}

		var recovered []space.RecordRef
		cursor := ""
		for i := 0; i < 10; i++ {
			params := map[string]string{"space": sp, "repo": bob.did, "limit": "2"}
			if cursor != "" {
				params["cursor"] = cursor
			}
			res := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRecords", params))
			for _, rec := range res.list("records") {
				recovered = append(recovered, space.RecordRef{Collection: rec["collection"].(string), Rkey: rec["rkey"].(string), Cid: mustCid(t, rec["cid"].(string))})
			}
			cursor = res.str("cursor")
			if cursor == "" {
				break
			}
		}
		if cursor != "" {
			t.Fatal("listRecords did not drain within ten pages")
		}
		if len(recovered) != 5 {
			t.Fatalf("recovered %d records, want five", len(recovered))
		}
		latest := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": bob.did}))
		latestCommit := syncVerifyResponseCommit(t, cred, latest, sp, bob.did)
		if !space.RepoCommitFromRecords(recovered).Matches(latestCommit) {
			t.Fatal("full-state listRecords rebuild does not match getLatestCommit")
		}
	})
}

func TestSpaceSyncGetRepo(t *testing.T) {
	r := newSyncNet(t)
	alice, bob, carol := r.alice, r.bob, r.carol

	t.Run("serves a verifiable STAR archive for full-state recovery", func(t *testing.T) {
		// Reference: getRepo / serves a verifiable STAR archive for full-state recovery.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		for _, collection := range []string{testCollection, testCollectionAlt} {
			for i := 0; i < 2; i++ {
				mustOK(t, doWrite(bob, sp, writeOpts{collection: collection, rkey: fmt.Sprintf("star-%d", i), text: fmt.Sprintf("star %d", i)}))
			}
		}
		cred := credentialFor(t, carol, r.pds1, sp)
		res := mustOK(t, syncFetchRepo(t, cred, r.pds2, sp, bob.did))
		if ct := res.header.Get("Content-Type"); !strings.Contains(ct, "application/vnd.dasl.star") {
			t.Fatalf("Content-Type %q, want application/vnd.dasl.star", ct)
		}
		syncCheckStarFraming(t, res.raw, 4)
		recovered := syncVerifyRepo(t, cred, res.raw, sp, bob.did)
		state := repoState(t, bob, sp)
		if len(recovered.Records) != 4 || recovered.Commit.Rev != *state.Rev {
			t.Fatalf("recovered %d records at rev %s, want four at %s", len(recovered.Records), recovered.Commit.Rev, *state.Rev)
		}
		stored, err := space.RepoCommitFromState(state.SetHash)
		if err != nil {
			t.Fatal(err)
		}
		var refs []space.RecordRef
		var texts []string
		for _, rec := range recovered.Records {
			refs = append(refs, space.RecordRef{Collection: rec.Collection, Rkey: rec.Rkey, Cid: rec.Cid})
			if rec.Collection == testCollection {
				texts = append(texts, rec.Record["text"].(string))
			}
		}
		sort.Strings(texts)
		if !reflect.DeepEqual(texts, []string{"star 0", "star 1"}) {
			t.Fatalf("recovered record texts %v", texts)
		}
		if !space.RepoCommitFromRecords(refs).SetHash.Equal(stored.SetHash) {
			t.Fatal("recovered archive's set hash differs from stored state")
		}
	})

	t.Run("recovers from a cleared repo", func(t *testing.T) {
		// Reference: getRepo / recovers from a cleared repo.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		mustOK(t, doWrite(bob, sp, writeOpts{rkey: "one", text: "one"}))
		mustOK(t, doWrite(bob, sp, writeOpts{rkey: "two", text: "two"}))
		cred := credentialFor(t, carol, r.pds1, sp)
		synced := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": bob.did}))
		syncedCommit := syncResponseCommit(t, synced)
		local := space.NewRepoCommit()
		syncApplyWireOps(t, local, synced.list("ops"))
		if !local.Matches(syncedCommit) {
			t.Fatal("initial oplog did not sync")
		}

		mustOK(t, clearRecords(bob, sp))
		incremental := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": bob.did, "since": syncedCommit.Rev}))
		if len(incremental.list("ops")) != 0 {
			t.Fatalf("cleared oplog returned ops: %s", incremental.raw)
		}
		emptyCommit := syncVerifyResponseCommit(t, cred, incremental, sp, bob.did)
		if local.Matches(emptyCommit) {
			t.Fatal("old local state matches the cleared commit")
		}
		res := mustOK(t, syncFetchRepo(t, cred, r.pds2, sp, bob.did))
		syncCheckStarFraming(t, res.raw, 0)
		recovered := syncVerifyRepo(t, cred, res.raw, sp, bob.did)
		if len(recovered.Records) != 0 || recovered.Commit.Rev != emptyCommit.Rev {
			t.Fatalf("cleared recovery returned %d records at %s, want zero at %s", len(recovered.Records), recovered.Commit.Rev, emptyCommit.Rev)
		}
	})

	t.Run("refuses a repo without a credential for that space", func(t *testing.T) {
		// Reference: getRepo / refuses a repo without a credential for that space.
		sp := createSpace(t, alice, spaceOpts{skey: "star-auth", members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{rkey: "auth-check"}))
		other := createSpace(t, alice, spaceOpts{skey: "star-auth-other", members: []*actor{carol}})
		wrongCred := credentialFor(t, carol, r.pds1, other)
		res := syncFetchRepo(t, wrongCred, r.pds2, sp, bob.did)
		if res.status < 400 {
			t.Fatalf("wrong-space credential was accepted: %d %s", res.status, res.raw)
		}
	})

	t.Run("reports RepoNotFound for an unwritten repo", func(t *testing.T) {
		// Reference: getRepo / reports RepoNotFound for an unwritten repo.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{carol}})
		cred := credentialFor(t, carol, r.pds1, sp)
		params := map[string]string{"space": sp, "repo": alice.did}
		expectErr(t, cred.get(t, r.pds1, "com.atproto.space.getLatestCommit", params), 400, "RepoNotFound")
		expectErr(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", params), 400, "RepoNotFound")
		expectErr(t, syncFetchRepo(t, cred, r.pds1, sp, alice.did), 400, "RepoNotFound")
	})
}

func TestSpaceSyncMacs(t *testing.T) {
	r := newSyncNet(t)
	alice, bob, carol := r.alice, r.bob, r.carol
	latestParams := func(sp string, a *actor) map[string]string {
		return map[string]string{"space": sp, "repo": a.did}
	}

	t.Run("publishes a KEM key for each account", func(t *testing.T) {
		// Reference: MACs / publishes a KEM key for each account.
		repo, err := bob.pds.s.getRepoActorByDid(context.Background(), bob.did)
		if err != nil {
			t.Fatal(err)
		}
		kem, err := accountKemDIDKey(repo.Repo)
		if err != nil || kem == "" {
			t.Fatalf("stored KEM key %q: %v", kem, err)
		}
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		cred := credentialFor(t, bob, r.pds1, sp)
		if got := cred.kemKey(t, bob.did); got != kem {
			t.Fatalf("published KEM key %s, want %s", got, kem)
		}
		// newTestServer leaves network collaborators nil. Supply a real PLC
		// client for this endpoint: CreateDidCredentials itself is local and
		// only needs a rotation key, not network access.
		plcClient, err := plc.NewClient(&plc.ClientArgs{H: r.net.http, Service: r.net.dir.srv.URL, RotationKey: bob.key.Bytes(), PdsHostname: bob.pds.s.config.Hostname})
		if err != nil {
			t.Fatal(err)
		}
		bob.pds.s.plcClient = plcClient
		defer func() { bob.pds.s.plcClient = nil }()
		recommended := mustOK(t, bob.get("com.atproto.identity.getRecommendedDidCredentials", nil))
		methods, _ := recommended.body["verificationMethods"].(map[string]any)
		if methods["atproto_kem"] != kem {
			t.Fatalf("recommended atproto_kem %v, want %s", methods["atproto_kem"], kem)
		}
	})

	t.Run("macs a record served to a syncer", func(t *testing.T) {
		// Reference: MACs / macs a record served to a syncer.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		mustOK(t, doWrite(bob, sp, writeOpts{rkey: "maced"}))
		cred := credentialFor(t, carol, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.getRecord", map[string]string{"space": sp, "repo": bob.did, "collection": testCollection, "rkey": "maced"}))
		if cred.lastMac.profile != space.RecordMacProfile {
			t.Fatalf("request MAC profile %s, want %s", cred.lastMac.profile, space.RecordMacProfile)
		}
		if res.header.Get(space.HeaderRecord) == "" || res.header.Get("Signature") == "" || res.header.Get("Signature-Input") == "" {
			t.Fatalf("record response lacks MAC headers: %v", res.header)
		}
		value, _ := res.body["value"].(map[string]any)
		record, err := syncAtdataFromJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		uri := sp + "/" + bob.did + "/" + testCollection + "/maced"
		params := space.VerifyRecordParams{URI: uri, VerifyMacParams: cred.macParams(t)}
		if err := space.VerifyRecord(res.str("uri"), res.str("cid"), record, params); err != nil {
			t.Fatalf("record MAC does not verify: %v", err)
		}
		params.URI += "x"
		if err := space.VerifyRecord(res.str("uri"), res.str("cid"), record, params); err == nil {
			t.Fatal("record verified under another URI")
		}
	})

	t.Run("macs every oplog page", func(t *testing.T) {
		// Reference: MACs / macs every oplog page.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{rkey: "page-0"}))
		mustOK(t, doWrite(bob, sp, writeOpts{rkey: "page-1"}))
		cred := credentialFor(t, bob, r.pds1, sp)
		first := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": bob.did, "limit": "1"}))
		if first.str("cursor") == "" {
			t.Fatalf("full first page has no cursor: %s", first.raw)
		}
		syncVerifyResponseCommit(t, cred, first, sp, bob.did)
		second := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": bob.did, "limit": "1", "cursor": first.str("cursor")}))
		syncVerifyResponseCommit(t, cred, second, sp, bob.did)
	})

	t.Run("requires a well formed MAC request with a space credential", func(t *testing.T) {
		// Reference: MACs / requires a MAC request with a space credential; also
		// pins the November Accept-Signature parser cases from space/mac.test.ts.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		cred := credentialFor(t, bob, r.pds1, sp)
		sigHeaders := cred.headers(t, bob.did)
		enc, err := space.Encapsulate(cred.kemKey(t, bob.did))
		if err != nil {
			t.Fatal(err)
		}
		valid := space.FormatMacRequest(space.CommitMacProfile, enc.KeyShare)
		second := strings.Replace(valid, "mac=", "other=", 1)
		cases := []struct {
			name, header string
		}{
			{"missing", ""},
			{"malformed", "???"},
			{"two requests with the same tag", valid + ", " + second},
			{"created parameter", valid + ";created=1700000000"},
			{"expires parameter", valid + ";expires=1700000000"},
			{"nonce parameter", valid + `;nonce="abc"`},
			{"wrong covered header", strings.Replace(valid, space.CommitMacProfile+`";sf`, space.RecordMacProfile+`";sf`, 1)},
			{"wrong profile", space.FormatMacRequest(space.RecordMacProfile, enc.KeyShare)},
			{"wrong algorithm", valid + `;alg="ecdsa-p256-sha256"`},
			{"missing key", `mac=("atproto-space-commit";sf);tag="atproto-space-commit"`},
			{"bad key", space.FormatMacRequest(space.CommitMacProfile, "did:key:nope")},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h := map[string]string{}
				for k, v := range sigHeaders {
					h[k] = v
				}
				if tc.header != "" {
					h[space.HeaderAcceptSignature] = tc.header
				}
				for _, method := range []string{"com.atproto.space.getLatestCommit", "com.atproto.space.getRepo", "com.atproto.space.listRepoOps"} {
					expectErr(t, r.pds2.get(method, latestParams(sp, bob), h), 400, "InvalidSpaceMac")
				}
			})
		}

		// The record profile is likewise mandatory before looking up a record.
		h := map[string]string{}
		for k, v := range sigHeaders {
			h[k] = v
		}
		expectErr(t, r.pds2.get("com.atproto.space.getRecord", map[string]string{"space": sp, "repo": bob.did, "collection": testCollection, "rkey": "missing"}, h), 400, "InvalidSpaceMac")
		// Reads which do not return authenticated values need no MAC request.
		mustOK(t, r.pds2.get("com.atproto.space.listRecords", latestParams(sp, bob), h))
	})

	t.Run("macs an account its own data only when asked", func(t *testing.T) {
		// Reference: MACs / macs an account its own data only when asked.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		params := latestParams(sp, bob)
		unasked := mustOK(t, bob.get("com.atproto.space.getLatestCommit", params))
		if unasked.header.Get("Signature") != "" || unasked.header.Get(space.HeaderCommit) != "" {
			t.Fatal("unrequested response carried a MAC")
		}
		if !strings.Contains(strings.ToLower(strings.Join(unasked.header.Values("Vary"), ",")), "accept-signature") {
			t.Fatalf("Vary does not include Accept-Signature: %v", unasked.header.Values("Vary"))
		}

		other := bob.auth()
		other[space.HeaderAcceptSignature] = `other=("@status");tag="other"`
		otherRes := mustOK(t, r.pds2.get("com.atproto.space.getLatestCommit", params, other))
		if otherRes.header.Get("Signature") != "" {
			t.Fatal("request for another signature tag was not ignored")
		}

		cred := credentialFor(t, bob, r.pds1, sp)
		enc, err := space.Encapsulate(cred.kemKey(t, bob.did))
		if err != nil {
			t.Fatal(err)
		}
		askedHeaders := bob.auth()
		askedHeaders[space.HeaderAcceptSignature] = space.FormatMacRequest(space.CommitMacProfile, enc.KeyShare)
		asked := mustOK(t, r.pds2.get("com.atproto.space.getLatestCommit", params, askedHeaders))
		exposed := strings.ToLower(strings.Join(asked.header.Values("Access-Control-Expose-Headers"), ","))
		for _, name := range []string{"atproto-space-commit", "signature-input", "signature"} {
			if !strings.Contains(exposed, name) {
				t.Fatalf("Access-Control-Expose-Headers %q lacks %s", exposed, name)
			}
		}
		commit := syncResponseCommit(t, asked)
		macParams := space.VerifyMacParams{Encapsulation: *enc, Headers: asked.header}
		if err := space.VerifyCommit(commit, space.VerifyCommitParams{Space: sp, Repo: bob.did, VerifyMacParams: macParams}); err != nil {
			t.Fatalf("self-read commit MAC does not verify: %v", err)
		}
		if asked.header.Get(space.HeaderCommit) == "" {
			t.Fatal("response lacks the covered Atproto-Space-Commit header")
		}

		// The covered header is bound to the returned body, and verification
		// uses the 32-byte secret exported by HPKE, not merely the key share.
		changed := commit
		changed.Rev = nextTID(commit.Rev)
		if err := space.VerifyCommit(changed, space.VerifyCommitParams{Space: sp, Repo: bob.did, VerifyMacParams: macParams}); err == nil {
			t.Fatal("a body that differs from the covered commit header verified")
		}
		wrongSecret := macParams
		wrongSecret.SharedSecret = bytes.Clone(enc.SharedSecret)
		wrongSecret.SharedSecret[0] ^= 0xff
		if err := space.VerifyCommit(commit, space.VerifyCommitParams{Space: sp, Repo: bob.did, VerifyMacParams: wrongSecret}); err == nil {
			t.Fatal("commit verified under the wrong HPKE secret")
		}
		serverSecret, err := space.Decapsulate(bob.kem, enc.KeyShare)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(serverSecret, enc.SharedSecret) {
			t.Fatal("HPKE decapsulation exported a different secret")
		}

		// Labels have no protocol meaning: the server responds under the
		// requested label, and the verifier selects the response by tag.
		labelRequest := strings.Replace(space.FormatMacRequest(space.CommitMacProfile, enc.KeyShare), "mac=", "proof=", 1)
		cred.getWith(t, r.pds2, "com.atproto.space.getLatestCommit", params, map[string]string{space.HeaderAcceptSignature: labelRequest})
		labeled := cred.lastMac.headers
		if !strings.HasPrefix(labeled.Get("Signature-Input"), "proof=") || !strings.HasPrefix(labeled.Get("Signature"), "proof=") {
			t.Fatalf("response did not use requested label: %v", labeled)
		}
		labelParams := space.VerifyMacParams{Encapsulation: *enc, Headers: labeled}
		if err := space.VerifyCommit(commit, space.VerifyCommitParams{Space: sp, Repo: bob.did, VerifyMacParams: labelParams}); err != nil {
			t.Fatalf("MAC under another label was not found by tag: %v", err)
		}
	})
}

func TestSpaceSyncWriterSet(t *testing.T) {
	r := newSyncNet(t)
	alice, dan, bob, carol := r.alice, r.dan, r.bob, r.carol

	t.Run("records a co-located writer without resolving its public PDS endpoint", func(t *testing.T) {
		// Reference: writer set / records a co-located writer without resolving its public PDS endpoint.
		sp := createSpace(t, alice, spaceOpts{policy: memberPolicy(map[string]any{"publicWrite": true})})
		r.net.dir.down.Store(true)
		res := doWrite(dan, sp, writeOpts{text: "same PDS"})
		r.net.dir.down.Store(false)
		mustOK(t, res)
		if got := syncWriterDids(t, r, sp); !reflect.DeepEqual(got, []string{dan.did}) {
			t.Fatalf("writer set %v, want only dan", got)
		}
	})

	t.Run("records a writer from notifyRepoUpdate and it is not the member list", func(t *testing.T) {
		// Reference: writer set / records a writer from notifyRepoUpdate, and it is not the member list.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{text: "writer set entry"}))
		cred := credentialFor(t, bob, r.pds1, sp)
		var listed xres
		if !awaitCond(t, func() bool {
			listed = syncListWriters(t, cred, r.pds1, sp, nil)
			return syncContains(syncActiveWriterDids(listed), bob.did)
		}) {
			t.Fatal("bob never reached the writer set")
		}
		dids := syncListedWriterDids(listed)
		if !syncContains(dids, bob.did) || syncContains(dids, alice.did) {
			t.Fatalf("writer set %v is not the actual writer boundary", dids)
		}
		entry := syncWriterEntry(t, listed, bob.did, "com.atproto.space.defs#repoWrite")
		state := repoState(t, bob, sp)
		spaceRev, ok := entry["spaceRev"].(string)
		if entry["repoRev"] != *state.Rev || !ok || spaceRev == "" {
			t.Fatalf("writer entry lacks repo/space positions: %v", entry)
		}
		gotHash, err := syncLexBytes(entry["data"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotHash, syncLtHashDigest(t, state.SetHash)) {
			t.Fatal("writer entry carries the wrong commit data")
		}
	})

	t.Run("records a writer admitted by public write access who was never a member", func(t *testing.T) {
		// Reference: writer set / records a writer admitted by public write access, who was never a member.
		sp := createSpace(t, alice, spaceOpts{policy: memberPolicy(map[string]any{"publicWrite": true})})
		mustOK(t, doWrite(bob, sp, writeOpts{text: "from a non-member"}))
		if !awaitCond(t, func() bool { return syncContains(syncWriterDids(t, r, sp), bob.did) }) {
			t.Fatal("public writer never reached the writer set")
		}
		cred := credentialFor(t, alice, r.pds1, sp)
		syncExpectActiveWriters(t, cred, r.pds1, sp, bob.did)
	})

	t.Run("records a writer into an app gated space whose PDS presents no attestation", func(t *testing.T) {
		// Reference: writer set / records a writer into an app-gated space, whose PDS presents no attestation.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}, policy: memberPolicy(map[string]any{"allowedApps": []string{"https://app.example.com/client-metadata.json"}})})
		mustOK(t, doWrite(bob, sp, writeOpts{text: "app-gated space"}))
		if !awaitCond(t, func() bool { return syncContains(syncWriterDids(t, r, sp), bob.did) }) {
			t.Fatal("app-gated writer never reached the writer set")
		}
	})

	for _, removal := range []string{"removeWriter", "removeMembers"} {
		t.Run("announces "+removal+" and tracks the writer again after a write", func(t *testing.T) {
			// Reference: writer set / drops a writer on removeWriter, and tracks
			// it again once it writes. The removeMembers variant exercises the
			// same removal announcement through membership changes.
			syncer := syncMockSyncer(r, false)
			sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}, policy: memberPolicy(map[string]any{"publicWrite": true})})
			cred, _ := credentialWithNotify(t, carol, r.pds1, sp, &notifyReg{endpoint: syncer.url, token: "writer-removal-" + removal})
			mustOK(t, doWrite(bob, sp, writeOpts{text: "before removal"}))
			r.net.waitSpaceJobs()
			before := syncListWriters(t, cred, r.pds1, sp, nil)
			beforeCursor := before.str("cursor")
			if beforeCursor == "" {
				t.Fatalf("initial writer page has no cursor: %s", before.raw)
			}

			if removal == "removeWriter" {
				mustOK(t, removeWriter(alice, sp, bob))
			} else {
				removeMember(t, alice, sp, bob)
			}
			r.net.waitSpaceJobs()
			syncExpectActiveWriters(t, cred, r.pds1, sp)
			caughtUp := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": beforeCursor})
			removed := syncWriterEntry(t, caughtUp, bob.did, "com.atproto.space.defs#repoRemoved")
			if len(caughtUp.list("repos")) != 1 || removed["spaceRev"] != caughtUp.str("cursor") || caughtUp.str("cursor") <= beforeCursor {
				t.Fatalf("bad removal checkpoint: before %s after %s", before.raw, caughtUp.raw)
			}
			if !awaitCond(t, func() bool {
				for _, update := range syncSpaceUpdates(syncer) {
					if update["$type"] == "com.atproto.space.defs#repoRemoved" && update["repo"] == bob.did {
						return update["spaceRev"] == removed["spaceRev"]
					}
				}
				return false
			}) {
				t.Fatalf("%s removal was not announced: %+v", removal, syncSpaceUpdates(syncer))
			}

			// publicWrite still authorizes bob even after removeMembers.
			mustOK(t, doWrite(bob, sp, writeOpts{text: "after removal"}))
			r.net.waitSpaceJobs()
			syncExpectActiveWriters(t, cred, r.pds1, sp, bob.did)
			readded := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": caughtUp.str("cursor")})
			write := syncWriterEntry(t, readded, bob.did, "com.atproto.space.defs#repoWrite")
			if write["spaceRev"].(string) <= removed["spaceRev"].(string) {
				t.Fatalf("re-added writer did not advance the space revision: %s", readded.raw)
			}
		})
	}

	t.Run("ignores removeWriter for a repo outside the writer set", func(t *testing.T) {
		// Reference: writer set / ignores removeWriter for a repo outside the writer set.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{}))
		mustOK(t, removeWriter(alice, sp, dan))
		cred := credentialFor(t, alice, r.pds1, sp)
		before := syncListWriters(t, cred, r.pds1, sp, nil)
		mustOK(t, removeWriter(alice, sp, bob))
		mustOK(t, removeWriter(alice, sp, dan))
		after := syncListWriters(t, cred, r.pds1, sp, nil)
		if !reflect.DeepEqual(before.body, after.body) {
			t.Fatalf("no-op removals advanced writer state: before %s after %s", before.raw, after.raw)
		}
	})

	t.Run("refuses removeWriter from anyone but the authority", func(t *testing.T) {
		// Reference: writer set / refuses removeWriter from anyone but the authority.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{text: "still tracked"}))
		expectErr(t, removeWriter(dan, sp, dan), 400, "NotAuthorized")
		if got := syncWriterDids(t, r, sp); !reflect.DeepEqual(got, []string{dan.did}) {
			t.Fatalf("writer set changed after unauthorized removal: %v", got)
		}
	})

	t.Run("keeps a cleared repo in the writer set at the empty digest", func(t *testing.T) {
		// Reference: writer set / keeps a cleared repo in the writer set, at the empty digest.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{text: "to be cleared"}))
		mustOK(t, clearRecords(dan, sp))
		cred := credentialFor(t, alice, r.pds1, sp)
		listed := syncListWriters(t, cred, r.pds1, sp, nil)
		entry := syncWriterEntry(t, listed, dan.did, "com.atproto.space.defs#repoWrite")
		state := repoState(t, dan, sp)
		if entry["repoRev"] != *state.Rev {
			t.Fatalf("cleared writer repoRev %v, want %s", entry["repoRev"], *state.Rev)
		}
		got, err := syncLexBytes(entry["data"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, syncEmptyHash()) {
			t.Fatal("cleared repo is not listed at the empty LtHash digest")
		}
	})
}

func TestSpaceSyncCatchUp(t *testing.T) {
	r := newSyncNet(t)
	alice, bob, dan, carol := r.alice, r.bob, r.dan, r.carol

	t.Run("recovers missed notifications with a space checkpoint", func(t *testing.T) {
		// Reference: space catch-up / recovers missed notifications with a space checkpoint.
		syncer := syncMockSyncer(r, true)
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, dan, carol}})
		cred, _ := credentialWithNotify(t, carol, r.pds1, sp, &notifyReg{endpoint: syncer.url, token: "missed-notifications"})
		empty := syncListWriters(t, cred, r.pds1, sp, nil)
		if len(empty.list("repos")) != 0 {
			t.Fatalf("initial writers: %s", empty.raw)
		}
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		initial := syncAwaitListedWriter(t, cred, r.pds1, sp, bob.did, "", nil)
		cursor := initial.str("cursor")
		if cursor == "" || cursor != initial.list("repos")[len(initial.list("repos"))-1]["spaceRev"] {
			t.Fatalf("initial checkpoint: %s", initial.raw)
		}
		mustOK(t, doWrite(dan, sp, writeOpts{}))
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		r.net.waitSpaceJobs()
		if got := len(syncSpaceUpdates(syncer)); got != 3 {
			t.Fatalf("rejecting syncer received %d update attempts, want all three writes", got)
		}

		first := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": cursor, "limit": "1"})
		if got := syncListedWriterDids(first); !reflect.DeepEqual(got, []string{dan.did}) {
			t.Fatalf("first catch-up page %v, want dan", got)
		}
		// A repo already seen can advance while a syncer is still paging.
		mustOK(t, doWrite(dan, sp, writeOpts{}))
		second := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": first.str("cursor"), "limit": "1"})
		if got := syncListedWriterDids(second); !reflect.DeepEqual(got, []string{bob.did}) {
			t.Fatalf("second catch-up page %v, want bob", got)
		}
		last := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": second.str("cursor"), "limit": "1"})
		if got := syncListedWriterDids(last); !reflect.DeepEqual(got, []string{dan.did}) {
			t.Fatalf("last catch-up page %v, want dan", got)
		}
		nextCursor := last.str("cursor")
		if nextCursor == "" || nextCursor != last.list("repos")[0]["spaceRev"] {
			t.Fatalf("last checkpoint: %s", last.raw)
		}
		caughtUp := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": nextCursor})
		if len(caughtUp.list("repos")) != 0 || caughtUp.str("cursor") != "" {
			t.Fatalf("not caught up: %s", caughtUp.raw)
		}
	})

	t.Run("returns the current space revision on authorization and listSpaces", func(t *testing.T) {
		// Reference: space catch-up / returns the space's current revision on
		// each authorization. Also checks the same checkpoint in listSpaces.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan, carol}})
		authorize := func() xres {
			key := newP256Key(t)
			return mustOK(t, exchange(t, r.pds1, sp, delegationTokenFor(t, carol, sp), key, ""))
		}
		if got := authorize().str("spaceRev"); got != "" {
			t.Fatalf("new space has spaceRev %q", got)
		}
		mustOK(t, doWrite(dan, sp, writeOpts{}))
		cred := credentialFor(t, carol, r.pds1, sp)
		written := syncListWriters(t, cred, r.pds1, sp, nil)
		writerEntry := syncWriterEntry(t, written, dan.did, "com.atproto.space.defs#repoWrite")
		if written.str("cursor") == "" || writerEntry["spaceRev"] != written.str("cursor") {
			t.Fatalf("write did not publish a nonempty checkpoint: %s", written.raw)
		}
		if got := authorize().str("spaceRev"); got != written.str("cursor") {
			t.Fatalf("authorization spaceRev %q, want %q", got, written.str("cursor"))
		}
		mustOK(t, removeWriter(alice, sp, dan))
		removed := syncListWriters(t, cred, r.pds1, sp, nil)
		if removed.str("cursor") <= written.str("cursor") {
			t.Fatalf("removal cursor did not advance: %s -> %s", written.str("cursor"), removed.str("cursor"))
		}
		if got := authorize().str("spaceRev"); got != removed.str("cursor") {
			t.Fatalf("authorization after removal spaceRev %q, want %q", got, removed.str("cursor"))
		}
		spaces := mustOK(t, alice.get("com.atproto.space.listSpaces", map[string]string{"spaceDid": alice.did}))
		var entry map[string]any
		for _, candidate := range spaces.list("spaces") {
			if candidate["space"] == sp {
				entry = candidate
			}
		}
		if entry == nil || entry["spaceRev"] != removed.str("cursor") {
			t.Fatalf("listSpaces did not publish the checkpoint %q: %s", removed.str("cursor"), spaces.raw)
		}
	})

	t.Run("resumes after an empty page using the last processed repo revision", func(t *testing.T) {
		// Reference: space catch-up / resumes after an empty page using the last processed repo revision.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		cred := credentialFor(t, alice, r.pds1, sp)
		initial := syncAwaitListedWriter(t, cred, r.pds1, sp, bob.did, "", nil)
		cursor := initial.str("cursor")
		empty := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": cursor})
		if len(empty.list("repos")) != 0 || empty.str("cursor") != "" {
			t.Fatalf("expected an empty page without a new cursor: %s", empty.raw)
		}
		if empty.str("cursor") != "" {
			cursor = empty.str("cursor")
		}
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		catchUp := syncAwaitListedWriter(t, cred, r.pds1, sp, bob.did, cursor, map[string]string{"cursor": cursor})
		if got := syncListedWriterDids(catchUp); !reflect.DeepEqual(got, []string{bob.did}) {
			t.Fatalf("catch-up writers %v, want bob", got)
		}
		if catchUp.list("repos")[0]["spaceRev"].(string) <= cursor {
			t.Fatal("catch-up did not advance the saved revision")
		}
	})

	t.Run("accepts arbitrary string listWriters cursors", func(t *testing.T) {
		// Reference: space catch-up / accepts arbitrary string listWriters cursors.
		sp := createSpace(t, alice, spaceOpts{})
		mustOK(t, doWrite(alice, sp, writeOpts{}))
		cred := credentialFor(t, alice, r.pds1, sp)
		before := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": "0"})
		if got := syncListedWriterDids(before); !reflect.DeepEqual(got, []string{alice.did}) {
			t.Fatalf("writers after cursor 0: %v", got)
		}
		after := syncListWriters(t, cred, r.pds1, sp, map[string]string{"cursor": "not-a-tid"})
		if len(after.list("repos")) != 0 || after.str("cursor") != "" {
			t.Fatalf("future arbitrary cursor returned entries: %s", after.raw)
		}
	})

	t.Run("chains forwarded notifications across local and remote writers", func(t *testing.T) {
		// Reference: space catch-up / chains forwarded notifications across local and remote writers.
		syncer := syncMockSyncer(r, false)
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, dan, carol}})
		cred, _ := credentialWithNotify(t, carol, r.pds1, sp, &notifyReg{endpoint: syncer.url, token: "sequence-chain"})
		mustOK(t, doWrite(alice, sp, writeOpts{}))
		start := make(chan struct{})
		responses := make(chan xres, 2)
		var wg sync.WaitGroup
		for _, writer := range []*actor{bob, dan} {
			wg.Add(1)
			go func(a *actor) {
				defer wg.Done()
				<-start
				responses <- doWrite(a, sp, writeOpts{})
			}(writer)
		}
		close(start)
		wg.Wait()
		close(responses)
		for res := range responses {
			mustOK(t, res)
		}
		r.net.waitSpaceJobs()
		updates := syncSpaceUpdates(syncer)
		if len(updates) != 3 {
			t.Fatalf("got %d forwarded updates, want three: %+v", len(updates), updates)
		}
		sort.Slice(updates, func(i, j int) bool { return updates[i]["spaceRev"].(string) < updates[j]["spaceRev"].(string) })
		for i, update := range updates {
			if update["$type"] != "com.atproto.space.defs#repoWrite" {
				t.Fatalf("unexpected update type: %v", update)
			}
			if i == 0 {
				if _, ok := update["prevSpaceRev"]; ok {
					t.Fatalf("first update has prevSpaceRev: %v", update)
				}
			} else if update["prevSpaceRev"] != updates[i-1]["spaceRev"] {
				t.Fatalf("space revision chain broken at %d: %+v", i, updates)
			}
		}
		listed := syncListWriters(t, cred, r.pds1, sp, nil)
		repos := listed.list("repos")
		if len(repos) != 3 || repos[len(repos)-1]["spaceRev"] != updates[2]["spaceRev"] {
			t.Fatalf("listed sequence differs from notifications: %s / %+v", listed.raw, updates)
		}
		seen := map[string]bool{}
		for _, entry := range repos {
			seen[entry["spaceRev"].(string)] = true
		}
		if len(seen) != 3 {
			t.Fatalf("writer entries reused space revisions: %s", listed.raw)
		}
	})

	t.Run("forwards a removal from the writer set in the space sequence", func(t *testing.T) {
		// Reference: space catch-up / forwards a removal from the writer set, in the space sequence.
		syncer := syncMockSyncer(r, false)
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan, carol}})
		cred, _ := credentialWithNotify(t, carol, r.pds1, sp, &notifyReg{endpoint: syncer.url, token: "removal-chain"})
		mustOK(t, doWrite(dan, sp, writeOpts{}))
		mustOK(t, removeWriter(alice, sp, dan))
		r.net.waitSpaceJobs()
		var write, removal map[string]any
		for _, update := range syncSpaceUpdates(syncer) {
			switch update["$type"] {
			case "com.atproto.space.defs#repoWrite":
				write = update
			case "com.atproto.space.defs#repoRemoved":
				removal = update
			}
		}
		listed := syncListWriters(t, cred, r.pds1, sp, nil)
		if write == nil || removal == nil || removal["repo"] != dan.did || removal["spaceRev"] != listed.str("cursor") || removal["prevSpaceRev"] != write["spaceRev"] {
			t.Fatalf("removal does not continue the notification chain: write=%v removal=%v listed=%s", write, removal, listed.raw)
		}
	})

	t.Run("resolves a space host through the authority atproto pds entry", func(t *testing.T) {
		// Reference: space catch-up / resolves a space host through the authority's #atproto_pds entry.
		host := syncMockSyncer(r, false)
		resolve := func(service string) (string, bool) {
			return bob.pds.s.resolveServiceEndpoint(context.Background(), service)
		}
		if got, ok := resolve(host.serviceRef()); !ok || got != host.url {
			t.Fatalf("service endpoint %q ok=%v, want %s", got, ok, host.url)
		}
		if got, ok := resolve(space.SpaceHostAud(alice.did)); !ok || got != alice.pds.url {
			t.Fatalf("space host %q ok=%v, want %s", got, ok, alice.pds.url)
		}
		// A legacy dedicated #atproto_space_host service is not preferred.
		doc := r.net.dir.get(alice.did)
		withHost := *doc
		withHost.Service = append(append([]identity.DidDocService{}, doc.Service...), identity.DidDocService{Id: "#atproto_space_host", Type: "AtprotoSpaceHost", ServiceEndpoint: "https://elsewhere.example"})
		r.net.dir.put(&withHost)
		defer r.net.dir.put(doc)
		if got, ok := resolve(space.SpaceHostAud(alice.did)); !ok || got != alice.pds.url {
			t.Fatalf("legacy service displaced #atproto_pds: %q ok=%v", got, ok)
		}
	})

	t.Run("retries the latest state after delivery failure and worker restart", func(t *testing.T) {
		// Reference: space catch-up / retries the latest state after delivery
		// failure and worker restart. Cocoon's worker is stopped and its due
		// retry pass is driven synchronously instead of restarting a TS class.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		func() {
			r.net.dir.down.Store(true)
			defer r.net.dir.down.Store(false)
			mustOK(t, doWrite(bob, sp, writeOpts{}))
			mustOK(t, doWrite(bob, sp, writeOpts{}))
		}()
		if got := syncWriterDids(t, r, sp); len(got) != 0 {
			t.Fatalf("writer reached authority while its directory was down: %v", got)
		}
		state := repoState(t, bob, sp)
		oldLogger := bob.pds.s.logger
		bob.pds.s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		defer func() { bob.pds.s.logger = oldLogger }()
		bob.pds.s.stopSpaceWorkers()
		var retries []models.SpaceNotificationRetry
		if err := bob.pds.s.db.Raw(context.Background(), "SELECT * FROM space_notification_retries WHERE space = ?", nil, sp).Scan(&retries).Error; err != nil {
			t.Fatal(err)
		}
		if len(retries) != 1 || retries[0].Repo != bob.did || retries[0].RepoRev != *state.Rev {
			t.Fatalf("retry does not hold the newest state at %s: %+v", *state.Rev, retries)
		}
		if err := bob.pds.s.db.Exec(context.Background(), "UPDATE space_notification_retries SET retry_at = 0 WHERE space = ?", nil, sp).Error; err != nil {
			t.Fatal(err)
		}
		bob.pds.s.retrySpaceNotifications(context.Background())
		var left []models.SpaceNotificationRetry
		if err := bob.pds.s.db.Raw(context.Background(), "SELECT * FROM space_notification_retries WHERE space = ?", nil, sp).Scan(&left).Error; err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			t.Fatalf("delivered retry remained queued: %+v", left)
		}
		cred := credentialFor(t, bob, r.pds1, sp)
		listed := syncListWriters(t, cred, r.pds1, sp, nil)
		entry := syncWriterEntry(t, listed, bob.did, "com.atproto.space.defs#repoWrite")
		if len(listed.list("repos")) != 1 || entry["repoRev"] != *state.Rev {
			t.Fatalf("retry published the wrong state: %s", listed.raw)
		}
		got, err := syncLexBytes(entry["data"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, syncLtHashDigest(t, state.SetHash)) {
			t.Fatal("retry published the wrong commit data")
		}
		bob.pds.s.retrySpaceNotifications(context.Background())
		again := syncListWriters(t, cred, r.pds1, sp, nil)
		if !reflect.DeepEqual(listed.body, again.body) {
			t.Fatalf("redundant retry changed writer state: before %s after %s", listed.raw, again.raw)
		}
	})
}

func TestSpaceSyncNotifyRepoUpdate(t *testing.T) {
	r := newSyncNet(t)
	alice, bob, carol := r.alice, r.bob, r.carol

	t.Run("ignores duplicate and older revisions without forwarding them", func(t *testing.T) {
		// Reference: notifyRepoUpdate / ignores duplicate and older revisions without forwarding them.
		syncer := syncMockSyncer(r, false)
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		cred, _ := credentialWithNotify(t, alice, r.pds1, sp, &notifyReg{endpoint: syncer.url, token: "duplicates"})
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		older := *repoState(t, bob, sp).Rev
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		current := *repoState(t, bob, sp).Rev
		r.net.waitSpaceJobs()
		before := syncListWriters(t, cred, r.pds1, sp, nil)
		calls := len(syncSpaceUpdates(syncer))
		for _, rev := range []string{older, current} {
			mustOK(t, syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, rev, nil), syncNotifyOpts{}))
		}
		r.net.waitSpaceJobs()
		after := syncListWriters(t, cred, r.pds1, sp, nil)
		if !reflect.DeepEqual(before.body, after.body) {
			t.Fatalf("duplicate/old notification moved writer state: before %s after %s", before.raw, after.raw)
		}
		if got := len(syncSpaceUpdates(syncer)); got != calls {
			t.Fatalf("forwarded updates grew from %d to %d", calls, got)
		}
	})

	t.Run("keeps the newest repo revision when notifications race", func(t *testing.T) {
		// Reference: notifyRepoUpdate / keeps the newest repo revision when notifications race.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		older := syntax.NewTIDNow(0)
		newer := syntax.NewTIDFromInteger(older.Integer() + 1)
		hash := syncEmptyHash()
		start := make(chan struct{})
		responses := make(chan xres, 2)
		for _, update := range []struct {
			rev  string
			data []byte
		}{{newer.String(), hash}, {older.String(), nil}} {
			go func(rev string, data []byte) {
				<-start
				responses <- syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, rev, data), syncNotifyOpts{})
			}(update.rev, update.data)
		}
		close(start)
		for i := 0; i < 2; i++ {
			mustOK(t, <-responses)
		}
		cred := credentialFor(t, bob, r.pds1, sp)
		listed := syncListWriters(t, cred, r.pds1, sp, nil)
		entry := syncWriterEntry(t, listed, bob.did, "com.atproto.space.defs#repoWrite")
		if len(listed.list("repos")) != 1 || entry["repoRev"] != newer.String() {
			t.Fatalf("racing notification regressed the writer revision: %s", listed.raw)
		}
		got, err := syncLexBytes(entry["data"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, hash) {
			t.Fatal("racing notification also regressed commit data")
		}
	})

	t.Run("rejects future revisions while allowing a small clock skew", func(t *testing.T) {
		// Reference: notifyRepoUpdate / rejects future revisions while allowing a small clock skew.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		future := syntax.NewTIDFromTime(time.Now().Add(10*time.Minute), 0).String()
		expectErr(t, syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, future, syncEmptyHash()), syncNotifyOpts{}), 400, "FutureRev")
		if got := syncWriterDids(t, r, sp); len(got) != 0 {
			t.Fatalf("future revision created writers: %v", got)
		}
		skew := syntax.NewTIDFromTime(time.Now().Add(time.Minute), 0).String()
		mustOK(t, syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, skew, syncEmptyHash()), syncNotifyOpts{}))
		if got := syncWriterDids(t, r, sp); !reflect.DeepEqual(got, []string{bob.did}) {
			t.Fatalf("small clock skew was not accepted: %v", got)
		}
	})

	t.Run("rejects one that spoofs the writer", func(t *testing.T) {
		// Reference: notifyRepoUpdate / rejects one that spoofs the writer.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		res := syncNotify(t, r, bob, syncNotifyBody(sp, carol.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), syncNotifyOpts{})
		if res.status != 403 || !strings.Contains(res.message(), "iss does not match the repo") {
			t.Fatalf("want 403 iss mismatch, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects one addressed to another authority", func(t *testing.T) {
		// Reference: notifyRepoUpdate / rejects one addressed to another authority.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{text: "misaddressed"}))
		state := repoState(t, bob, sp)
		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, *state.Rev, syncLtHashDigest(t, state.SetHash)), syncNotifyOpts{aud: carol.did})
		if res.status != 403 || !strings.Contains(res.message(), "aud does not match the space authority") {
			t.Fatalf("want 403 audience mismatch, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects service auth for another lexicon method", func(t *testing.T) {
		// Service-auth counterpart to the iss/aud cases: a token for another
		// method must not authorize notifyRepoUpdate.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), syncNotifyOpts{lxm: "com.atproto.space.notifyCredentialsRevoked"})
		expectErr(t, res, 401, "BadJwtLexiconMethod")
		if got := syncWriterDids(t, r, sp); len(got) != 0 {
			t.Fatalf("wrong-lxm token changed the writer set: %v", got)
		}
	})

	t.Run("rejects one from a non member", func(t *testing.T) {
		// Reference: notifyRepoUpdate / rejects one from a non-member.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		res := syncNotify(t, r, carol, syncNotifyBody(sp, carol.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), syncNotifyOpts{})
		if res.status != 403 || !strings.Contains(res.message(), "not authorized") {
			t.Fatalf("want 403 unauthorized non-member, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects a member without write access", func(t *testing.T) {
		// Reference: notifyRepoUpdate / rejects a member without write access.
		sp := createSpace(t, alice, spaceOpts{})
		putMember(t, alice, sp, bob, true, false)
		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), syncNotifyOpts{})
		if res.status != 403 || !strings.Contains(res.message(), "not authorized") {
			t.Fatalf("want 403 read-only member, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects a member without write access even when writes are public", func(t *testing.T) {
		// Reference: notifyRepoUpdate / rejects a member without write access even when writes are public.
		sp := createSpace(t, alice, spaceOpts{policy: memberPolicy(map[string]any{"publicWrite": true})})
		putMember(t, alice, sp, bob, true, false)
		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), syncNotifyOpts{})
		if res.status != 403 || !strings.Contains(res.message(), "not authorized") {
			t.Fatalf("publicWrite bypassed an explicit read-only member: %d %s", res.status, res.raw)
		}
		mustOK(t, syncNotify(t, r, carol, syncNotifyBody(sp, carol.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), syncNotifyOpts{}))
		if got := syncWriterDids(t, r, sp); !reflect.DeepEqual(got, []string{carol.did}) {
			t.Fatalf("public non-member writer was not admitted: %v", got)
		}
	})

	t.Run("rejects a rev that is not a TID before any auth check", func(t *testing.T) {
		// Reference: notifyRepoUpdate / rejects a rev that is not a TID before any auth check.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, "not-a-tid", syncEmptyHash()), syncNotifyOpts{})
		if res.status != 400 || !strings.Contains(strings.ToLower(res.message()), "tid") {
			t.Fatalf("want 400 invalid TID, got %d %s", res.status, res.raw)
		}
	})
}
