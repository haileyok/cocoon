package server

// Ported from packages/pds/tests/space/sync.test.ts (bluesky-social/atproto
// 5b95b2f2): how a syncing service follows a space. The oplog is the
// incremental path (page forward from a cursor, apply each op to a local set
// hash, check it against the repo's signed commit); listRecords +
// getLatestCommit (or a getRepo CAR) rebuilds from full state when the oplog
// no longer reaches back far enough.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
)

// syncNet is a three-PDS network, as the reference's space_sync suite builds:
// alice (authority) and dan co-located on pds1, bob on pds2, carol on pds3.
type syncNet struct {
	net                    *spaceNet
	pds1, pds2, pds3       *spacePDS
	alice, dan, bob, carol *actor
}

func newSyncNet(t *testing.T) *syncNet {
	t.Helper()
	n := newSpaceNet(t)
	r := &syncNet{net: n, pds1: n.newPDS(), pds2: n.newPDS(), pds3: n.newPDS()}
	r.alice = r.pds1.createActor("alice") // authority
	r.dan = r.pds1.createActor("dan")     // member on the authority's PDS
	r.bob = r.pds2.createActor("bob")     // member on pds2
	r.carol = r.pds3.createActor("carol") // stands in for a syncing service
	return r
}

// syncListRepoOps pages a repo's oplog as a syncer would, returning each
// page, the rkeys in order, the last cursor and the last commit seen.
func syncListRepoOps(t *testing.T, c *spaceCredential, p *spacePDS, sp, repo string, params map[string]string) ([][]string, string, map[string]any) {
	t.Helper()
	if params == nil {
		params = map[string]string{}
	}
	merged := map[string]string{"space": sp, "repo": repo}
	for k, v := range params {
		merged[k] = v
	}
	var rkeys [][]string
	cursor := ""
	var commit map[string]any
	for i := 0; i < 10; i++ {
		if cursor != "" {
			merged["cursor"] = cursor
		} else {
			delete(merged, "cursor")
		}
		page := mustOK(t, c.get(t, p, "com.atproto.space.listRepoOps", merged))
		var pageRkeys []string
		for _, op := range page.list("ops") {
			pageRkeys = append(pageRkeys, op["rkey"].(string))
		}
		rkeys = append(rkeys, pageRkeys)
		cursor = page.str("cursor")
		if cm, ok := page.body["commit"].(map[string]any); ok {
			commit = cm
		}
		if cursor == "" {
			break
		}
	}
	return rkeys, cursor, commit
}

// syncOp is one oplog op in wire form, with its cid/prev decoded.
type syncOp struct {
	rev        string
	collection string
	rkey       string
	cid        *string
	prev       *string
}

// syncWireOps pulls every op of a repo in one page and converts them for
// folding into a local RepoCommit.
func syncWireOps(t *testing.T, c *spaceCredential, p *spacePDS, sp, repo string) []syncOp {
	t.Helper()
	page := mustOK(t, c.get(t, p, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": repo, "limit": "100"}))
	var ops []syncOp
	for _, m := range page.list("ops") {
		op := syncOp{rev: m["rev"].(string), collection: m["collection"].(string), rkey: m["rkey"].(string)}
		if v, ok := m["cid"].(string); ok {
			op.cid = &v
		}
		if v, ok := m["prev"].(string); ok {
			op.prev = &v
		}
		ops = append(ops, op)
	}
	return ops
}

// syncWireOp converts one wire op object into its decoded form.
func syncWireOp(t *testing.T, m map[string]any) syncOp {
	t.Helper()
	op := syncOp{collection: m["collection"].(string), rkey: m["rkey"].(string)}
	if op.rev, _ = m["rev"].(string); true {
	}
	if v, ok := m["cid"].(string); ok {
		op.cid = &v
	}
	if v, ok := m["prev"].(string); ok {
		op.prev = &v
	}
	return op
}

// syncApplyOp folds one wire op into a local repo, as the reference's
// local.applyOp does.
func syncApplyOp(t *testing.T, rc *space.RepoCommit, op syncOp) {
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
	rc.ApplyOp(ro)
}

// syncSignedCommit converts a wire commit object into space.SignedCommit,
// asserting ver == 1 as the reference's asSignedCommit does.
func syncSignedCommit(t *testing.T, m map[string]any) space.SignedCommit {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c space.SignedCommit
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Ver != 1 {
		t.Fatalf("commit ver %d, want 1", c.Ver)
	}
	return c
}

// syncDidKey returns a repo author's did:key, as the reference derives it
// from the actor store's keypair: didDocFor(...)'s multibase key.
func syncDidKey(t *testing.T, n *syncNet, a *actor) string {
	t.Helper()
	doc := n.net.dir.get(a.did)
	if doc == nil || len(doc.VerificationMethods) == 0 {
		t.Fatalf("no did doc for %s", a.did)
	}
	pub, err := atcrypto.ParsePublicMultibase(doc.VerificationMethods[0].PublicKeyMultibase)
	if err != nil {
		t.Fatal(err)
	}
	return pub.DIDKey()
}

// syncFetchRepoCar fetches a getRepo CAR with the credential, as the
// reference's cred.fetch does for a raw download.
func syncFetchRepoCar(t *testing.T, c *spaceCredential, p *spacePDS, params map[string]string) (int, string, []byte) {
	t.Helper()
	v := url.Values{}
	for k, x := range params {
		v.Set(k, x)
	}
	u := p.url + "/xrpc/com.atproto.space.getRepo"
	if len(v) > 0 {
		u += "?" + v.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, hv := range c.headers(t, params["repo"]) {
		req.Header.Set(k, hv)
	}
	resp, err := p.net.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	ct := resp.Header.Get("Content-Type")
	return resp.StatusCode, ct, raw
}

// syncWriterDids reads the writer set as stored by the authority, as the
// reference's sc.writerDids does through storage.
func syncWriterDids(t *testing.T, n *syncNet, sp string) []string {
	t.Helper()
	ref, err := space.ParseRef(sp)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		WriterDid string
	}
	if err := n.pds1.s.db.Raw(context.Background(),
		"SELECT writer_did FROM space_writers WHERE did = ? AND space = ? ORDER BY space_rev ASC", nil, ref.Authority, sp).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.WriterDid)
	}
	return out
}

// syncNotify sends a notifyWrite as signer's PDS would: service auth from the
// signer's own repo key, addressed to the space host by default.
func syncNotify(t *testing.T, n *syncNet, signer *actor, body map[string]any, aud string) xres {
	t.Helper()
	if aud == "" {
		aud = space.SpaceHostAud(n.alice.did)
	}
	tok, err := mintServiceAuth(signer.key, signer.did, aud, "com.atproto.space.notifyWrite", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return n.pds1.post("com.atproto.space.notifyWrite", body, map[string]string{"Authorization": "Bearer " + tok})
}

// syncNotifyBody builds a notifyWrite body. hash may be nil for a 32-byte
// zero hash, as the reference's new Uint8Array(32).
func syncNotifyBody(sp, repo, repoRev string, hash []byte) map[string]any {
	if hash == nil {
		hash = make([]byte, 32)
	}
	return map[string]any{"space": sp, "repo": repo, "repoRev": repoRev, "hash": space.LexBytes(hash)}
}

// syncLtHashDigest is the hash a repo's set hash digests to, as listRepos
// publishes it.
func syncLtHashDigest(t *testing.T, setHash []byte) []byte {
	t.Helper()
	h, err := space.LtHashFromState(setHash)
	if err != nil {
		t.Fatal(err)
	}
	d := h.Digest()
	return d[:]
}

// syncRegisterNotify registers a mock service for a space with the authority.
func syncRegisterNotify(t *testing.T, c *spaceCredential, p *spacePDS, sp, serviceRef string) {
	t.Helper()
	mustOK(t, c.post(t, p, "com.atproto.space.registerNotify", map[string]any{"space": sp, "service": serviceRef}))
}

// syncListRepos pages listRepos once with the given params.
func syncListRepos(t *testing.T, c *spaceCredential, p *spacePDS, sp string, params map[string]string) xres {
	t.Helper()
	merged := map[string]string{"space": sp}
	for k, v := range params {
		merged[k] = v
	}
	return mustOK(t, c.get(t, p, "com.atproto.space.listRepos", merged))
}

func TestSpaceSyncOplogPaging(t *testing.T) {
	r := newSyncNet(t)
	alice, dan := r.alice, r.dan

	t.Run("pages through a single rev without dropping ops", func(t *testing.T) {
		// One batch is one rev, so a page boundary can land inside it. The
		// cursor carries (rev, idx), so resuming picks up mid-rev rather than
		// re-reading or skipping the rest of it.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		var writes []any
		for i := 0; i < 5; i++ {
			writes = append(writes, map[string]any{
				"$type":      "com.atproto.space.applyWrites#create",
				"collection": testCollection,
				"rkey":       fmt.Sprintf("atomic-%d", i),
				"value":      testRecord(testCollection, fmt.Sprintf("atomic %d", i)),
			})
		}
		mustOK(t, dan.post("com.atproto.space.applyWrites", map[string]any{"space": sp, "repo": dan.did, "writes": writes}))

		cred := credentialFor(t, dan, r.pds1, sp)
		pages, _, _ := syncListRepoOps(t, cred, r.pds1, sp, dan.did, map[string]string{"limit": "2"})
		var rkeys []string
		for _, pg := range pages {
			rkeys = append(rkeys, pg...)
		}
		want := []string{"atomic-0", "atomic-1", "atomic-2", "atomic-3", "atomic-4"}
		if strings.Join(rkeys, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", rkeys, want)
		}
	})

	t.Run("withholds the commit until the oplog is drained to head", func(t *testing.T) {
		// The commit is the syncer's checkpoint, so handing it out mid-backfill
		// would let it believe it had caught up.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		for i := 0; i < 3; i++ {
			mustOK(t, doWrite(dan, sp, writeOpts{rkey: fmt.Sprintf("paged-%d", i)}))
		}

		cred := credentialFor(t, dan, r.pds1, sp)
		first := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "1"}))
		if _, ok := first.body["commit"]; ok {
			t.Fatalf("first page carried a commit: %s", first.raw)
		}
		cursor := first.str("cursor")
		if cursor == "" {
			t.Fatalf("first page had no cursor: %s", first.raw)
		}

		var seen []string
		if ops := first.list("ops"); len(ops) > 0 {
			seen = append(seen, ops[0]["rev"].(string))
		}
		var commit map[string]any
		for i := 0; i < 5 && cursor != ""; i++ {
			next := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "cursor": cursor, "limit": "1"}))
			if ops := next.list("ops"); len(ops) > 0 {
				seen = append(seen, ops[0]["rev"].(string))
			}
			cursor = next.str("cursor")
			if cm, ok := next.body["commit"].(map[string]any); ok {
				commit = cm
			}
		}
		// Each page advances: paging on a cursor that was ignored would repeat
		// a rev.
		dedup := map[string]bool{}
		for _, rev := range seen {
			if dedup[rev] {
				t.Fatalf("rev %s repeated across pages: %v", rev, seen)
			}
			dedup[rev] = true
		}
		if commit == nil {
			t.Fatal("drained the oplog without ever seeing a commit")
		}
	})

	t.Run("pages with since and cursor together", func(t *testing.T) {
		// A syncer holds `since` at its own last-synced position and passes
		// back each `cursor`, so the two have to compose rather than one
		// overriding the other.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		for i := 0; i < 4; i++ {
			mustOK(t, doWrite(dan, sp, writeOpts{rkey: fmt.Sprintf("prec-%d", i)}))
		}

		cred := credentialFor(t, dan, r.pds1, sp)
		all := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		if len(all.list("ops")) != 4 {
			t.Fatalf("%s", all.raw)
		}

		// Synced through op 0; page the rest one at a time, holding `since`
		// steady.
		since := all.list("ops")[0]["rev"].(string)
		pages, _, _ := syncListRepoOps(t, cred, r.pds1, sp, dan.did, map[string]string{"since": since, "limit": "1"})
		var rkeys []string
		for _, pg := range pages {
			rkeys = append(rkeys, pg...)
		}
		want := []string{"prec-1", "prec-2", "prec-3"}
		if strings.Join(rkeys, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", rkeys, want)
		}
	})

	t.Run("inlines only a record current value", func(t *testing.T) {
		// The oplog join matches on cid as well as uri, so an op a later one
		// superseded inlines nothing rather than serving a stale value.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "inlined", text: "first"}))
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "inlined", text: "second"}))

		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		ops := res.list("ops")
		if len(ops) != 2 {
			t.Fatalf("%s", res.raw)
		}
		if _, ok := ops[0]["value"]; ok {
			t.Fatalf("superseded op inlined a value: %v", ops[0])
		}
		v, _ := ops[1]["value"].(map[string]any)
		if v == nil || v["text"] != "second" {
			t.Fatalf("current op did not inline its value: %v", ops[1])
		}
	})

	t.Run("omits values entirely with excludeValues", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "no-value", text: "body"}))

		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "excludeValues": "true"}))
		ops := res.list("ops")
		if len(ops) != 1 {
			t.Fatalf("%s", res.raw)
		}
		if _, ok := ops[0]["value"]; ok {
			t.Fatalf("excludeValues still inlined a value: %v", ops[0])
		}
		// The op still names the record, so a syncer can fetch what it needs.
		if ops[0]["rkey"] != "no-value" {
			t.Fatalf("%v", ops[0])
		}
	})

	t.Run("rejects a malformed cursor", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "cursor-check"}))
		cred := credentialFor(t, dan, r.pds1, sp)

		expectErr(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "cursor": "not-a-cursor"}), 400, "MalformedCursor")
	})
}

func TestSpaceSyncIncrementalCatchUp(t *testing.T) {
	r := newSyncNet(t)
	alice, dan, bob := r.alice, r.dan, r.bob

	t.Run("replays the oplog to the repo signed commit", func(t *testing.T) {
		// The whole point of the oplog: a syncer that applies every op ends up
		// with a set hash matching what the author signed.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "one", text: "one"}))
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "two", text: "two"}))
		mustOK(t, doPut(dan, sp, writeOpts{rkey: "two", text: "two revised"}))
		mustOK(t, doDel(dan, sp, "", "one"))

		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		commit, ok := res.body["commit"].(map[string]any)
		if !ok {
			t.Fatalf("no commit: %s", res.raw)
		}

		local := space.NewRepoCommit()
		for _, m := range res.list("ops") {
			op := syncOp{collection: m["collection"].(string), rkey: m["rkey"].(string)}
			if v, ok := m["cid"].(string); ok {
				op.cid = &v
			}
			if v, ok := m["prev"].(string); ok {
				op.prev = &v
			}
			syncApplyOp(t, local, op)
		}
		if !local.Matches(syncSignedCommit(t, commit)) {
			t.Fatal("replayed oplog does not match the signed commit")
		}
	})

	t.Run("detects divergence when an op is missed", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "kept", text: "kept"}))
		mustOK(t, doWrite(dan, sp, writeOpts{rkey: "missed", text: "missed"}))

		cred := credentialFor(t, dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": dan.did, "limit": "100"}))
		commit, ok := res.body["commit"].(map[string]any)
		if !ok {
			t.Fatalf("no commit: %s", res.raw)
		}

		// Apply all but the last: the mismatch is what tells a syncer to
		// recover.
		ops := res.list("ops")
		local := space.NewRepoCommit()
		for _, m := range ops[:len(ops)-1] {
			op := syncOp{collection: m["collection"].(string), rkey: m["rkey"].(string)}
			if v, ok := m["cid"].(string); ok {
				op.cid = &v
			}
			if v, ok := m["prev"].(string); ok {
				op.prev = &v
			}
			syncApplyOp(t, local, op)
		}
		if local.Matches(syncSignedCommit(t, commit)) {
			t.Fatal("missed op still matched the commit")
		}
	})

	// Known gap in the reference too: nothing prunes the oplog on its own yet
	// (no retention window, no compaction), so the recovery path below is
	// tested by forcing a prune by hand.
	t.Run("prunes the oplog on its own, past a retention window", func(t *testing.T) {
		t.Skip("reference it.todo: nothing prunes the oplog on its own yet")
	})

	t.Run("recovers from a pruned oplog via listRecords", func(t *testing.T) {
		// When the oplog no longer reaches back to a consumer's cursor, an
		// incremental pull yields an incomplete diff — detectable as a setHash
		// mismatch. Recovery is listRecords + getLatestCommit; no new endpoint.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})

		for _, text := range []string{"pre 1", "pre 2", "pre 3"} {
			mustOK(t, doWrite(bob, sp, writeOpts{text: text}))
		}
		consumerSince := repoState(t, bob, sp).Rev

		mustOK(t, doWrite(bob, sp, writeOpts{text: "post 1"}))
		mustOK(t, doWrite(bob, sp, writeOpts{text: "post 2"}))

		// Simulate retention by dropping oplog rows at or below the cursor. No
		// endpoint prunes, so this reaches into storage deliberately.
		if err := bob.pds.s.db.Exec(context.Background(),
			"DELETE FROM space_record_oplogs WHERE space = ? AND rev <= ?", nil, sp, *consumerSince).Error; err != nil {
			t.Fatal(err)
		}

		cred := credentialFor(t, bob, r.pds1, sp)
		incremental := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": bob.did, "since": *consumerSince, "limit": "100"}))
		if len(incremental.list("ops")) != 2 {
			t.Fatalf("%s", incremental.raw)
		}

		applied := space.NewRepoCommit()
		for _, m := range incremental.list("ops") {
			op := syncOp{collection: m["collection"].(string), rkey: m["rkey"].(string)}
			if v, ok := m["cid"].(string); ok {
				op.cid = &v
			}
			if v, ok := m["prev"].(string); ok {
				op.prev = &v
			}
			syncApplyOp(t, applied, op)
		}
		commit, ok := incremental.body["commit"].(map[string]any)
		if !ok {
			t.Fatalf("no commit: %s", incremental.raw)
		}
		if applied.Matches(syncSignedCommit(t, commit)) {
			t.Fatal("incremental diff matched the commit despite the pruned oplog")
		}

		// Recovery: page listRecords across all collections, recompute, compare.
		type rec struct{ collection, rkey, cidStr string }
		var recovered []rec
		cursor := ""
		for page := 0; page < 10; page++ {
			params := map[string]string{"space": sp, "repo": bob.did, "limit": "2"}
			if cursor != "" {
				params["cursor"] = cursor
			}
			res := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRecords", params))
			for _, m := range res.list("records") {
				recovered = append(recovered, rec{m["collection"].(string), m["rkey"].(string), m["cid"].(string)})
			}
			cursor = res.str("cursor")
			if cursor == "" {
				break
			}
		}
		if len(recovered) != 5 {
			t.Fatalf("recovered %d records, want 5: %v", len(recovered), recovered)
		}

		refs := make([]space.RecordRef, 0, len(recovered))
		for _, rc := range recovered {
			refs = append(refs, space.RecordRef{Collection: rc.collection, Rkey: rc.rkey, Cid: mustCid(t, rc.cidStr)})
		}
		latest := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": bob.did}))
		latestCommit, ok := latest.body["commit"].(map[string]any)
		if !ok {
			t.Fatalf("no commit: %s", latest.raw)
		}
		if !space.RepoCommitFromRecords(refs).Matches(syncSignedCommit(t, latestCommit)) {
			t.Fatal("rebuild from listRecords does not match the latest commit")
		}
	})
}

func TestSpaceSyncGetRepo(t *testing.T) {
	r := newSyncNet(t)
	alice, bob, carol := r.alice, r.bob, r.carol

	t.Run("serves a verifiable CAR for full-state recovery", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		for _, collection := range []string{testCollection, testCollectionAlt} {
			for i := 0; i < 2; i++ {
				mustOK(t, doWrite(bob, sp, writeOpts{collection: collection, rkey: fmt.Sprintf("car-%d", i), text: fmt.Sprintf("car %d", i)}))
			}
		}

		// Carol syncs bob's repo in full, as a syncing service would.
		cred := credentialFor(t, carol, r.pds1, sp)
		status, ct, car := syncFetchRepoCar(t, cred, r.pds2, map[string]string{"space": sp, "repo": bob.did})
		if status != 200 {
			t.Fatalf("status %d: %s", status, car)
		}
		if !strings.Contains(ct, "application/vnd.ipld.car") {
			t.Fatalf("content-type %s", ct)
		}

		didKey := syncDidKey(t, r, bob)
		state := repoState(t, bob, sp)
		recovered, err := space.VerifyRepoCarFull(strings.NewReader(string(car)), space.VerifyRepoParams{Space: sp, Author: bob.did, DidKey: didKey})
		if err != nil {
			t.Fatal(err)
		}

		if len(recovered.Records) != 4 {
			t.Fatalf("recovered %d records, want 4", len(recovered.Records))
		}
		if !recovered.Repo.Matches(recovered.Commit) {
			t.Fatal("recovered repo does not match its commit")
		}
		if recovered.Commit.Rev != *state.Rev {
			t.Fatalf("commit rev %s, want %s", recovered.Commit.Rev, *state.Rev)
		}
		stored, err := space.RepoCommitFromState(state.SetHash)
		if err != nil {
			t.Fatal(err)
		}
		if !recovered.Repo.SetHash.Equal(stored.SetHash) {
			t.Fatal("recovered set hash diverged from the stored set hash")
		}

		var texts []string
		for _, rec := range recovered.Records {
			if rec.Collection == testCollection {
				if text, _ := rec.Record["text"].(string); text != "" {
					texts = append(texts, text)
				}
			}
		}
		sort.Strings(texts)
		if strings.Join(texts, ",") != "car 0,car 1" {
			t.Fatalf("texts %v", texts)
		}
	})

	t.Run("serves an index-only CAR with excludeValues", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		for i := 0; i < 2; i++ {
			mustOK(t, doWrite(bob, sp, writeOpts{rkey: fmt.Sprintf("idx-%d", i), text: fmt.Sprintf("idx %d", i)}))
		}

		cred := credentialFor(t, carol, r.pds1, sp)
		status, _, car := syncFetchRepoCar(t, cred, r.pds2, map[string]string{"space": sp, "repo": bob.did, "excludeValues": "true"})
		if status != 200 {
			t.Fatalf("status %d: %s", status, car)
		}

		// The set hash folds from the index alone, so it still matches the
		// commit with no record blocks present — which is what makes an
		// index-only sync verifiable.
		didKey := syncDidKey(t, r, bob)
		recovered, err := space.VerifyRepoCarFull(strings.NewReader(string(car)), space.VerifyRepoParams{Space: sp, Author: bob.did, DidKey: didKey, IndexOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(recovered.Records) != 0 {
			t.Fatalf("index-only CAR carried %d record blocks", len(recovered.Records))
		}
		if len(recovered.Index) != 2 {
			t.Fatalf("index has %d entries, want 2", len(recovered.Index))
		}
		if !recovered.Repo.Matches(recovered.Commit) {
			t.Fatal("index-only repo does not match its commit")
		}
	})

	t.Run("refuses a CAR without a credential for that space", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "car-auth", members: []*actor{bob}})
		other := createSpace(t, alice, spaceOpts{skey: "car-auth-other", members: []*actor{carol}})

		wrongCred := credentialFor(t, carol, r.pds1, other)
		status, _, _ := syncFetchRepoCar(t, wrongCred, r.pds2, map[string]string{"space": sp, "repo": bob.did})
		if status < 400 {
			t.Fatalf("wrong-space credential accepted: %d", status)
		}
	})

	t.Run("reports RepoNotFound for an unwritten repo", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{carol}})
		cred := credentialFor(t, carol, r.pds1, sp)
		expectErr(t, cred.get(t, r.pds1, "com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": alice.did}), 400, "RepoNotFound")
	})
}

func TestSpaceSyncWriterSet(t *testing.T) {
	r := newSyncNet(t)
	alice, dan, bob, _ := r.alice, r.dan, r.bob, r.carol

	t.Run("records a co-located writer without resolving its public PDS endpoint", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{writePolicy: publicPolicy()})

		// The reference mocks the DID resolver to fail; taking the directory
		// down has the same effect: no DID document can be resolved at all
		// during the write.
		r.net.dir.down.Store(true)
		mustOK(t, doWrite(dan, sp, writeOpts{text: "same PDS"}))
		r.net.dir.down.Store(false)

		if got := syncWriterDids(t, r, sp); len(got) != 1 || got[0] != dan.did {
			t.Fatalf("writer set %v, want [%s]", got, dan.did)
		}
	})

	t.Run("records a writer from notifyWrite, and it is not the member list", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})

		// Bob writes on pds2; his PDS delivers notifyWrite at the authority,
		// which records him in the writer set.
		mustOK(t, doWrite(bob, sp, writeOpts{text: "writer set entry"}))

		cred := credentialFor(t, bob, r.pds1, sp)
		var repos []map[string]any
		if !awaitCond(t, func() bool {
			res := syncListRepos(t, cred, r.pds1, sp, nil)
			repos = res.list("repos")
			for _, rp := range repos {
				if rp["did"] == bob.did {
					return true
				}
			}
			return false
		}) {
			t.Fatal("bob never reached the writer set")
		}
		var dids []string
		for _, rp := range repos {
			dids = append(dids, rp["did"].(string))
		}
		if !containsStr(dids, bob.did) {
			t.Fatalf("writer set %v misses bob", dids)
		}
		// Alice is a member who hasn't written, so she is absent: the writer
		// set is the sync boundary, not the membership list.
		if containsStr(dids, alice.did) {
			t.Fatalf("writer set %v carries non-writer alice", dids)
		}

		// And it carries where each writer is up to, so a syncer knows what to
		// pull.
		var entry map[string]any
		for _, rp := range repos {
			if rp["did"] == bob.did {
				entry = rp
			}
		}
		state := repoState(t, bob, sp)
		if entry["repoRev"] != *state.Rev {
			t.Fatalf("repoRev %v, want %s", entry["repoRev"], *state.Rev)
		}
		want := syncLtHashDigest(t, state.SetHash)
		got, err := lexBytesOf(entry["hash"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytesEqual(got, want) {
			t.Fatalf("hash %v, want %v", entry["hash"], want)
		}
	})

	t.Run("records a writer admitted by public write policy, who was never a member", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{writePolicy: publicPolicy()})
		mustOK(t, doWrite(bob, sp, writeOpts{text: "from a non-member"}))

		if !awaitCond(t, func() bool {
			return containsStr(syncWriterDids(t, r, sp), bob.did)
		}) {
			t.Fatal("bob never reached the writer set")
		}

		cred := credentialFor(t, alice, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRepos", map[string]string{"space": sp}))
		var dids []string
		for _, rp := range res.list("repos") {
			dids = append(dids, rp["did"].(string))
		}
		if len(dids) != 1 || dids[0] != bob.did {
			t.Fatalf("published writer set %v, want [%s]", dids, bob.did)
		}
	})

	t.Run("records a writer into an allowList space, whose PDS presents no attestation", func(t *testing.T) {
		// notifyWrite comes from the writer's PDS, not an app, so there is no
		// client attestation to present. Applying the app perimeter here would
		// reject every write into an app-gated space.
		sp := createSpace(t, alice, spaceOpts{
			members:   []*actor{bob},
			appAccess: allowList("https://app.example.com/client-metadata.json"),
		})
		mustOK(t, doWrite(bob, sp, writeOpts{text: "app-gated space"}))

		if !awaitCond(t, func() bool {
			return containsStr(syncWriterDids(t, r, sp), bob.did)
		}) {
			t.Fatal("bob never reached the writer set")
		}
		if !containsStr(syncWriterDids(t, r, sp), bob.did) {
			t.Fatal("bob missing from the writer set")
		}
	})

	// The reference's "migrates existing writer state" case is a SQLite
	// migration test (packages/pds/src/actor-store/db migrations 003->latest
	// on a hand-built space_writer table). Cocoon uses GORM AutoMigrate from
	// struct models, so there is no equivalent migration to exercise: N/A.
}

func TestSpaceSyncCatchUp(t *testing.T) {
	r := newSyncNet(t)
	alice, bob, dan, carol := r.alice, r.bob, r.dan, r.carol

	t.Run("recovers missed notifications with a space checkpoint", func(t *testing.T) {
		syncer := r.net.newMockService("atproto_space_syncer", func(*http.Request, mockCall) (int, any) {
			return 503, map[string]any{}
		})
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, dan, carol}})
		cred := credentialFor(t, carol, r.pds1, sp)
		syncRegisterNotify(t, cred, r.pds1, sp, syncer.serviceRef())
		empty := syncListRepos(t, cred, r.pds1, sp, nil)
		if len(empty.list("repos")) != 0 {
			t.Fatalf("%s", empty.raw)
		}

		mustOK(t, doWrite(bob, sp, writeOpts{}))
		initial := syncListRepos(t, cred, r.pds1, sp, nil)
		cursor := initial.str("cursor")
		repos := initial.list("repos")
		if cursor == "" || cursor != repos[len(repos)-1]["spaceRev"] {
			t.Fatalf("cursor %q vs last spaceRev %v", cursor, repos[len(repos)-1])
		}
		mustOK(t, doWrite(dan, sp, writeOpts{}))
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		r.net.waitSpaceJobs()

		first := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": cursor, "limit": "1"})
		if dids := listRepoDids(first); len(dids) != 1 || dids[0] != dan.did {
			t.Fatalf("first page dids %v, want [%s]", dids, dan.did)
		}

		// A repo already returned can move forward while the caller paginates.
		mustOK(t, doWrite(dan, sp, writeOpts{}))
		second := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": first.str("cursor"), "limit": "1"})
		if dids := listRepoDids(second); len(dids) != 1 || dids[0] != bob.did {
			t.Fatalf("second page dids %v, want [%s]", dids, bob.did)
		}
		last := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": second.str("cursor"), "limit": "1"})
		if dids := listRepoDids(last); len(dids) != 1 || dids[0] != dan.did {
			t.Fatalf("last page dids %v, want [%s]", dids, dan.did)
		}
		nextCursor := last.str("cursor")
		if nextCursor == "" || nextCursor != last.list("repos")[0]["spaceRev"] {
			t.Fatalf("nextCursor %q vs %v", nextCursor, last.list("repos")[0])
		}
		caughtUp := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": nextCursor})
		if len(caughtUp.list("repos")) != 0 {
			t.Fatalf("not caught up: %s", caughtUp.raw)
		}
		if caughtUp.str("cursor") != "" {
			t.Fatalf("caught-up page carried a cursor: %s", caughtUp.raw)
		}
	})

	t.Run("resumes after an empty page using the last processed repo revision", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		cred := credentialFor(t, alice, r.pds1, sp)
		initial := syncListRepos(t, cred, r.pds1, sp, nil)
		cursor := initial.str("cursor")
		empty := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": cursor})
		if len(empty.list("repos")) != 0 {
			t.Fatalf("%s", empty.raw)
		}
		if empty.str("cursor") != "" {
			t.Fatalf("empty page carried a cursor: %s", empty.raw)
		}
		if empty.str("cursor") != "" {
			cursor = empty.str("cursor")
		}

		mustOK(t, doWrite(bob, sp, writeOpts{}))
		catchUp := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": cursor})
		if dids := listRepoDids(catchUp); len(dids) != 1 || dids[0] != bob.did {
			t.Fatalf("catch-up dids %v, want [%s]", dids, bob.did)
		}
		if got := catchUp.list("repos")[0]["spaceRev"].(string); got <= cursor {
			t.Fatalf("spaceRev %s did not advance past cursor %s", got, cursor)
		}
	})

	t.Run("accepts arbitrary string listRepos cursors", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		mustOK(t, doWrite(alice, sp, writeOpts{}))
		cred := credentialFor(t, alice, r.pds1, sp)
		before := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": "0"})
		if dids := listRepoDids(before); len(dids) != 1 || dids[0] != alice.did {
			t.Fatalf("dids %v, want [%s]", dids, alice.did)
		}
		after := syncListRepos(t, cred, r.pds1, sp, map[string]string{"cursor": "not-a-tid"})
		if len(after.list("repos")) != 0 {
			t.Fatalf("%s", after.raw)
		}
		if after.str("cursor") != "" {
			t.Fatalf("page carried a cursor: %s", after.raw)
		}
	})

	t.Run("chains forwarded notifications across local and remote writers", func(t *testing.T) {
		syncer := r.net.newMockService("atproto_space_syncer", nil)
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, dan, carol}})
		cred := credentialFor(t, carol, r.pds1, sp)
		syncRegisterNotify(t, cred, r.pds1, sp, syncer.serviceRef())
		mustOK(t, doWrite(alice, sp, writeOpts{}))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); mustOK(t, doWrite(bob, sp, writeOpts{})) }()
		go func() { defer wg.Done(); mustOK(t, doWrite(dan, sp, writeOpts{})) }()
		wg.Wait()
		r.net.waitSpaceJobs()

		calls := syncer.callsTo("com.atproto.space.notifyWrite")
		if len(calls) != 3 {
			t.Fatalf("got %d notifyWrite calls, want 3", len(calls))
		}
		type note struct{ spaceRev, prevSpaceRev string }
		var notes []note
		for _, c := range calls {
			sr, _ := c.body["spaceRev"].(string)
			psr, _ := c.body["prevSpaceRev"].(string)
			notes = append(notes, note{sr, psr})
		}
		sort.Slice(notes, func(i, j int) bool { return notes[i].spaceRev < notes[j].spaceRev })
		if notes[0].prevSpaceRev != "" {
			t.Fatalf("first notification carried prevSpaceRev %q", notes[0].prevSpaceRev)
		}
		if notes[1].prevSpaceRev != notes[0].spaceRev || notes[2].prevSpaceRev != notes[1].spaceRev {
			t.Fatalf("notifications do not chain: %+v", notes)
		}
		listed := syncListRepos(t, cred, r.pds1, sp, nil)
		repos := listed.list("repos")
		if got := repos[len(repos)-1]["spaceRev"].(string); got != notes[2].spaceRev {
			t.Fatalf("last spaceRev %s, want %s", got, notes[2].spaceRev)
		}
		revs := map[string]bool{}
		for _, rp := range repos {
			revs[rp["spaceRev"].(string)] = true
		}
		if len(revs) != 3 {
			t.Fatalf("distinct spaceRevs %d, want 3: %s", len(revs), listed.raw)
		}
	})

	t.Run("resolves a dedicated space host and falls back only when it is absent", func(t *testing.T) {
		host := r.net.newMockService("atproto_space_host", nil)
		s := bob.pds.s
		resolve := func(service string) (string, bool) {
			return s.resolveServiceEndpoint(context.Background(), service)
		}
		if got, ok := resolve(host.serviceRef()); !ok || got != host.url {
			t.Fatalf("dedicated host resolved %q ok=%v, want %s", got, ok, host.url)
		}
		if got, ok := resolve(space.SpaceHostAud(alice.did)); !ok || got != alice.pds.url {
			t.Fatalf("fallback resolved %q ok=%v, want %s", got, ok, alice.pds.url)
		}
		// Publish an invalid dedicated space host: only then does resolution
		// give up, as the reference's mocked did doc shows.
		doc := r.net.dir.get(alice.did)
		withHost := *doc
		withHost.Service = append(append([]identity.DidDocService{}, doc.Service...), identity.DidDocService{
			Id: "#atproto_space_host", Type: "AtprotoSpaceHost", ServiceEndpoint: "invalid",
		})
		r.net.dir.put(&withHost)
		defer r.net.dir.put(doc)
		if _, ok := resolve(space.SpaceHostAud(alice.did)); ok {
			t.Fatal("resolved a dedicated space host that is invalid")
		}
	})

	t.Run("retries the latest state after delivery failure and worker restart", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		func() {
			r.net.dir.down.Store(true)
			defer r.net.dir.down.Store(false)
			mustOK(t, doWrite(bob, sp, writeOpts{}))
			mustOK(t, doWrite(bob, sp, writeOpts{}))
		}()
		if got := syncWriterDids(t, r, sp); len(got) != 0 {
			t.Fatalf("writer set %v, want empty (directory was down)", got)
		}
		state := repoState(t, bob, sp)
		// Silence the worker's logs for the hand-driven pass below (errors
		// from delivery are expected while it is exercised).
		bob.pds.s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		// Stop the running worker, as the reference's destroy() does, so the
		// hand-driven pass below is the only mover.
		bob.pds.s.stopSpaceWorkers()

		// A retry is queued holding the newest state. (The last write wins:
		// the retry row keeps the repo's latest rev.)
		var retries []models.SpaceNotificationRetry
		if err := bob.pds.s.db.Raw(context.Background(), "SELECT * FROM space_notification_retries WHERE space = ?", nil, sp).Scan(&retries).Error; err != nil {
			t.Fatal(err)
		}
		if len(retries) != 1 || retries[0].Repo != bob.did || retries[0].Space != sp || retries[0].RepoRev != *state.Rev {
			t.Fatalf("retries %+v, want one for %s/%s at %s", retries, bob.did, sp, *state.Rev)
		}

		// Restart, as the reference's destroy + new SpaceNotifications does:
		// stop the running worker first, then clear the timers and run one
		// pass synchronously.
		if err := bob.pds.s.db.Exec(context.Background(), "UPDATE space_notification_retries SET retry_at = 0 WHERE space = ?", nil, sp).Error; err != nil {
			t.Fatal(err)
		}
		bob.pds.s.retrySpaceNotifications(context.Background())

		// A fresh slice: Scan leaves a reused one as it was when no rows match.
		var left []models.SpaceNotificationRetry
		if err := bob.pds.s.db.Raw(context.Background(), "SELECT * FROM space_notification_retries WHERE space = ?", nil, sp).Scan(&left).Error; err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			t.Fatalf("retry rows survived the pass: %+v", left)
		}
		cred := credentialFor(t, bob, r.pds1, sp)
		var listed xres
		if !awaitCond(t, func() bool {
			listed = syncListRepos(t, cred, r.pds1, sp, nil)
			return len(listed.list("repos")) == 1
		}) {
			t.Fatalf("writer set never filled: %s", listed.raw)
		}
		repos := listed.list("repos")
		if repos[0]["repoRev"] != *state.Rev {
			t.Fatalf("repoRev %v, want %s", repos[0]["repoRev"], *state.Rev)
		}
		want := syncLtHashDigest(t, state.SetHash)
		got, err := lexBytesOf(repos[0]["hash"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytesEqual(got, want) {
			t.Fatalf("hash %v, want %v", repos[0]["hash"], want)
		}
		// The retry is gone, so another pass is a no-op. The worker is stopped,
		// so the pass runs without contending for it.
		bob.pds.s.retrySpaceNotifications(context.Background())
		again := syncListRepos(t, cred, r.pds1, sp, nil)
		if len(again.list("repos")) != 1 || again.list("repos")[0]["repoRev"] != *state.Rev {
			t.Fatalf("state changed after a redundant pass: %s", again.raw)
		}
	})
}

func TestSpaceSyncNotifyWrite(t *testing.T) {
	r := newSyncNet(t)
	alice, bob, carol := r.alice, r.bob, r.carol

	t.Run("ignores duplicate and older revisions without forwarding them", func(t *testing.T) {
		syncer := r.net.newMockService("atproto_space_syncer", nil)
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		cred := credentialFor(t, alice, r.pds1, sp)
		syncRegisterNotify(t, cred, r.pds1, sp, syncer.serviceRef())
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		older := repoState(t, bob, sp).Rev
		mustOK(t, doWrite(bob, sp, writeOpts{}))
		r.net.waitSpaceJobs()
		before := syncListRepos(t, cred, r.pds1, sp, nil)
		calls := len(syncer.callsTo("com.atproto.space.notifyWrite"))

		for _, repoRev := range []*string{older, syncStrPtr(before.list("repos")[0]["repoRev"].(string))} {
			mustOK(t, syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, *repoRev, nil), ""))
		}
		r.net.waitSpaceJobs()

		after := syncListRepos(t, cred, r.pds1, sp, nil)
		if !sameJSON(t, before.raw, after.raw) {
			t.Fatalf("writer set moved: before %s after %s", before.raw, after.raw)
		}
		if got := len(syncer.callsTo("com.atproto.space.notifyWrite")); got != calls {
			t.Fatalf("notifyWrite calls grew from %d to %d", calls, got)
		}
	})

	t.Run("keeps the newest repo revision when notifications race", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		older := syntax.NewTIDNow(0)
		newer := syntax.NewTIDFromInteger(older.Integer() + 1)
		hash := space.NewLtHash().Digest()
		h := hash[:]

		start := make(chan struct{})
		responses := make(chan xres, 2)
		go func() {
			<-start
			responses <- syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, newer.String(), h), "")
		}()
		go func() {
			<-start
			responses <- syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, older.String(), nil), "")
		}()
		close(start)
		first, second := <-responses, <-responses
		mustOK(t, first)
		mustOK(t, second)

		cred := credentialFor(t, bob, r.pds1, sp)
		listed := syncListRepos(t, cred, r.pds1, sp, nil)
		repos := listed.list("repos")
		if len(repos) != 1 {
			t.Fatalf("%s", listed.raw)
		}
		if repos[0]["repoRev"] != newer.String() {
			t.Fatalf("repoRev %v, want %s", repos[0]["repoRev"], newer)
		}
		got, err := lexBytesOf(repos[0]["hash"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytesEqual(got, h) {
			t.Fatalf("hash %v, want %v", repos[0]["hash"], h)
		}
	})

	t.Run("sequences concurrent notifications from different writers", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		syncer := r.net.newMockService("atproto_space_syncer", nil)
		cred := credentialFor(t, alice, r.pds1, sp)
		syncRegisterNotify(t, cred, r.pds1, sp, syncer.serviceRef())
		rev := syntax.NewTIDNow(0).String()
		start := make(chan struct{})
		responses := make(chan xres, 2)
		for _, writer := range []*actor{bob, carol} {
			go func() {
				<-start
				responses <- syncNotify(t, r, writer, syncNotifyBody(sp, writer.did, rev, nil), "")
			}()
		}
		close(start)
		first, second := <-responses, <-responses
		mustOK(t, first)
		mustOK(t, second)
		r.net.waitSpaceJobs()
		repos := syncListRepos(t, cred, r.pds1, sp, nil).list("repos")
		if len(repos) != 2 || repos[0]["did"] == repos[1]["did"] || repos[0]["repoRev"] != rev || repos[1]["repoRev"] != rev {
			t.Fatalf("expected both writers at %s: %+v", rev, repos)
		}
		calls := syncer.callsTo("com.atproto.space.notifyWrite")
		if len(calls) != 2 {
			t.Fatalf("got %d notifications, want 2", len(calls))
		}
		sort.Slice(calls, func(i, j int) bool { return calls[i].body["spaceRev"].(string) < calls[j].body["spaceRev"].(string) })
		if prev, _ := calls[0].body["prevSpaceRev"].(string); prev != "" || calls[1].body["prevSpaceRev"] != calls[0].body["spaceRev"] {
			t.Fatal("notifications did not form a single space revision chain")
		}
		for i := range repos {
			if repos[i]["spaceRev"] != calls[i].body["spaceRev"] || repos[i]["did"] != calls[i].body["repo"] {
				t.Fatal("listed writers differ from the published sequence")
			}
		}
	})

	t.Run("rejects future revisions while allowing a small clock skew", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		future := syntax.NewTIDFromTime(time.Now().Add(10*time.Minute), 0).String()
		expectErr(t, syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, future, syncEmptyHash()), ""), 400, "FutureRev")
		if got := syncWriterDids(t, r, sp); len(got) != 0 {
			t.Fatalf("writer set %v after a rejected future rev", got)
		}
		skew := syntax.NewTIDFromTime(time.Now().Add(time.Minute), 0).String()
		mustOK(t, syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, skew, syncEmptyHash()), ""))
		if got := syncWriterDids(t, r, sp); len(got) != 1 || got[0] != bob.did {
			t.Fatalf("writer set %v, want [%s]", got, bob.did)
		}
	})

	t.Run("rejects one that spoofs the writer", func(t *testing.T) {
		// Bob signs but claims carol wrote. The authority refuses on iss ≠ repo,
		// which is what keeps a PDS from moving another account's sync position.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
		res := syncNotify(t, r, bob, syncNotifyBody(sp, carol.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), "")
		if res.status != 403 || !strings.Contains(res.message(), "iss does not match claimed writer") {
			t.Fatalf("want 403 iss mismatch, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects one addressed to another authority", func(t *testing.T) {
		// Everything but the audience checks out: bob is a member signing for
		// himself, off a real write. Only the aud stands between him and
		// moving the writer set that listRepos publishes.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		mustOK(t, doWrite(bob, sp, writeOpts{text: "misaddressed"}))
		state := repoState(t, bob, sp)

		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, *state.Rev, syncLtHashDigest(t, state.SetHash)), carol.did)
		if res.status != 403 || !strings.Contains(res.message(), "aud does not match the space authority") {
			t.Fatalf("want 403 aud mismatch, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects one from a non-member", func(t *testing.T) {
		// iss === repo, but the signer isn't admitted by the write policy.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		res := syncNotify(t, r, carol, syncNotifyBody(sp, carol.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), "")
		if res.status != 403 || !strings.Contains(res.message(), "not authorized") {
			t.Fatalf("want 403 not authorized, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects a member without write access", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		putMember(t, alice, sp, bob, true, false)

		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, syntax.NewTIDNow(0).String(), syncEmptyHash()), "")
		if res.status != 403 || !strings.Contains(res.message(), "not authorized") {
			t.Fatalf("want 403 not authorized, got %d %s", res.status, res.raw)
		}
	})

	t.Run("rejects a repoRev that is not a TID before any auth check", func(t *testing.T) {
		// `repoRev` is typed as a tid, so a malformed one is refused before the
		// service auth is even checked. Worth pinning: an adversarial test that
		// passes a junk rev would be rejected here and never exercise the
		// check it means to.
		sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
		res := syncNotify(t, r, bob, syncNotifyBody(sp, bob.did, "not-a-tid", syncEmptyHash()), "")
		if res.status != 400 || !strings.Contains(res.message(), "TID") {
			t.Fatalf("want 400 invalid TID, got %d %s", res.status, res.raw)
		}
	})
}

// sync helpers ------------------------------------------------------------

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func listRepoDids(res xres) []string {
	var out []string
	for _, rp := range res.list("repos") {
		if did, ok := rp["did"].(string); ok {
			out = append(out, did)
		}
	}
	return out
}

// syncStrPtr boxes a string.
func syncStrPtr(s string) *string { return &s }

// syncEmptyHash is a fresh empty-repo hash, the reference's new LtHash().digest().
func syncEmptyHash() []byte {
	d := space.NewLtHash().Digest()
	return d[:]
}

// lexBytesOf decodes an atproto {"$bytes": base64} value from JSON-decoded
// output, as space.LexBytes encodes it (raw, unpadded std base64).
func lexBytesOf(v any) ([]byte, error) {
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

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameJSON compares two JSON bodies by their decoded form.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatal(err)
	}
	ab, _ := json.Marshal(av)
	bb, _ := json.Marshal(bv)
	return string(ab) == string(bb)
}
