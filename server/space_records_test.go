package server

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
)

// Ported from packages/pds/tests/space/records.test.ts (bluesky-social/atproto
// 5b95b2f2). Blob cases live in space_blobs_test.go.

type recordsNet struct {
	net                    *spaceNet
	pds1, pds2, pds3       *spacePDS
	alice, dan, bob, carol *actor
}

func newRecordsNet(t *testing.T) *recordsNet {
	t.Helper()
	n := newSpaceNet(t)
	r := &recordsNet{net: n, pds1: n.newPDS(), pds2: n.newPDS(), pds3: n.newPDS()}
	r.alice = r.pds1.createActor("alice") // authority, on pds1
	r.dan = r.pds1.createActor("dan")     // member co-located with the authority
	r.bob = r.pds2.createActor("bob")     // member on pds2
	r.carol = r.pds3.createActor("carol") // on pds3
	return r
}

func mustCid(t *testing.T, s string) cid.Cid {
	t.Helper()
	c, err := cid.Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSpaceRecordsWrites(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("writes a record as a co-located member", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		before := repoState(t, r.dan, sp)
		created := mustOK(t, doWrite(r.dan, sp, writeOpts{text: "hello from dan"}))
		if !strings.Contains(created.str("uri"), r.dan.did) {
			t.Fatal(created.str("uri"))
		}
		got := mustOK(t, r.dan.get("com.atproto.space.getRecord", map[string]string{"space": sp, "repo": r.dan.did, "collection": testCollection, "rkey": lastSegment(created.str("uri"))}))
		if v, _ := got.body["value"].(map[string]any); v["text"] != "hello from dan" {
			t.Fatalf("%s", got.raw)
		}
		after := repoState(t, r.dan, sp)
		if after == nil || (before != nil && (*after.Rev == *before.Rev || bytes.Equal(after.SetHash, before.SetHash))) {
			t.Fatal("repo did not advance")
		}
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("writes a record from a remote PDS", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		created := mustOK(t, doWrite(r.bob, sp, writeOpts{text: "hello from bob"}))
		if !strings.Contains(created.str("uri"), r.bob.did) {
			t.Fatal(created.str("uri"))
		}
		ops := mustOK(t, r.bob.get("com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": r.bob.did})).list("ops")
		last := ops[len(ops)-1]
		if last["cid"] != created.str("cid") || last["prev"] != nil {
			t.Fatalf("%v", last)
		}
		if _, hasAction := last["action"]; hasAction {
			t.Fatal("wire op carries an action")
		}
		listed := mustOK(t, r.bob.get("com.atproto.space.listSpaces", nil)).list("spaces")
		found := false
		for _, s := range listed {
			found = found || s["uri"] == sp
		}
		if !found {
			t.Fatalf("listSpaces on the writer's PDS misses %s", sp)
		}
	})

	t.Run("refuses a write to another account repo", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		res := r.dan.post("com.atproto.space.createRecord", map[string]any{"space": sp, "repo": r.alice.did, "collection": testCollection, "record": testRecord(testCollection, "")})
		expectErr(t, res, 403, "Forbidden")
	})

	t.Run("deletes a record", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		created := mustOK(t, doWrite(r.dan, sp, writeOpts{text: "to be deleted"}))
		rkey := lastSegment(created.str("uri"))
		mustOK(t, doDel(r.dan, sp, "", rkey))
		ops := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": r.dan.did})).list("ops")
		var deleted map[string]any
		for _, op := range ops {
			if op["cid"] == nil {
				deleted = op
				break
			}
		}
		if deleted == nil || deleted["rkey"] != rkey || deleted["prev"] != created.str("cid") {
			t.Fatalf("%v", ops)
		}
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("deleteRecord is idempotent", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		mustOK(t, doDel(r.alice, sp, "", "gone"))
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "gone", text: "here"}))
		mustOK(t, doDel(r.alice, sp, "", "gone"))
		mustOK(t, doDel(r.alice, sp, "", "gone"))
	})
}

func TestSpaceRecordsPutRecord(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("creates a record that does not yet exist", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		put := mustOK(t, doPut(r.dan, sp, writeOpts{rkey: "put-new", text: "first"}))
		if put.str("uri") != sp+"/"+r.dan.did+"/"+testCollection+"/put-new" {
			t.Fatal(put.str("uri"))
		}
		got := mustOK(t, r.dan.get("com.atproto.space.getRecord", map[string]string{"space": sp, "repo": r.dan.did, "collection": testCollection, "rkey": "put-new"}))
		if v, _ := got.body["value"].(map[string]any); v["text"] != "first" {
			t.Fatalf("%s", got.raw)
		}
	})

	t.Run("overwrites an existing record, and the oplog names what it replaced", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		created := mustOK(t, doPut(r.dan, sp, writeOpts{rkey: "put-over", text: "first"}))
		updated := mustOK(t, doPut(r.dan, sp, writeOpts{rkey: "put-over", text: "second"}))
		if updated.str("cid") == created.str("cid") {
			t.Fatal("cid unchanged")
		}
		got := mustOK(t, r.dan.get("com.atproto.space.getRecord", map[string]string{"space": sp, "repo": r.dan.did, "collection": testCollection, "rkey": "put-over"}))
		if v, _ := got.body["value"].(map[string]any); v["text"] != "second" {
			t.Fatalf("%s", got.raw)
		}
		ops := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": r.dan.did})).list("ops")
		last := ops[len(ops)-1]
		if last["cid"] != updated.str("cid") || last["prev"] != created.str("cid") {
			t.Fatalf("%v", last)
		}
		expectSetHashMatchesStore(t, r.dan, sp)
		listed := mustOK(t, r.dan.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.dan.did, "collection": testCollection}))
		if len(listed.list("records")) != 1 {
			t.Fatalf("%s", listed.raw)
		}
	})
}

func createWrite(rkey, text string) map[string]any {
	return map[string]any{"$type": "com.atproto.space.applyWrites#create", "collection": testCollection, "rkey": rkey, "value": testRecord(testCollection, text)}
}

func TestSpaceRecordsApplyWrites(t *testing.T) {
	r := newRecordsNet(t)
	apply := func(sp string, writes []any) xres {
		return r.dan.post("com.atproto.space.applyWrites", map[string]any{"space": sp, "repo": r.dan.did, "writes": writes})
	}

	t.Run("applies a batch as one rev", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, apply(sp, []any{createWrite("batch-0", "batch 0"), createWrite("batch-1", "batch 1"), createWrite("batch-2", "batch 2")}))
		ops := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": r.dan.did})).list("ops")
		revs := map[any]bool{}
		var rkeys []string
		for _, op := range ops {
			revs[op["rev"]] = true
			rkeys = append(rkeys, op["rkey"].(string))
		}
		if len(revs) != 1 || strings.Join(rkeys, ",") != "batch-0,batch-1,batch-2" {
			t.Fatalf("%v", ops)
		}
	})

	t.Run("rejects a duplicate create within one batch", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		expectErr(t, apply(sp, []any{createWrite("dupe", "one"), createWrite("dupe", "two")}), 400, "RecordAlreadyExists")
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("applies dependent writes within one batch", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, apply(sp, []any{
			createWrite("dependent", "first"),
			map[string]any{"$type": "com.atproto.space.applyWrites#update", "collection": testCollection, "rkey": "dependent", "value": testRecord(testCollection, "second")},
			createWrite("survivor", "survivor"),
			map[string]any{"$type": "com.atproto.space.applyWrites#delete", "collection": testCollection, "rkey": "dependent"},
		}))
		listed := mustOK(t, r.dan.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.dan.did})).list("records")
		if len(listed) != 1 || listed[0]["rkey"] != "survivor" {
			t.Fatalf("%v", listed)
		}
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("treats an empty batch as a no-op", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		res := mustOK(t, apply(sp, []any{}))
		if res.raw == nil || len(res.list("results")) != 0 || res.body["results"] == nil {
			t.Fatalf("%s", res.raw)
		}
		if repoState(t, r.dan, sp) != nil {
			t.Fatal("empty batch materialized a repo")
		}
		expectErr(t, r.dan.get("com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.dan.did}), 400, "RepoNotFound")
	})

	t.Run("reports each result against the write it came from", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "doomed", text: "doomed"}))
		res := mustOK(t, apply(sp, []any{
			createWrite("first", "first"),
			map[string]any{"$type": "com.atproto.space.applyWrites#delete", "collection": testCollection, "rkey": "doomed"},
			createWrite("last", "last"),
		})).list("results")
		if len(res) != 3 || res[1]["$type"] != "com.atproto.space.applyWrites#deleteResult" {
			t.Fatalf("%v", res)
		}
		if res[0]["uri"] != sp+"/"+r.dan.did+"/"+testCollection+"/first" || res[2]["uri"] != sp+"/"+r.dan.did+"/"+testCollection+"/last" {
			t.Fatalf("%v", res)
		}
		if res[0]["validationStatus"] != "unknown" || res[2]["validationStatus"] != "unknown" {
			t.Fatalf("%v", res)
		}
	})

	t.Run("refuses a batch over the write limit", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		var writes []any
		for i := 0; i < 201; i++ {
			writes = append(writes, createWrite(fmt.Sprintf("over-%d", i), "over"))
		}
		res := apply(sp, writes)
		if res.status != 400 || !strings.Contains(res.message(), "Too many writes") {
			t.Fatalf("%d %s", res.status, res.raw)
		}
	})

	t.Run("refuses an unrecognized write type at the schema", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		expectErr(t, apply(sp, []any{map[string]any{"$type": "com.example.somethingElse"}}), 400, "InvalidRequest")
	})
}

func TestSpaceRecordsValidation(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("rejects a record whose $type disagrees with its collection", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		res := doWrite(r.alice, sp, writeOpts{collection: testCollection, record: testRecord(testCollectionAlt, "mismatched")})
		if res.status == 200 {
			t.Fatal("accepted")
		}
	})

	t.Run("reports unknown for a collection with no resolvable schema", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		if s := mustOK(t, doWrite(r.alice, sp, writeOpts{text: "unvalidatable"})).str("validationStatus"); s != "unknown" {
			t.Fatal(s)
		}
	})

	t.Run("refuses an unvalidatable record when validation is demanded", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		if res := doWrite(r.alice, sp, writeOpts{text: "strict", validate: boolp(true)}); res.status == 200 {
			t.Fatal("accepted")
		}
	})
}

func TestSpaceRecordsListRecords(t *testing.T) {
	r := newRecordsNet(t)
	list := func(a *actor, params map[string]string) xres {
		return mustOK(t, a.get("com.atproto.space.listRecords", params))
	}

	t.Run("paginates across collections", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{collection: testCollection, rkey: "a", text: "post"}))
		mustOK(t, doWrite(r.dan, sp, writeOpts{collection: testCollectionAlt, rkey: "b", text: "note"}))
		first := list(r.dan, map[string]string{"space": sp, "repo": r.dan.did, "limit": "1"})
		if len(first.list("records")) != 1 || first.str("cursor") == "" {
			t.Fatalf("%s", first.raw)
		}
		second := list(r.dan, map[string]string{"space": sp, "repo": r.dan.did, "limit": "1", "cursor": first.str("cursor")})
		if len(second.list("records")) != 1 || second.list("records")[0]["collection"] == first.list("records")[0]["collection"] {
			t.Fatalf("%s", second.raw)
		}
		third := list(r.dan, map[string]string{"space": sp, "repo": r.dan.did, "limit": "1", "cursor": second.str("cursor")})
		if len(third.list("records")) != 0 {
			t.Fatalf("%s", third.raw)
		}
	})

	t.Run("filters to one collection", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{collection: testCollection, rkey: "a"}))
		mustOK(t, doWrite(r.dan, sp, writeOpts{collection: testCollectionAlt, rkey: "b"}))
		recs := list(r.dan, map[string]string{"space": sp, "repo": r.dan.did, "collection": testCollectionAlt}).list("records")
		if len(recs) != 1 || recs[0]["collection"] != testCollectionAlt {
			t.Fatalf("%v", recs)
		}
	})

	t.Run("reverses the listing order", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		for _, k := range []string{"aaa", "bbb", "ccc"} {
			mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: k}))
		}
		rkeys := func(rs []map[string]any) []string {
			var out []string
			for _, x := range rs {
				out = append(out, x["rkey"].(string))
			}
			return out
		}
		fwd := rkeys(list(r.dan, map[string]string{"space": sp, "repo": r.dan.did, "collection": testCollection}).list("records"))
		rev := rkeys(list(r.dan, map[string]string{"space": sp, "repo": r.dan.did, "collection": testCollection, "reverse": "true"}).list("records"))
		if len(fwd) != 3 || fwd[0] != rev[2] || fwd[1] != rev[1] || fwd[2] != rev[0] {
			t.Fatalf("%v %v", fwd, rev)
		}
	})

	t.Run("scopes a listing to one space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{skey: "scope-a"})
		other := createSpace(t, r.alice, spaceOpts{skey: "scope-b"})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "here"}))
		if recs := list(r.alice, map[string]string{"space": other, "repo": r.alice.did}).list("records"); len(recs) != 0 {
			t.Fatalf("%v", recs)
		}
	})
}

func TestSpaceRecordsGetRecord(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("returns the record and its current cid", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		created := mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "by-cid"}))
		got := mustOK(t, r.alice.get("com.atproto.space.getRecord", map[string]string{"space": sp, "repo": r.alice.did, "collection": testCollection, "rkey": "by-cid"}))
		if got.str("cid") != created.str("cid") || got.str("uri") != sp+"/"+r.alice.did+"/"+testCollection+"/by-cid" {
			t.Fatalf("%s", got.raw)
		}
	})

	t.Run("reports RecordNotFound for a record that never existed", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "present"}))
		expectErr(t, r.alice.get("com.atproto.space.getRecord", map[string]string{"space": sp, "repo": r.alice.did, "collection": testCollection, "rkey": "absent"}), 400, "RecordNotFound")
	})
}
