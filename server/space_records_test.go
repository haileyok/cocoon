package server

// Ports packages/pds/tests/space/records.test.ts from bluesky-social/atproto
// d4def6e9, plus its records-specific November cases in auth.test.ts (OAuth
// clearRecords grants), policy.test.ts (published records and listSpaces), and
// sync.test.ts (record MACs). Blob cases live in space_blobs_test.go.
//
// The October listRecords "reverse" case is deliberately not ported: the
// parameter was removed in November. The reference's record-size case calls
// prepareCreate directly because its HTTP body limit is lower; Cocoon's
// equivalent seam is prepareSpaceWrite. No lexicon-catalog cases are skipped:
// Cocoon deliberately reports third-party collections as validationStatus
// "unknown" and rejects validate=true for them.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
)

const recordsEmptyRepoData = "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"

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

func recordsCreateWrite(rkey, text string) map[string]any {
	return map[string]any{
		"$type": "com.atproto.space.applyWrites#create", "collection": testCollection,
		"rkey": rkey, "value": testRecord(testCollection, text),
	}
}

func recordsLexBytes(t *testing.T, value any) []byte {
	t.Helper()
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("not a lex bytes object: %#v", value)
	}
	encoded, ok := m["$bytes"].(string)
	if !ok {
		t.Fatalf("not a lex bytes object: %#v", value)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("invalid lex bytes %q: %v", encoded, err)
	}
	return decoded
}

func recordsCommitDataHex(t *testing.T, res xres) string {
	t.Helper()
	commit, ok := res.body["commit"].(map[string]any)
	if !ok {
		t.Fatalf("response has no commit: %s", res.raw)
	}
	return hex.EncodeToString(recordsLexBytes(t, commit["data"]))
}

func recordsSameRepoState(a, b *models.SpaceRepo) bool {
	if a == nil || b == nil {
		return a == b
	}
	if (a.Rev == nil) != (b.Rev == nil) {
		return false
	}
	return (a.Rev == nil || *a.Rev == *b.Rev) && bytes.Equal(a.SetHash, b.SetHash)
}

func recordsListedSpace(res xres, spaceURI string) map[string]any {
	for _, entry := range res.list("spaces") {
		if entry["space"] == spaceURI {
			return entry
		}
	}
	return nil
}

func recordsExpectMessage(t *testing.T, res xres, status int, name, substring string) {
	t.Helper()
	if res.status != status || (name != "" && res.errName() != name) || !strings.Contains(res.message(), substring) {
		t.Fatalf("want %d %s with message containing %q, got %d: %s", status, name, substring, res.status, res.raw)
	}
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
		got := mustOK(t, r.dan.get("com.atproto.space.getRecord", map[string]string{
			"space": sp, "repo": r.dan.did, "collection": testCollection, "rkey": lastSegment(created.str("uri")),
		}))
		value, _ := got.body["value"].(map[string]any)
		if value["text"] != "hello from dan" {
			t.Fatalf("%s", got.raw)
		}
		after := repoState(t, r.dan, sp)
		if after == nil || after.Rev == nil || (before != nil && before.Rev != nil && *after.Rev == *before.Rev) || (before != nil && bytes.Equal(after.SetHash, before.SetHash)) {
			t.Fatal("repo did not advance on both its revision and set hash")
		}
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("writes a record from a remote PDS", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		created := mustOK(t, doWrite(r.bob, sp, writeOpts{text: "hello from bob"}))
		if !strings.Contains(created.str("uri"), r.bob.did) {
			t.Fatal(created.str("uri"))
		}
		ops := mustOK(t, r.bob.get("com.atproto.space.listRepoOps", map[string]string{
			"space": sp, "repo": r.bob.did,
		})).list("ops")
		last := ops[len(ops)-1]
		if last["cid"] != created.str("cid") || last["prev"] != nil {
			t.Fatalf("%v", last)
		}
		if _, hasAction := last["action"]; hasAction {
			t.Fatal("wire op carries an action")
		}
		listed := mustOK(t, r.bob.get("com.atproto.space.listSpaces", nil))
		if recordsListedSpace(listed, sp) == nil {
			t.Fatalf("listSpaces on the writer's PDS misses %s: %s", sp, listed.raw)
		}
	})

	t.Run("refuses a write to another account repo", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		res := r.dan.post("com.atproto.space.createRecord", map[string]any{
			"space": sp, "repo": r.alice.did, "collection": testCollection, "record": testRecord(testCollection, ""),
		})
		expectErr(t, res, 403, "Forbidden")
	})

	t.Run("creates a repo in another authority's space without checking it exists", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{ungoverned: true})
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "first write"}))
		expectSetHashMatchesStore(t, r.bob, sp)
	})

	t.Run("refuses an authority write to its own deleted space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		mustOK(t, r.alice.post("com.atproto.space.deleteSpace", map[string]any{"space": sp}))
		expectErr(t, doWrite(r.alice, sp, writeOpts{text: "revived?"}), 400, "SpaceNotFound")
		row, err := r.alice.pds.s.spaceStore(nil, r.alice.did).getSpace(sp)
		if err != nil {
			t.Fatal(err)
		}
		if row == nil || row.DeletedAt == nil {
			t.Fatal("the deleted-space tombstone did not survive the write")
		}
	})

	t.Run("deletes a record", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		created := mustOK(t, doWrite(r.dan, sp, writeOpts{text: "to be deleted"}))
		rkey := lastSegment(created.str("uri"))
		mustOK(t, doDel(r.dan, sp, "", rkey))
		ops := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{
			"space": sp, "repo": r.dan.did,
		})).list("ops")
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
		got := mustOK(t, r.dan.get("com.atproto.space.getRecord", map[string]string{
			"space": sp, "repo": r.dan.did, "collection": testCollection, "rkey": "put-new",
		}))
		value, _ := got.body["value"].(map[string]any)
		if value["text"] != "first" {
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
		got := mustOK(t, r.dan.get("com.atproto.space.getRecord", map[string]string{
			"space": sp, "repo": r.dan.did, "collection": testCollection, "rkey": "put-over",
		}))
		value, _ := got.body["value"].(map[string]any)
		if value["text"] != "second" {
			t.Fatalf("%s", got.raw)
		}
		ops := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{
			"space": sp, "repo": r.dan.did,
		})).list("ops")
		last := ops[len(ops)-1]
		if last["cid"] != updated.str("cid") || last["prev"] != created.str("cid") {
			t.Fatalf("%v", last)
		}
		expectSetHashMatchesStore(t, r.dan, sp)
		listed := mustOK(t, r.dan.get("com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.dan.did, "collection": testCollection,
		}))
		if len(listed.list("records")) != 1 {
			t.Fatalf("%s", listed.raw)
		}
	})
}

func TestSpaceRecordsApplyWrites(t *testing.T) {
	r := newRecordsNet(t)
	apply := func(sp string, writes []any) xres {
		return r.dan.post("com.atproto.space.applyWrites", map[string]any{
			"space": sp, "repo": r.dan.did, "writes": writes,
		})
	}

	t.Run("applies a batch as one rev", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, apply(sp, []any{
			recordsCreateWrite("batch-0", "batch 0"), recordsCreateWrite("batch-1", "batch 1"), recordsCreateWrite("batch-2", "batch 2"),
		}))
		ops := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{
			"space": sp, "repo": r.dan.did,
		})).list("ops")
		revs := map[any]bool{}
		var rkeys []string
		for _, op := range ops {
			revs[op["rev"]] = true
			rkey, _ := op["rkey"].(string)
			rkeys = append(rkeys, rkey)
		}
		if len(revs) != 1 || strings.Join(rkeys, ",") != "batch-0,batch-1,batch-2" {
			t.Fatalf("%v", ops)
		}
	})

	t.Run("rejects a duplicate create within one batch", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		expectErr(t, apply(sp, []any{recordsCreateWrite("dupe", "one"), recordsCreateWrite("dupe", "two")}), 400, "RecordAlreadyExists")
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("applies dependent writes within one batch", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, apply(sp, []any{
			recordsCreateWrite("dependent", "first"),
			map[string]any{
				"$type": "com.atproto.space.applyWrites#update", "collection": testCollection,
				"rkey": "dependent", "value": testRecord(testCollection, "second"),
			},
			recordsCreateWrite("survivor", "survivor"),
			map[string]any{
				"$type": "com.atproto.space.applyWrites#update", "collection": testCollection,
				"rkey": "survivor", "value": testRecord(testCollection, "survivor updated"),
			},
			map[string]any{
				"$type": "com.atproto.space.applyWrites#delete", "collection": testCollection, "rkey": "dependent",
			},
		}))
		listed := mustOK(t, r.dan.get("com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.dan.did,
		})).list("records")
		if len(listed) != 1 || listed[0]["rkey"] != "survivor" {
			t.Fatalf("%v", listed)
		}
		value, _ := listed[0]["value"].(map[string]any)
		if value["text"] != "survivor updated" {
			t.Fatalf("an update in the batch did not change the surviving record: %v", listed)
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
		expectErr(t, r.dan.get("com.atproto.space.getLatestCommit", map[string]string{
			"space": sp, "repo": r.dan.did,
		}), 400, "RepoNotFound")
	})

	t.Run("reports each result against the write it came from", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "doomed", text: "doomed"}))
		results := mustOK(t, apply(sp, []any{
			recordsCreateWrite("first", "first"),
			map[string]any{
				"$type": "com.atproto.space.applyWrites#delete", "collection": testCollection, "rkey": "doomed",
			},
			recordsCreateWrite("last", "last"),
		})).list("results")
		if len(results) != 3 || results[1]["$type"] != "com.atproto.space.applyWrites#deleteResult" {
			t.Fatalf("%v", results)
		}
		if results[0]["uri"] != sp+"/"+r.dan.did+"/"+testCollection+"/first" || results[2]["uri"] != sp+"/"+r.dan.did+"/"+testCollection+"/last" {
			t.Fatalf("%v", results)
		}
		if results[0]["validationStatus"] != "unknown" || results[2]["validationStatus"] != "unknown" {
			t.Fatalf("%v", results)
		}
	})

	t.Run("refuses a batch over the write limit", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		var writes []any
		for i := 0; i < 201; i++ {
			writes = append(writes, recordsCreateWrite(fmt.Sprintf("over-%d", i), fmt.Sprintf("over %d", i)))
		}
		recordsExpectMessage(t, apply(sp, writes), 400, "", "Too many writes")
	})

	t.Run("refuses an unrecognized write type at the schema", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		res := apply(sp, []any{map[string]any{"$type": "com.example.somethingElse"}})
		if res.status != 400 || !strings.Contains(res.message(), "Expected one of") ||
			!strings.Contains(res.message(), "applyWrites#create") || !strings.Contains(res.message(), "$.writes[0]") {
			t.Fatalf("schema error does not identify the closed union and write: %d %s", res.status, res.raw)
		}
	})
}

func TestSpaceRecordsClearRecords(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("deletes every record, leaving the repo empty at a new rev", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "one", text: "one"}))
		mustOK(t, doWrite(r.dan, sp, writeOpts{collection: testCollectionAlt, rkey: "two", text: "two"}))
		before := repoState(t, r.dan, sp)
		mustOK(t, clearRecords(r.dan, sp))
		listed := mustOK(t, r.dan.get("com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.dan.did,
		}))
		if len(listed.list("records")) != 0 {
			t.Fatalf("%s", listed.raw)
		}
		res := mustOK(t, r.dan.get("com.atproto.space.getLatestCommit", map[string]string{
			"space": sp, "repo": r.dan.did,
		}))
		after := repoState(t, r.dan, sp)
		commit, _ := res.body["commit"].(map[string]any)
		if before == nil || before.Rev == nil || after == nil || after.Rev == nil || *after.Rev <= *before.Rev {
			t.Fatalf("clear did not advance the revision: before=%+v after=%+v", before, after)
		}
		if commit["rev"] != *after.Rev || recordsCommitDataHex(t, res) != recordsEmptyRepoData {
			t.Fatalf("wrong empty-repo commit: %s", res.raw)
		}
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("clears the oplog rather than logging a delete per record", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "one", text: "one"}))
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "two", text: "two"}))
		mustOK(t, clearRecords(r.dan, sp))
		res := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{
			"space": sp, "repo": r.dan.did,
		}))
		if len(res.list("ops")) != 0 || res.body["commit"] == nil || recordsCommitDataHex(t, res) != recordsEmptyRepoData {
			t.Fatalf("%s", res.raw)
		}
	})

	t.Run("notifies after a clear and does nothing on an empty or unwritten repo", func(t *testing.T) {
		host := r.net.newMockService("atproto_pds", nil)
		sp := space.Ref{Authority: host.did, Type: testSpaceType, Skey: testSkey(t)}.String()
		calls := func() []mockCall { return host.callsTo(lxmNotifyRepoUpdate) }

		// No first commit exists, so clearing an unwritten repo sends nothing.
		mustOK(t, clearRecords(r.bob, sp))
		if repoState(t, r.bob, sp) != nil || len(calls()) != 0 {
			t.Fatalf("unwritten clear changed state or notified: state=%+v calls=%v", repoState(t, r.bob, sp), calls())
		}

		mustOK(t, doWrite(r.bob, sp, writeOpts{rkey: "one"}))
		if len(calls()) != 1 {
			t.Fatalf("write produced %d notifications", len(calls()))
		}
		before := repoState(t, r.bob, sp)
		mustOK(t, clearRecords(r.bob, sp))
		cleared := repoState(t, r.bob, sp)
		if before == nil || before.Rev == nil || cleared == nil || cleared.Rev == nil || *cleared.Rev <= *before.Rev {
			t.Fatal("clear did not produce a new rev")
		}
		if len(calls()) != 2 {
			t.Fatalf("clear produced %d total notifications, want 2", len(calls()))
		}
		notice := calls()[1]
		if notice.body["space"] != sp || notice.body["repo"] != r.bob.did || notice.body["repoRev"] != *cleared.Rev ||
			hex.EncodeToString(recordsLexBytes(t, notice.body["data"])) != recordsEmptyRepoData {
			t.Fatalf("wrong clear notification: %#v", notice.body)
		}

		// A clear has already emptied this repo. Repeating it changes nothing and
		// sends no notifyRepoUpdate.
		mustOK(t, clearRecords(r.bob, sp))
		if !recordsSameRepoState(cleared, repoState(t, r.bob, sp)) || len(calls()) != 2 {
			t.Fatal("clearing an already-cleared repo advanced state or notified")
		}

		// The same no-op rule applies when ordinary deletes emptied the repo.
		mustOK(t, doWrite(r.bob, sp, writeOpts{rkey: "gone"}))
		mustOK(t, doDel(r.bob, sp, "", "gone"))
		emptied := repoState(t, r.bob, sp)
		beforeCalls := len(calls())
		mustOK(t, clearRecords(r.bob, sp))
		if !recordsSameRepoState(emptied, repoState(t, r.bob, sp)) || len(calls()) != beforeCalls {
			t.Fatal("clearing a repo emptied by delete advanced state or notified")
		}
	})

	t.Run("recreates the repo on a later write", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "before"}))
		mustOK(t, clearRecords(r.dan, sp))
		cleared := repoState(t, r.dan, sp)
		created := mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "after"}))
		after := repoState(t, r.dan, sp)
		if cleared == nil || cleared.Rev == nil || after == nil || after.Rev == nil || *after.Rev <= *cleared.Rev {
			t.Fatal("later write did not advance the cleared repo")
		}
		ops := mustOK(t, r.dan.get("com.atproto.space.listRepoOps", map[string]string{
			"space": sp, "repo": r.dan.did,
		})).list("ops")
		if len(ops) != 1 || ops[0]["rkey"] != "after" || ops[0]["cid"] != created.str("cid") || ops[0]["prev"] != nil {
			t.Fatalf("%v", ops)
		}
		expectSetHashMatchesStore(t, r.dan, sp)
	})

	t.Run("leaves the account's repos in other spaces alone", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		other := createSpace(t, r.alice, spaceOpts{skey: "clear-records-other", members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "cleared"}))
		mustOK(t, doWrite(r.dan, other, writeOpts{rkey: "kept"}))
		mustOK(t, clearRecords(r.dan, sp))
		listed := mustOK(t, r.dan.get("com.atproto.space.listRecords", map[string]string{
			"space": other, "repo": r.dan.did,
		})).list("records")
		if len(listed) != 1 || listed[0]["rkey"] != "kept" {
			t.Fatalf("%v", listed)
		}
		expectSetHashMatchesStore(t, r.dan, other)
	})

	t.Run("refuses to clear another account repo", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		res := r.dan.post("com.atproto.space.clearRecords", map[string]any{"space": sp, "repo": r.alice.did})
		expectErr(t, res, 403, "Forbidden")
	})

	t.Run("requires delete on every collection an OAuth clear removes", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		mustOK(t, doWrite(r.alice, sp, writeOpts{collection: testCollection, rkey: "first"}))
		mustOK(t, doWrite(r.alice, sp, writeOpts{collection: testCollectionAlt, rkey: "second"}))
		asOAuth := func(params, action string) *actor {
			copy := *r.alice
			copy.oauth = r.pds1.newOAuthSession(r.alice,
				"atproto space:"+testSpaceType+"?authority="+r.alice.did+"&"+params+"&action="+action)
			return &copy
		}

		bothCollections := "collection=" + testCollection + "&collection=" + testCollectionAlt
		for _, action := range []string{"create", "update"} {
			wrongAction := asOAuth(bothCollections, action)
			expectErr(t, clearRecords(wrongAction, sp), 403, "InsufficientScope")
		}
		limited := asOAuth("collection="+testCollection, "delete")
		expectErr(t, clearRecords(limited, sp), 403, "InsufficientScope")
		kept := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.alice.did,
		})).list("records")
		if len(kept) != 2 {
			t.Fatalf("partial clear changed the repo: %v", kept)
		}

		allowed := asOAuth(bothCollections, "delete")
		mustOK(t, clearRecords(allowed, sp))
		remaining := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.alice.did,
		})).list("records")
		if len(remaining) != 0 {
			t.Fatalf("OAuth clear left records behind: %v", remaining)
		}
	})

	t.Run("keeps published policy and member records in the authority's repo", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{
			policy:  memberPolicy(map[string]any{"publishPolicy": true, "publishMembers": true}),
			members: []*actor{r.bob},
		})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "own"}))
		mustOK(t, clearRecords(r.alice, sp))
		records := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.alice.did,
		})).list("records")
		var collections []string
		for _, record := range records {
			collection, _ := record["collection"].(string)
			collections = append(collections, collection)
		}
		sort.Strings(collections)
		want := []string{collMember, collPolicy}
		sort.Strings(want)
		if strings.Join(collections, ",") != strings.Join(want, ",") {
			t.Fatalf("published records were not preserved: %v", records)
		}
		expectSetHashMatchesStore(t, r.alice, sp)

		// Only PDS-published records remain, so there is nothing more to clear.
		cleared := repoState(t, r.alice, sp)
		mustOK(t, clearRecords(r.alice, sp))
		if !recordsSameRepoState(cleared, repoState(t, r.alice, sp)) {
			t.Fatal("a clear that retained only published records was not a no-op")
		}
	})
}

func TestSpaceRecordsPublishedRecordsRefuseDirectWrites(t *testing.T) {
	r := newRecordsNet(t)
	sp := createSpace(t, r.alice, spaceOpts{
		policy:  memberPolicy(map[string]any{"publishPolicy": true, "publishMembers": true}),
		members: []*actor{r.bob},
	})

	for _, writer := range []*actor{r.alice, r.bob} {
		for _, collection := range []string{collPolicy, collMember} {
			for _, method := range []string{"createRecord", "putRecord", "deleteRecord", "applyWrites"} {
				t.Run(writer.name+"/"+collection+"/"+method, func(t *testing.T) {
					record := map[string]any{"$type": collection}
					if collection == collPolicy {
						record["policy"] = personalPolicy()
					} else {
						record["read"] = true
						record["write"] = true
					}
					var res xres
					switch method {
					case "createRecord":
						res = doWrite(writer, sp, writeOpts{collection: collection, rkey: "self", record: record})
					case "putRecord":
						res = doPut(writer, sp, writeOpts{collection: collection, rkey: "self", record: record})
					case "deleteRecord":
						res = doDel(writer, sp, collection, "self")
					case "applyWrites":
						for _, action := range []string{"create", "update", "delete"} {
							t.Run(action, func(t *testing.T) {
								write := map[string]any{
									"$type": "com.atproto.space.applyWrites#" + action, "collection": collection, "rkey": "self",
								}
								if action != "delete" {
									write["value"] = record
								}
								res := writer.post("com.atproto.space.applyWrites", map[string]any{
									"space": sp, "repo": writer.did, "writes": []any{write},
								})
								recordsExpectMessage(t, res, 400, "InvalidRequest", "cannot be written directly")
							})
						}
						return
					}
					recordsExpectMessage(t, res, 400, "InvalidRequest", "cannot be written directly")
				})
			}
		}
	}

	// Turning validation off does not open a way around the restriction.
	res := doPut(r.alice, sp, writeOpts{
		collection: collPolicy, rkey: "self", validate: boolp(false),
		record: map[string]any{"$type": collPolicy, "policy": personalPolicy()},
	})
	recordsExpectMessage(t, res, 400, "InvalidRequest", "cannot be written directly")

	// Nor can the PDS-published policy be withdrawn through deleteRecord.
	published := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{
		"space": sp, "repo": r.alice.did, "collection": collPolicy,
	})).list("records")
	if len(published) != 1 || published[0]["rkey"] != "self" {
		t.Fatalf("published policy was changed by refused writes: %v", published)
	}
}

func TestSpaceRecordsValidation(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("rejects a record whose $type disagrees with its collection", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		res := doWrite(r.alice, sp, writeOpts{
			collection: testCollection, record: testRecord(testCollectionAlt, "mismatched"),
		})
		expectErr(t, res, 400, "InvalidRecord")
	})

	t.Run("reports unknown for a collection with no resolvable schema", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		if status := mustOK(t, doWrite(r.alice, sp, writeOpts{text: "unvalidatable"})).str("validationStatus"); status != "unknown" {
			t.Fatal(status)
		}
	})

	t.Run("refuses an unvalidatable record when validation is demanded", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		expectErr(t, doWrite(r.alice, sp, writeOpts{text: "strict", validate: boolp(true)}), 400, "InvalidRecord")
	})

	t.Run("refuses a record over the size limit", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		ref, err := space.ParseRef(sp)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(testRecord(testCollection, strings.Repeat("x", space.MaxRecordSize)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = prepareSpaceWrite(r.alice.did, ref, "create", testCollection, "", raw, nil)
		if err == nil || !strings.Contains(err.Error(), "Record too large") {
			t.Fatalf("expected the record-size check to reject the write, got %v", err)
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
		second := list(r.dan, map[string]string{
			"space": sp, "repo": r.dan.did, "limit": "1", "cursor": first.str("cursor"),
		})
		if len(second.list("records")) != 1 || second.list("records")[0]["collection"] == first.list("records")[0]["collection"] {
			t.Fatalf("%s", second.raw)
		}
		third := list(r.dan, map[string]string{
			"space": sp, "repo": r.dan.did, "limit": "1", "cursor": second.str("cursor"),
		})
		if len(third.list("records")) != 0 {
			t.Fatalf("%s", third.raw)
		}
	})

	t.Run("filters to one collection", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{collection: testCollection, rkey: "a"}))
		mustOK(t, doWrite(r.dan, sp, writeOpts{collection: testCollectionAlt, rkey: "b"}))
		records := list(r.dan, map[string]string{
			"space": sp, "repo": r.dan.did, "collection": testCollectionAlt,
		}).list("records")
		if len(records) != 1 || records[0]["collection"] != testCollectionAlt {
			t.Fatalf("%v", records)
		}
	})

	t.Run("scopes a listing to one space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{skey: "scope-a"})
		other := createSpace(t, r.alice, spaceOpts{skey: "scope-b"})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "here"}))
		if records := list(r.alice, map[string]string{"space": other, "repo": r.alice.did}).list("records"); len(records) != 0 {
			t.Fatalf("%v", records)
		}
	})

	t.Run("omits values entirely with excludeValues", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "no-value", text: "body"}))
		cred := credentialFor(t, r.dan, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.dan.did, "excludeValues": "true",
		}))
		records := res.list("records")
		if len(records) != 1 || records[0]["rkey"] != "no-value" {
			t.Fatalf("%s", res.raw)
		}
		if recordCid, ok := records[0]["cid"].(string); !ok || recordCid == "" {
			t.Fatalf("missing record CID: %s", res.raw)
		}
		if _, present := records[0]["value"]; present {
			t.Fatalf("excludeValues still returned a value: %v", records[0])
		}
	})

	t.Run("rejects a malformed cursor", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{rkey: "cursor-check"}))
		expectErr(t, r.dan.get("com.atproto.space.listRecords", map[string]string{
			"space": sp, "repo": r.dan.did, "cursor": "not-a-cursor",
		}), 400, "InvalidCursor")
	})
}

func TestSpaceRecordsGetRecord(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("returns the record and its current cid", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		created := mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "by-cid"}))
		got := mustOK(t, r.alice.get("com.atproto.space.getRecord", map[string]string{
			"space": sp, "repo": r.alice.did, "collection": testCollection, "rkey": "by-cid",
		}))
		if got.str("cid") != created.str("cid") || got.str("uri") != sp+"/"+r.alice.did+"/"+testCollection+"/by-cid" {
			t.Fatalf("%s", got.raw)
		}
	})

	t.Run("reports RecordNotFound for a record that never existed", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "present"}))
		expectErr(t, r.alice.get("com.atproto.space.getRecord", map[string]string{
			"space": sp, "repo": r.alice.did, "collection": testCollection, "rkey": "absent",
		}), 400, "RecordNotFound")
	})

	t.Run("macs a record served to a syncer with the record profile", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		mustOK(t, doWrite(r.bob, sp, writeOpts{rkey: "maced"}))
		cred := credentialFor(t, r.carol, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.getRecord", map[string]string{
			"space": sp, "repo": r.bob.did, "collection": testCollection, "rkey": "maced",
		}))
		if cred.lastMac == nil || cred.lastMac.profile != space.RecordMacProfile {
			t.Fatalf("getRecord did not request the record MAC profile: %+v", cred.lastMac)
		}
		uri := sp + "/" + r.bob.did + "/" + testCollection + "/maced"
		if res.str("uri") != uri || res.header.Get(space.HeaderRecord) == "" || res.header.Get("Signature") == "" {
			t.Fatalf("record response lacks its MAC: headers=%v body=%s", res.header, res.raw)
		}
		if !strings.Contains(strings.ToLower(res.header.Get("Vary")), "accept-signature") {
			t.Fatalf("Vary does not include Accept-Signature: %v", res.header)
		}
		value, _ := res.body["value"].(map[string]any)
		params := space.VerifyRecordParams{URI: uri, VerifyMacParams: cred.macParams(t)}
		if err := space.VerifyRecord(res.str("uri"), res.str("cid"), value, params); err != nil {
			t.Fatalf("record did not verify against its MAC: %v", err)
		}
		if err := space.VerifyRecordMac(uri+"x", mustCid(t, res.str("cid")), cred.macParams(t)); err == nil {
			t.Fatal("record MAC was accepted for another record uri")
		}
	})
}

func TestSpaceRecordsListSpaces(t *testing.T) {
	r := newRecordsNet(t)

	t.Run("uses spaceDid and lists each repo's current state", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		empty := createSpace(t, r.alice, spaceOpts{skey: "list-state-empty"})
		otherAuthority := createSpace(t, r.dan, spaceOpts{
			skey: "list-state-other-authority", members: []*actor{r.alice, r.bob},
		})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "alice"}))
		mustOK(t, doWrite(r.bob, sp, writeOpts{rkey: "bob"}))
		// Both accounts also have a repo in Dan's space, so ignoring the filter
		// would visibly return another authority's space on each PDS.
		mustOK(t, doWrite(r.alice, otherAuthority, writeOpts{rkey: "other"}))
		mustOK(t, doWrite(r.bob, otherAuthority, writeOpts{rkey: "other"}))

		viewOf := func(a *actor, target string) map[string]any {
			t.Helper()
			listed := mustOK(t, a.get("com.atproto.space.listSpaces", map[string]string{"spaceDid": r.alice.did}))
			for _, item := range listed.list("spaces") {
				uri, _ := item["space"].(string)
				ref, err := space.ParseRef(uri)
				if err != nil || ref.Authority != r.alice.did {
					t.Fatalf("spaceDid filter returned another authority: %v", item)
				}
			}
			if recordsListedSpace(listed, otherAuthority) != nil {
				t.Fatalf("spaceDid filter did not exclude %s: %s", otherAuthority, listed.raw)
			}
			entry := recordsListedSpace(listed, target)
			if entry == nil {
				t.Fatalf("spaceDid-filtered listing for %s misses %s: %s", a.did, target, listed.raw)
			}
			return entry
		}

		for _, a := range []*actor{r.alice, r.bob} {
			state := repoState(t, a, sp)
			if state == nil || state.Rev == nil {
				t.Fatalf("no repo state for %s", a.did)
			}
			entry := viewOf(a, sp)
			if entry["repoRev"] != *state.Rev {
				t.Fatalf("repoRev for %s: %v, want %s", a.did, entry, *state.Rev)
			}
			hash, err := space.LtHashFromState(state.SetHash)
			if err != nil {
				t.Fatal(err)
			}
			digest := hash.Digest()
			if !bytes.Equal(recordsLexBytes(t, entry["data"]), digest[:]) {
				t.Fatalf("data for %s does not match its repo state: %v", a.did, entry)
			}
			if a == r.bob {
				if _, present := entry["spaceRev"]; present {
					t.Fatalf("writer PDS fabricated a spaceRev: %v", entry)
				}
			}
		}

		writers, err := r.pds1.s.spaceStore(nil, r.alice.did).listWriters(sp, 0, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(writers) == 0 || viewOf(r.alice, sp)["spaceRev"] != writers[len(writers)-1].SpaceRev {
			t.Fatalf("authority did not report the latest spaceRev: writers=%v entry=%v", writers, viewOf(r.alice, sp))
		}
		if entry := viewOf(r.alice, empty); len(entry) != 1 || entry["space"] != empty {
			t.Fatalf("unwritten space gained repo or space state: %v", entry)
		}
	})

	t.Run("rejects a malformed cursor", func(t *testing.T) {
		expectErr(t, r.alice.get("com.atproto.space.listSpaces", map[string]string{"cursor": "not-a-cursor"}), 400, "InvalidCursor")
	})
}
