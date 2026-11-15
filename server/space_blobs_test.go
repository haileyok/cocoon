package server

// Ports the blob cases of packages/pds/tests/space/records.test.ts from
// bluesky-social/atproto d4def6e9. The October "filters listBlobs by revision"
// case is deliberately not ported: its `since` parameter was removed in
// November; the replacement case lists all current blob CIDs without it.
// Reference background-queue/processAll calls do not apply because Cocoon
// updates and collects space blob references in the write transaction.

import (
	"bytes"
	"context"
	"net/http"
	"sort"
	"testing"
)

// spaceBlobsUpload uploads bytes as a's blob, returning the blob ref and CID.
func spaceBlobsUpload(t *testing.T, a *actor, data []byte) (map[string]any, string) {
	t.Helper()
	headers := a.auth()
	headers["Content-Type"] = "image/png"
	res := mustOK(t, a.pds.net.do(http.MethodPost, a.pds.url, "com.atproto.repo.uploadBlob", nil, data, headers))
	blob, _ := res.body["blob"].(map[string]any)
	ref, _ := blob["ref"].(map[string]any)
	blobCid, _ := ref["$link"].(string)
	if blob == nil || blobCid == "" {
		t.Fatalf("no blob cid: %s", res.raw)
	}
	return blob, blobCid
}

func spaceBlobsRecord(text string, blob map[string]any) map[string]any {
	return map[string]any{"$type": testCollection, "text": text, "image": blob}
}

func spaceBlobsGet(t *testing.T, c *spaceCredential, p *spacePDS, sp, repo, blobCid string) xres {
	t.Helper()
	return c.get(t, p, "com.atproto.space.getBlob", map[string]string{
		"space": sp, "repo": repo, "cid": blobCid,
	})
}

func spaceBlobsExists(t *testing.T, a *actor, blobCid string) bool {
	t.Helper()
	_, found, err := a.pds.s.readBlobBytes(context.Background(), a.did, mustCid(t, blobCid))
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func spaceBlobsPublicGet(a *actor, blobCid string) xres {
	return a.pds.get("com.atproto.sync.getBlob", map[string]string{"did": a.did, "cid": blobCid}, nil)
}

func TestSpaceBlobs(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice") // authority and blob uploader
	carol := pds2.createActor("carol") // member on another PDS

	t.Run("makes an uploaded blob permanent on a record and serves it to a member", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{carol}})
		data := []byte{1, 2, 3, 4, 5}
		blob, blobCid := spaceBlobsUpload(t, alice, data)
		cred := credentialFor(t, carol, pds1, sp)

		// Upload alone leaves the blob untethered: a space read cannot obtain it
		// until a space record names it. Cocoon keeps uploaded bytes in SQLite,
		// unlike the reference's separate temporary blobstore, so this checks the
		// same permanence boundary through the public space API.
		expectErr(t, spaceBlobsGet(t, cred, pds1, sp, alice.did, blobCid), 400, "BlobNotFound")

		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "with-blob", record: spaceBlobsRecord("has a blob", blob)}))
		if !spaceBlobsExists(t, alice, blobCid) {
			t.Fatal("blob bytes not stored")
		}
		listed := mustOK(t, cred.get(t, pds1, "com.atproto.space.listBlobs", map[string]string{
			"space": sp, "repo": alice.did,
		}))
		cids, _ := listed.body["cids"].([]any)
		if len(cids) != 1 || cids[0] != blobCid {
			t.Fatalf("%s", listed.raw)
		}
		got := spaceBlobsGet(t, cred, pds1, sp, alice.did, blobCid)
		if got.status != 200 || !bytes.Equal(got.raw, data) {
			t.Fatalf("%d %v", got.status, got.raw)
		}
	})

	t.Run("does not serve a space-only blob through public sync", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		blob, blobCid := spaceBlobsUpload(t, alice, []byte{5, 4, 3, 2, 1})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "private-blob", record: spaceBlobsRecord("private", blob)}))
		listed := mustOK(t, alice.pds.get("com.atproto.sync.listBlobs", map[string]string{"did": alice.did}, nil))
		cids, _ := listed.body["cids"].([]any)
		for _, c := range cids {
			if c == blobCid {
				t.Fatal("space-only blob listed by public sync")
			}
		}
		expectErr(t, spaceBlobsPublicGet(alice, blobCid), 400, "BlobNotFound")
	})

	t.Run("keeps a blob shared with a public record", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		blob, blobCid := spaceBlobsUpload(t, alice, []byte{7, 7, 7})
		mustOK(t, alice.post("com.atproto.repo.createRecord", map[string]any{
			"repo": alice.did, "collection": "app.bsky.actor.profile", "rkey": "self",
			"record": map[string]any{"$type": "app.bsky.actor.profile", "avatar": blob},
		}))
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "shared", record: spaceBlobsRecord("shared", blob)}))
		if res := spaceBlobsPublicGet(alice, blobCid); res.status != 200 {
			t.Fatalf("%d %s", res.status, res.raw)
		}

		// Deleting the public record must not strand the space record's bytes.
		mustOK(t, alice.post("com.atproto.repo.deleteRecord", map[string]any{
			"repo": alice.did, "collection": "app.bsky.actor.profile", "rkey": "self",
		}))
		if !spaceBlobsExists(t, alice, blobCid) {
			t.Fatal("public delete stranded the space record's blob")
		}
		if res := spaceBlobsPublicGet(alice, blobCid); res.status != 400 {
			t.Fatalf("%d %s", res.status, res.raw)
		}

		// Dropping the last (space) reference leaves nothing behind.
		mustOK(t, doDel(alice, sp, "", "shared"))
		if spaceBlobsExists(t, alice, blobCid) {
			t.Fatal("blob outlived its last reference")
		}
	})

	t.Run("drops the blobs of cleared records", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		blob, blobCid := spaceBlobsUpload(t, alice, []byte{3, 1, 3})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "cleared-blob", record: spaceBlobsRecord("cleared", blob)}))
		if !spaceBlobsExists(t, alice, blobCid) {
			t.Fatal("referenced blob was not stored")
		}
		other := createSpace(t, alice, spaceOpts{skey: "clear-blob-shared"})
		mustOK(t, doWrite(alice, other, writeOpts{rkey: "shared-blob", record: spaceBlobsRecord("shared", blob)}))
		mustOK(t, clearRecords(alice, sp))
		if !spaceBlobsExists(t, alice, blobCid) {
			t.Fatal("clearRecords deleted a blob still referenced by another space")
		}
		mustOK(t, clearRecords(alice, other))
		if spaceBlobsExists(t, alice, blobCid) {
			t.Fatal("clearRecords left the dropped record's blob behind")
		}
	})

	t.Run("lists the blobs of a repo to a syncer without since", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{carol}})
		first, firstCid := spaceBlobsUpload(t, alice, []byte{1})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "first", record: spaceBlobsRecord("first", first)}))
		second, secondCid := spaceBlobsUpload(t, alice, []byte{2})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "second", record: spaceBlobsRecord("second", second)}))
		cred := credentialFor(t, carol, pds1, sp)
		all := mustOK(t, cred.get(t, pds1, "com.atproto.space.listBlobs", map[string]string{
			"space": sp, "repo": alice.did,
		}))
		var got []string
		for _, value := range all.body["cids"].([]any) {
			cid, _ := value.(string)
			got = append(got, cid)
		}
		want := []string{firstCid, secondCid}
		sort.Strings(got)
		sort.Strings(want)
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("%v", got)
		}
	})

	t.Run("scopes listBlobs to one space", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blobs-scoped", members: []*actor{carol}})
		other := createSpace(t, alice, spaceOpts{skey: "blobs-scoped-other", members: []*actor{carol}})
		blob, _ := spaceBlobsUpload(t, alice, []byte{9, 9, 9})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "scoped-blob", record: spaceBlobsRecord("blob", blob)}))
		cred := credentialFor(t, carol, pds1, other)
		listed := mustOK(t, cred.get(t, pds1, "com.atproto.space.listBlobs", map[string]string{
			"space": other, "repo": alice.did,
		}))
		if cids, _ := listed.body["cids"].([]any); len(cids) != 0 {
			t.Fatalf("%s", listed.raw)
		}
	})

	t.Run("refuses a blob to a credential for another space", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blob-auth", members: []*actor{carol}})
		other := createSpace(t, alice, spaceOpts{skey: "blob-auth-other", members: []*actor{carol}})
		blob, blobCid := spaceBlobsUpload(t, alice, []byte{4, 2})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "guarded", record: spaceBlobsRecord("guarded", blob)}))
		wrong := credentialFor(t, carol, pds1, other)
		if got := spaceBlobsGet(t, wrong, pds1, sp, alice.did, blobCid); got.status < 400 {
			t.Fatalf("served with status %d", got.status)
		}
	})

	t.Run("refuses a blob that the authorized space does not reference", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blob-unrelated", members: []*actor{carol}})
		other := createSpace(t, alice, spaceOpts{skey: "blob-unrelated-other", members: []*actor{carol}})
		blob, blobCid := spaceBlobsUpload(t, alice, []byte{7, 7, 7})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "elsewhere", record: spaceBlobsRecord("elsewhere", blob)}))
		cred := credentialFor(t, carol, pds1, other)
		expectErr(t, spaceBlobsGet(t, cred, pds1, other, alice.did, blobCid), 400, "BlobNotFound")
	})

	t.Run("serves a blob the authorized space does reference", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blob-referenced", members: []*actor{carol}})
		blob, blobCid := spaceBlobsUpload(t, alice, []byte{1, 2, 3})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "referenced", record: spaceBlobsRecord("referenced", blob)}))
		cred := credentialFor(t, carol, pds1, sp)
		got := spaceBlobsGet(t, cred, pds1, sp, alice.did, blobCid)
		if got.status != 200 || !bytes.Equal(got.raw, []byte{1, 2, 3}) {
			t.Fatalf("%d %v", got.status, got.raw)
		}
	})
}
