package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"testing"
)

// Ported from the blob cases of packages/pds/tests/space/records.test.ts
// (bluesky-social/atproto 5b95b2f2).

// spaceUploadBlob uploads bytes as a's blob, returning the blob ref and its CID.
func spaceUploadBlob(t *testing.T, a *actor, data []byte) (map[string]any, string) {
	t.Helper()
	h := a.auth()
	h["Content-Type"] = "image/png"
	res := mustOK(t, a.pds.net.do(http.MethodPost, a.pds.url, "com.atproto.repo.uploadBlob", nil, data, h))
	blob, _ := res.body["blob"].(map[string]any)
	ref, _ := blob["ref"].(map[string]any)
	c, _ := ref["$link"].(string)
	if c == "" {
		t.Fatalf("no blob cid: %s", res.raw)
	}
	return blob, c
}

func spaceBlobRecord(text string, blob map[string]any) map[string]any {
	return map[string]any{"$type": testCollection, "text": text, "image": blob}
}

func spaceBlobGet(t *testing.T, c *spaceCredential, p *spacePDS, sp, repo, blobCid string) (int, []byte, xres) {
	t.Helper()
	res := c.get(t, p, "com.atproto.space.getBlob", map[string]string{"space": sp, "repo": repo, "cid": blobCid})
	return res.status, res.raw, res
}

func spaceBlobExists(t *testing.T, a *actor, blobCid string) bool {
	t.Helper()
	c := mustCid(t, blobCid)
	_, found, err := a.pds.s.readBlobBytes(context.Background(), a.did, c)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func publicGetBlob(t *testing.T, a *actor, blobCid string) xres {
	t.Helper()
	return a.pds.get("com.atproto.sync.getBlob", map[string]string{"did": a.did, "cid": blobCid}, nil)
}

func TestSpaceRecordsBlobs(t *testing.T) {
	r := newRecordsNet(t)
	alice, carol := r.alice, r.carol

	t.Run("tracks a blob on a space record and serves it to a member", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{carol}})
		data := []byte{1, 2, 3, 4, 5}
		blob, blobCid := spaceUploadBlob(t, alice, data)
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "with-blob", record: spaceBlobRecord("has a blob", blob)}))
		if !spaceBlobExists(t, alice, blobCid) {
			t.Fatal("blob bytes not stored")
		}
		cred := credentialFor(t, carol, r.pds1, sp)
		listed := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listBlobs", map[string]string{"space": sp, "repo": alice.did}))
		cids, _ := listed.body["cids"].([]any)
		if len(cids) != 1 || cids[0] != blobCid {
			t.Fatalf("%s", listed.raw)
		}
		status, raw, _ := spaceBlobGet(t, cred, r.pds1, sp, alice.did, blobCid)
		if status != 200 || !bytes.Equal(raw, data) {
			t.Fatalf("%d %v", status, raw)
		}
	})

	t.Run("does not serve a space-only blob through public sync", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		blob, blobCid := spaceUploadBlob(t, alice, []byte{5, 4, 3, 2, 1})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "private-blob", record: spaceBlobRecord("private", blob)}))
		listed := mustOK(t, alice.pds.get("com.atproto.sync.listBlobs", map[string]string{"did": alice.did}, nil))
		cids, _ := listed.body["cids"].([]any)
		for _, c := range cids {
			if c == blobCid {
				t.Fatal("space-only blob listed by public sync")
			}
		}
		expectErr(t, publicGetBlob(t, alice, blobCid), 400, "BlobNotFound")
	})

	t.Run("keeps a blob shared with a public record", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		blob, blobCid := spaceUploadBlob(t, alice, []byte{7, 7, 7})
		mustOK(t, alice.post("com.atproto.repo.createRecord", map[string]any{
			"repo": alice.did, "collection": "app.bsky.actor.profile", "rkey": "self",
			"record": map[string]any{"$type": "app.bsky.actor.profile", "avatar": blob},
		}))
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "shared", record: spaceBlobRecord("shared", blob)}))
		if res := publicGetBlob(t, alice, blobCid); res.status != 200 {
			t.Fatalf("%d %s", res.status, res.raw)
		}
		// Deleting the public record must not strand the space record's bytes.
		mustOK(t, alice.post("com.atproto.repo.deleteRecord", map[string]any{"repo": alice.did, "collection": "app.bsky.actor.profile", "rkey": "self"}))
		if !spaceBlobExists(t, alice, blobCid) {
			t.Fatal("public delete stranded the space record's blob")
		}
		if res := publicGetBlob(t, alice, blobCid); res.status != 400 {
			t.Fatalf("%d %s", res.status, res.raw)
		}
		// And the reverse: dropping the space record leaves nothing behind.
		mustOK(t, doDel(alice, sp, "", "shared"))
		if spaceBlobExists(t, alice, blobCid) {
			t.Fatal("blob outlived its last reference")
		}
	})

	t.Run("filters listBlobs by revision", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{carol}})
		first, firstCid := spaceUploadBlob(t, alice, []byte{1})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "first", record: spaceBlobRecord("first", first)}))
		midRev := *repoState(t, alice, sp).Rev
		second, secondCid := spaceUploadBlob(t, alice, []byte{2})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "second", record: spaceBlobRecord("second", second)}))
		cred := credentialFor(t, carol, r.pds1, sp)
		all := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listBlobs", map[string]string{"space": sp, "repo": alice.did}))
		got := []string{}
		for _, c := range all.body["cids"].([]any) {
			got = append(got, c.(string))
		}
		want := []string{firstCid, secondCid}
		sort.Strings(got)
		sort.Strings(want)
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("%v", got)
		}
		since := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listBlobs", map[string]string{"space": sp, "repo": alice.did, "since": midRev}))
		sc, _ := since.body["cids"].([]any)
		if len(sc) != 1 || sc[0] != secondCid {
			t.Fatalf("%s", since.raw)
		}
	})

	t.Run("scopes listBlobs to one space", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blobs-scoped", members: []*actor{carol}})
		other := createSpace(t, alice, spaceOpts{skey: "blobs-scoped-other", members: []*actor{carol}})
		blob, _ := spaceUploadBlob(t, alice, []byte{9, 9, 9})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "scoped-blob", record: spaceBlobRecord("blob", blob)}))
		cred := credentialFor(t, carol, r.pds1, other)
		listed := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listBlobs", map[string]string{"space": other, "repo": alice.did}))
		if cids, _ := listed.body["cids"].([]any); len(cids) != 0 {
			t.Fatalf("%s", listed.raw)
		}
	})

	t.Run("refuses a blob to a credential for another space", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blob-auth", members: []*actor{carol}})
		other := createSpace(t, alice, spaceOpts{skey: "blob-auth-other", members: []*actor{carol}})
		blob, blobCid := spaceUploadBlob(t, alice, []byte{4, 2})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "guarded", record: spaceBlobRecord("guarded", blob)}))
		wrong := credentialFor(t, carol, r.pds1, other)
		if status, _, _ := spaceBlobGet(t, wrong, r.pds1, sp, alice.did, blobCid); status < 400 {
			t.Fatalf("served with status %d", status)
		}
	})

	t.Run("refuses a blob that the authorized space does not reference", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blob-unrelated", members: []*actor{carol}})
		other := createSpace(t, alice, spaceOpts{skey: "blob-unrelated-other", members: []*actor{carol}})
		blob, blobCid := spaceUploadBlob(t, alice, []byte{7, 7, 7})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "elsewhere", record: spaceBlobRecord("elsewhere", blob)}))
		cred := credentialFor(t, carol, r.pds1, other)
		_, _, res := spaceBlobGet(t, cred, r.pds1, other, alice.did, blobCid)
		expectErr(t, res, 400, "BlobNotFound")
	})

	t.Run("serves a blob the authorized space does reference", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "blob-referenced", members: []*actor{carol}})
		blob, blobCid := spaceUploadBlob(t, alice, []byte{1, 2, 3})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "referenced", record: spaceBlobRecord("referenced", blob)}))
		cred := credentialFor(t, carol, r.pds1, sp)
		status, raw, _ := spaceBlobGet(t, cred, r.pds1, sp, alice.did, blobCid)
		if status != 200 || !bytes.Equal(raw, []byte{1, 2, 3}) {
			t.Fatalf("%d %v", status, raw)
		}
	})
}

var _ = io.EOF
