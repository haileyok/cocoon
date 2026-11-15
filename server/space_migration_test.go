package server

// Ports packages/pds/tests/space/migration.test.ts (bluesky-social/atproto
// d4def6e9): moving an account's space data to a new host, on top of the usual
// account migration. Each space the account is the authority of moves as a
// space host archive (exportSpaceMeta -> importSpaceMeta), then each of its
// space repos moves as a STAR file (getRepo -> importRepo), then the blobs
// those repos reference.
//
// Cases that do not apply to Cocoon, and what stands in for them:
//
//   - createMigratedAccount: the reference asks its old PDS for a service-auth
//     token for com.atproto.server.createAccount and creates the same DID on
//     the new PDS with it. Cocoon's harness has no signed account creation
//     between PDSes, so migrationNewHost inserts the account on the new host
//     directly, with the migrating account's DID and keys, which is the state
//     the reference ends up in.
//   - the store reads the reference makes through actorStore (writers) become
//     spaceStore reads here, of the same rows.
//
// Two cases here have no counterpart in the reference suite, which is why they
// are written against the handlers instead:
//
//   - TestSpaceMigrationImportScopes: space-scope.test.ts unit-tests the
//     matcher and auth.test.ts drives the record methods, but no reference case
//     covers the scope checks the two import methods make (create per
//     collection for importRepo, manage=create and manage=update for
//     importSpaceMeta).
//   - 'without the STAR content type': the reference's xrpc layer enforces the
//     lexicon's encoding, while Cocoon checks the header in the handler.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
)

// migrationNewHost creates, on this PDS, the account a migrating actor becomes
// there: the same DID and keys, as account migration carries them, without a
// DID document pointing at this host until the migration completes.
func (p *spacePDS) migrationNewHost(t *testing.T, from *actor) *actor {
	t.Helper()
	ctx := context.Background()
	// A password the tests never use: nothing here signs in.
	repo := models.Repo{
		Did:           from.did,
		CreatedAt:     time.Now(),
		Email:         from.name + "@test2.invalid",
		Password:      "migrated",
		SigningKey:    from.key.Bytes(),
		KemKey:        from.kem.Bytes(),
		TwoFactorType: models.TwoFactorTypeNone,
	}
	if err := p.s.db.Create(ctx, &repo, nil).Error; err != nil {
		t.Fatalf("insert migrated repo: %v", err)
	}
	actorRow := models.Actor{Did: from.did, Handle: from.name + ".test2"}
	if err := p.s.db.Create(ctx, &actorRow, nil).Error; err != nil {
		t.Fatalf("insert migrated actor: %v", err)
	}
	if _, _, err := p.s.initializeGenesisRepo(ctx, from.did, from.key.Bytes()); err != nil {
		t.Fatalf("genesis repo on the new host: %v", err)
	}
	ra, err := p.s.getRepoActorByDid(ctx, from.did)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := p.s.createSession(ctx, &ra.Repo)
	if err != nil {
		t.Fatal(err)
	}
	return &actor{name: from.name + "2", did: from.did, pds: p, key: from.key, kem: from.kem, access: sess.AccessToken}
}

// migrationExportSpaceMeta reads a space's host-side state from a's PDS.
func migrationExportSpaceMeta(t *testing.T, a *actor, spaceURI string) []byte {
	t.Helper()
	res := mustOK(t, a.get("com.atproto.space.exportSpaceMeta", map[string]string{"space": spaceURI}))
	if ct := res.header.Get("Content-Type"); ct != starContentType {
		t.Fatalf("exportSpaceMeta Content-Type = %q, want %s", ct, starContentType)
	}
	return res.raw
}

// migrationImportSpaceMeta imports an archive on a's PDS.
func migrationImportSpaceMeta(t *testing.T, a *actor, archive []byte) xres {
	t.Helper()
	return migrationPostStar(t, a, "com.atproto.space.importSpaceMeta", archive)
}

// migrationGetRepo reads a's own repo in a space as a STAR archive.
func migrationGetRepo(t *testing.T, a *actor, spaceURI string) []byte {
	t.Helper()
	res := mustOK(t, a.get("com.atproto.space.getRepo", map[string]string{"space": spaceURI, "repo": a.did}))
	if ct := res.header.Get("Content-Type"); ct != starContentType {
		t.Fatalf("getRepo Content-Type = %q, want %s", ct, starContentType)
	}
	return res.raw
}

// migrationImportRepo imports a STAR repo archive on a's PDS.
func migrationImportRepo(t *testing.T, a *actor, star []byte) xres {
	t.Helper()
	return migrationPostStar(t, a, "com.atproto.space.importRepo", star)
}

// migrationPostStar posts an archive: the import methods take STAR, not JSON.
func migrationPostStar(t *testing.T, a *actor, nsid string, archive []byte) xres {
	t.Helper()
	h := map[string]string{"Content-Type": starContentType}
	if a.oauth == nil {
		for k, v := range a.auth() {
			h[k] = v
		}
		return a.pds.net.do(http.MethodPost, a.pds.url, nsid, nil, archive, h)
	}
	// As the harness's doOAuth, but with the STAR content type.
	htu := "https://" + a.pds.s.config.Hostname + "/xrpc/" + nsid
	var res xres
	for i := 0; i < 2; i++ {
		h["Authorization"] = "DPoP " + a.oauth.token
		h["DPoP"] = a.oauth.proof(t, http.MethodPost, htu)
		res = a.pds.net.do(http.MethodPost, a.pds.url, nsid, nil, archive, h)
		if n := res.header.Get("DPoP-Nonce"); n != "" {
			a.oauth.mu.Lock()
			a.oauth.nonce = n
			a.oauth.mu.Unlock()
		}
		if res.status != 401 || res.errName() != "use_dpop_nonce" {
			break
		}
	}
	return res
}

// migrationUploadBlob uploads data as a's blob, returning the blob object and
// its CID.
func migrationUploadBlob(t *testing.T, a *actor, data []byte) (map[string]any, string) {
	t.Helper()
	h := a.auth()
	h["Content-Type"] = "image/png"
	res := mustOK(t, a.pds.net.do(http.MethodPost, a.pds.url, "com.atproto.repo.uploadBlob", nil, data, h))
	blob, _ := res.body["blob"].(map[string]any)
	ref, _ := blob["ref"].(map[string]any)
	c, _ := ref["$link"].(string)
	if c == "" {
		t.Fatalf("uploadBlob returned no blob: %s", res.raw)
	}
	return blob, c
}

// migrationMoveBlobs copies every blob a's repo in the space references from
// one host to the other, as a migrating client does.
func migrationMoveBlobs(t *testing.T, from, to *actor, spaceURI string) {
	t.Helper()
	listed := mustOK(t, from.get("com.atproto.space.listBlobs", map[string]string{"space": spaceURI, "repo": from.did}))
	cids, _ := listed.body["cids"].([]any)
	for _, c := range cids {
		cid, _ := c.(string)
		blob := mustOK(t, from.get("com.atproto.space.getBlob", map[string]string{"space": spaceURI, "repo": from.did, "cid": cid}))
		h := to.auth()
		h["Content-Type"] = blob.header.Get("Content-Type")
		mustOK(t, to.pds.net.do(http.MethodPost, to.pds.url, "com.atproto.repo.uploadBlob", nil, blob.raw, h))
	}
}

// migrationWriters reads a space's writer set from a's PDS, as the reference's
// store read does.
func migrationWriters(t *testing.T, a *actor, spaceURI string) []models.SpaceWriter {
	t.Helper()
	rows, err := a.pds.s.spaceStore(nil, a.did).listWriters(spaceURI, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// migrationLatestCommit reads the latest commit of a's own repo in a space.
func migrationLatestCommit(t *testing.T, a *actor, spaceURI string) space.Commit {
	t.Helper()
	res := mustOK(t, a.get("com.atproto.space.getLatestCommit", map[string]string{"space": spaceURI, "repo": a.did}))
	var out struct {
		Commit space.Commit `json:"commit"`
	}
	if err := json.Unmarshal(res.raw, &out); err != nil {
		t.Fatalf("decode commit: %v (%s)", err, res.raw)
	}
	return out.Commit
}

// migrationRecords lists a's records in a space.
func migrationRecords(t *testing.T, a *actor, spaceURI string) []map[string]any {
	t.Helper()
	return mustOK(t, a.get("com.atproto.space.listRecords", map[string]string{"space": spaceURI, "repo": a.did})).list("records")
}

// migrationStar builds a STAR archive by hand, for the malformed ones.
func migrationStar(t *testing.T, meta map[string]any, pairs [][2][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	sw, err := space.WriteStar(&buf, meta)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pairs {
		if err := sw.WritePair(p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// migrationSpaceMetaMeta is a well-formed space meta archive's metadata.
func migrationSpaceMetaMeta(spaceURI string) map[string]any {
	return map[string]any{"$type": space.SpaceMetaStarType, "ver": int64(space.SpaceMetaVersion), "space": spaceURI}
}

// migrationCBOR encodes a map as a STAR pair value.
func migrationCBOR(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := atdata.MarshalCBOR(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// migrationCBORText is the DAG-CBOR encoding of a string.
func migrationCBORText(s string) []byte {
	n := len(s)
	switch {
	case n < 24:
		return append([]byte{0x60 | byte(n)}, s...)
	case n < 1<<8:
		return append([]byte{0x78, byte(n)}, s...)
	default:
		return append([]byte{0x79, byte(n >> 8), byte(n)}, s...)
	}
}

// migrationSpaceMeta writes a space meta archive the exporter would not: the
// archive a case here wants to be rejected.
func migrationSpaceMeta(t *testing.T, spaceURI string, policy map[string]any, state []space.PolicyStateEntry, writers []space.SpaceMetaWriter) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := space.WriteSpaceMetaStar(&buf, space.SpaceMetaArchive{
		Space: spaceURI, Policy: policy, PolicyState: state, Writers: writers,
	}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSpaceMigrationMovesAuthoritySpacesAndRepos ports 'moves the spaces an
// account is the authority of, and its repos'.
func TestSpaceMigrationMovesAuthoritySpacesAndRepos(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	bob := pds1.createActor("bob")
	dan := pds1.createActor("dan")
	newAlice := pds2.migrationNewHost(t, alice)

	spaceURI := createSpace(t, alice, spaceOpts{
		policy: memberPolicy(map[string]any{"publishPolicy": true, "publishMembers": true}),
	})
	putMember(t, alice, spaceURI, bob, true, true)
	putMember(t, alice, spaceURI, dan, true, false)
	mustOK(t, doWrite(bob, spaceURI, writeOpts{rkey: "from-bob"}))

	blobData := []byte{1, 2, 3, 4}
	blob, blobCid := migrationUploadBlob(t, alice, blobData)
	mustOK(t, doWrite(alice, spaceURI, writeOpts{rkey: "from-alice", record: map[string]any{
		"$type": testCollection, "text": "with a blob", "image": blob,
	}}))

	// A space under another authority, which only alice's repo moves out of.
	guest := createSpace(t, bob, spaceOpts{skey: "guest", members: []*actor{alice}})
	mustOK(t, doWrite(alice, guest, writeOpts{rkey: "guest"}))

	listed := mustOK(t, alice.get("com.atproto.space.listSpaces", nil)).list("spaces")
	seen := map[string]bool{}
	for _, s := range listed {
		seen[s["space"].(string)] = true
	}
	if !seen[spaceURI] || !seen[guest] {
		t.Fatalf("listSpaces on the old host does not carry both spaces: %v", listed)
	}

	original := migrationExportSpaceMeta(t, alice, spaceURI)
	originalWriters := migrationWriters(t, alice, spaceURI)
	originalCommit := migrationLatestCommit(t, alice, spaceURI)
	guestCommit := migrationLatestCommit(t, alice, guest)
	originalRecords := migrationRecords(t, alice, spaceURI)

	// Step 2 and 3 of the flow: the space the account is the authority of comes
	// before the account's own repo in it.
	mustOK(t, migrationImportSpaceMeta(t, newAlice, original))
	mustOK(t, migrationImportRepo(t, newAlice, migrationGetRepo(t, alice, spaceURI)))
	migrationMoveBlobs(t, alice, newAlice, spaceURI)
	mustOK(t, migrationImportRepo(t, newAlice, migrationGetRepo(t, alice, guest)))
	migrationMoveBlobs(t, alice, newAlice, guest)

	// The policy and member list arrive intact.
	parsed, err := space.ReadSpaceMetaStar(bytes.NewReader(original))
	if err != nil {
		t.Fatalf("read the old host's archive: %v", err)
	}
	got := mustOK(t, newAlice.get("com.atproto.space.getSpace", map[string]string{"space": spaceURI}))
	if !reflect.DeepEqual(got.body["policy"], parsed.Policy) {
		t.Fatalf("policy on the new host = %v, want %v", got.body["policy"], parsed.Policy)
	}
	members := mustOK(t, newAlice.get("com.atproto.memberspace.listMembers", map[string]string{"space": spaceURI})).list("members")
	sort.Slice(members, func(i, j int) bool { return members[i]["did"].(string) < members[j]["did"].(string) })
	wantMembers := []map[string]any{
		{"did": bob.did, "read": true, "write": true},
		{"did": dan.did, "read": true, "write": false},
	}
	sort.Slice(wantMembers, func(i, j int) bool { return wantMembers[i]["did"].(string) < wantMembers[j]["did"].(string) })
	if !reflect.DeepEqual(members, wantMembers) {
		t.Fatalf("members on the new host = %v, want %v", members, wantMembers)
	}

	// The writer set, the authority included, keeps its place in the space
	// sequence.
	var originalDIDs []string
	for _, w := range originalWriters {
		originalDIDs = append(originalDIDs, w.WriterDid)
	}
	sort.Strings(originalDIDs)
	wantDIDs := []string{alice.did, bob.did}
	sort.Strings(wantDIDs)
	if !reflect.DeepEqual(originalDIDs, wantDIDs) {
		t.Fatalf("old host writer set = %v, want %v", originalDIDs, wantDIDs)
	}
	if gotWriters := migrationWriters(t, newAlice, spaceURI); !reflect.DeepEqual(gotWriters, originalWriters) {
		t.Fatalf("writer set on the new host = %+v, want %+v", gotWriters, originalWriters)
	}

	// The revisions are the space sequence's own, so a syncer's cursor still
	// lands where it did on the old host.
	cred := credentialFor(t, bob, pds2, spaceURI)
	page := mustOK(t, cred.get(t, pds2, "com.atproto.space.listWriters", map[string]string{"space": spaceURI, "limit": "1"}))
	if repos := page.list("repos"); len(repos) != 1 || repos[0]["spaceRev"] != originalWriters[0].SpaceRev {
		t.Fatalf("first page of listWriters = %v, want the writer at %s", page.body, originalWriters[0].SpaceRev)
	}
	rest := mustOK(t, cred.get(t, pds2, "com.atproto.space.listWriters", map[string]string{"space": spaceURI, "limit": "1", "cursor": page.str("cursor")}))
	if repos := rest.list("repos"); len(repos) != 1 || repos[0]["spaceRev"] != originalWriters[1].SpaceRev {
		t.Fatalf("second page of listWriters = %v, want the writer at %s", rest.body, originalWriters[1].SpaceRev)
	}

	// Re-exported from the new host, the space is unchanged.
	if reexported := migrationExportSpaceMeta(t, newAlice, spaceURI); !bytes.Equal(reexported, original) {
		t.Fatalf("re-exported archive differs from the original:\n%x\n%x", reexported, original)
	}

	// The repo holds the same records, so the same commit data under a new rev.
	newCommit := migrationLatestCommit(t, newAlice, spaceURI)
	if !bytes.Equal(newCommit.Data, originalCommit.Data) {
		t.Fatalf("commit data on the new host = %x, want %x", newCommit.Data, originalCommit.Data)
	}
	if !(newCommit.Rev > originalCommit.Rev) {
		t.Fatalf("new host rev %s is not after %s", newCommit.Rev, originalCommit.Rev)
	}
	if newRecords := migrationRecords(t, newAlice, spaceURI); !reflect.DeepEqual(newRecords, originalRecords) {
		t.Fatalf("records on the new host = %v, want %v", newRecords, originalRecords)
	}

	// The blob was uploaded after its record arrived, and is served with it.
	gotBlob := mustOK(t, newAlice.get("com.atproto.space.getBlob", map[string]string{"space": spaceURI, "repo": alice.did, "cid": blobCid}))
	if !bytes.Equal(gotBlob.raw, blobData) {
		t.Fatalf("served blob = %v, want %v", gotBlob.raw, blobData)
	}

	if guestNew := migrationLatestCommit(t, newAlice, guest); !bytes.Equal(guestNew.Data, guestCommit.Data) {
		t.Fatalf("guest space commit data on the new host = %x, want %x", guestNew.Data, guestCommit.Data)
	}
}

// TestSpaceMigrationLeavesRemovedWriterOutOfArchive ports 'leaves a removed
// writer out of the archive'.
func TestSpaceMigrationLeavesRemovedWriterOutOfArchive(t *testing.T) {
	n := newSpaceNet(t)
	pds := n.newPDS()
	alice := pds.createActor("alice")
	bob := pds.createActor("bob")

	spaceURI := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
	mustOK(t, doWrite(bob, spaceURI, writeOpts{}))
	mustOK(t, removeWriter(alice, spaceURI, bob))

	if rows := migrationWriters(t, alice, spaceURI); len(rows) != 1 || rows[0].WriterDid != bob.did || rows[0].RemovedAt == nil {
		t.Fatalf("expected bob's removed writer row, got %+v", rows)
	}
	archive, err := space.ReadSpaceMetaStar(bytes.NewReader(migrationExportSpaceMeta(t, alice, spaceURI)))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Writers) != 0 {
		t.Fatalf("archive carries a removed writer: %+v", archive.Writers)
	}
}

// TestSpaceMigrationRequiresSpaceBeforeAuthorityRepo ports "requires the space
// before the authority's own repo in it".
func TestSpaceMigrationRequiresSpaceBeforeAuthorityRepo(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	newAlice := pds2.migrationNewHost(t, alice)

	spaceURI := createSpace(t, alice, spaceOpts{policy: personalPolicy()})
	mustOK(t, doWrite(alice, spaceURI, writeOpts{}))

	star := migrationGetRepo(t, alice, spaceURI)
	expectErr(t, migrationImportRepo(t, newAlice, star), 400, "SpaceNotFound")

	// The space has to arrive first: importRepo answers SpaceNotFound for a
	// space this host does not have, since a repo may not conjure one.
	mustOK(t, migrationImportSpaceMeta(t, newAlice, migrationExportSpaceMeta(t, alice, spaceURI)))
	mustOK(t, migrationImportRepo(t, newAlice, star))
	newCommit := migrationLatestCommit(t, newAlice, spaceURI)
	if old := migrationLatestCommit(t, alice, spaceURI); !bytes.Equal(newCommit.Data, old.Data) {
		t.Fatalf("commit data on the new host = %x, want %x", newCommit.Data, old.Data)
	}
}

// TestSpaceMigrationReplacesNewHostState ports 'replaces what the new host
// holds when imported again'.
func TestSpaceMigrationReplacesNewHostState(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	bob := pds1.createActor("bob")
	newAlice := pds2.migrationNewHost(t, alice)

	spaceURI := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
	mustOK(t, doWrite(alice, spaceURI, writeOpts{rkey: "kept"}))
	mustOK(t, doWrite(alice, spaceURI, writeOpts{rkey: "deleted"}))
	mustOK(t, migrationImportSpaceMeta(t, newAlice, migrationExportSpaceMeta(t, alice, spaceURI)))
	mustOK(t, migrationImportRepo(t, newAlice, migrationGetRepo(t, alice, spaceURI)))

	// A record the new host holds that the old host never had, along with its
	// op.
	ref, err := space.ParseRef(spaceURI)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := space.SerializeRecord(testCollection, "stale", testRecord(testCollection, "stale"))
	if err != nil {
		t.Fatal(err)
	}
	st := pds2.s.spaceStore(nil, alice.did)
	if _, err := st.applyWrites(ref, []spaceWrite{{
		Action: "create", Collection: testCollection, Rkey: "stale",
		Uri: ref.RecordURI(alice.did, testCollection, "stale"), Record: &sr,
	}}); err != nil {
		t.Fatalf("write a record on the new host: %v", err)
	}
	ops := mustOK(t, newAlice.get("com.atproto.space.listRepoOps", map[string]string{"space": spaceURI, "repo": alice.did})).list("ops")
	if len(ops) == 0 {
		t.Fatal("expected the new host to hold an op before the second import")
	}

	mustOK(t, doDel(alice, spaceURI, testCollection, "deleted"))
	mustOK(t, doWrite(alice, spaceURI, writeOpts{rkey: "added"}))
	removeMember(t, alice, spaceURI, bob)

	mustOK(t, migrationImportSpaceMeta(t, newAlice, migrationExportSpaceMeta(t, alice, spaceURI)))
	mustOK(t, migrationImportRepo(t, newAlice, migrationGetRepo(t, alice, spaceURI)))

	original := migrationExportSpaceMeta(t, alice, spaceURI)
	if reexported := migrationExportSpaceMeta(t, newAlice, spaceURI); !bytes.Equal(reexported, original) {
		t.Fatalf("the new host's archive differs from the old host's:\n%x\n%x", reexported, original)
	}
	if got, want := migrationLatestCommit(t, newAlice, spaceURI), migrationLatestCommit(t, alice, spaceURI); !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("commit data on the new host = %x, want %x", got.Data, want.Data)
	}
	if ops := mustOK(t, newAlice.get("com.atproto.space.listRepoOps", map[string]string{"space": spaceURI, "repo": alice.did})).list("ops"); len(ops) != 0 {
		t.Fatalf("ops survived the import: %v", ops)
	}
}

// TestSpaceMigrationKeepsEncodedDidWebMember ports "keeps the percent-encoded
// port of a did:web member's DID".
func TestSpaceMigrationKeepsEncodedDidWebMember(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	newAlice := pds2.migrationNewHost(t, alice)

	spaceURI := createSpace(t, alice, spaceOpts{})
	const did = "did:web:localhost%3A2583"
	mustOK(t, alice.post("com.atproto.memberspace.putMembers", map[string]any{
		"space": spaceURI, "members": []map[string]any{{"did": did, "read": true, "write": true}},
	}))
	mustOK(t, migrationImportSpaceMeta(t, newAlice, migrationExportSpaceMeta(t, alice, spaceURI)))

	members := mustOK(t, newAlice.get("com.atproto.memberspace.listMembers", map[string]string{"space": spaceURI})).list("members")
	want := []map[string]any{{"did": did, "read": true, "write": true}}
	if !reflect.DeepEqual(members, want) {
		t.Fatalf("members on the new host = %v, want %v", members, want)
	}
}

// TestSpaceMigrationRejectsNonCanonicalRecord ports 'rejects a repo with a
// record that is not canonical DRISL'.
func TestSpaceMigrationRejectsNonCanonicalRecord(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	bob := pds1.createActor("bob")
	newAlice := pds2.migrationNewHost(t, alice)

	// DRISL orders map keys by length first, so `text` belongs before `$type`;
	// this map puts `$type` first.
	rec := bytes.Join([][]byte{
		{0xa2},
		migrationCBORText("$type"), migrationCBORText(testCollection),
		migrationCBORText("text"), migrationCBORText("out of order"),
	}, nil)
	const rkey = "non-canonical"
	spaceURI := space.Ref{Authority: bob.did, Type: testSpaceType, Skey: "non-canonical"}.String()
	commit := space.RepoCommitFromRecords(nil).Add(testCollection, rkey, space.CidForCBOR(rec)).
		ToCommit(space.CommitCtx{Space: spaceURI, Repo: alice.did, Rev: nextTID("")})

	var buf bytes.Buffer
	if err := space.SerializeRepo(&buf, commit, []space.SerializedRecord{{
		Collection: testCollection, Rkey: rkey, Cid: space.CidForCBOR(rec), Bytes: rec,
	}}); err != nil {
		t.Fatal(err)
	}
	res := migrationImportRepo(t, newAlice, buf.Bytes())
	expectErr(t, res, 400, "InvalidRepoFile")
	if !bytes.Contains([]byte(res.message()), []byte("not canonical DRISL")) {
		t.Fatalf("message = %q, want it to name canonical DRISL", res.message())
	}
}

// migrationStarWriter is a well-formed writer entry's value.
func migrationStarWriter(t *testing.T) []byte {
	t.Helper()
	rev := nextTID("")
	return migrationCBOR(t, map[string]any{"repoRev": rev, "data": atdata.Bytes{1}, "spaceRev": rev})
}

// minMax returns two strings in sorted order.
func minMax(a, b string) (string, string) {
	if a < b {
		return a, b
	}
	return b, a
}

// TestSpaceMigrationImportsOnlyOwnSpaces ports "imports only the account's own
// spaces and repos".
func TestSpaceMigrationImportsOnlyOwnSpaces(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	bob := pds1.createActor("bob")
	newAlice := pds2.migrationNewHost(t, alice)

	spaceURI := createSpace(t, bob, spaceOpts{members: []*actor{alice}})
	mustOK(t, doWrite(bob, spaceURI, writeOpts{}))

	expectErr(t, migrationImportSpaceMeta(t, newAlice, migrationExportSpaceMeta(t, bob, spaceURI)), 400, "NotAuthorized")
	expectErr(t, migrationImportRepo(t, newAlice, migrationGetRepo(t, bob, spaceURI)), 400, "RepoMismatch")
}

// TestSpaceMigrationRejectsArchive ports the 'rejects an archive' cases.
func TestSpaceMigrationRejectsArchive(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	bob := pds1.createActor("bob")
	newAlice := pds2.migrationNewHost(t, alice)

	archiveFor := func(skey string) string {
		return space.Ref{Authority: alice.did, Type: testSpaceType, Skey: skey}.String()
	}
	state := func(key string, value map[string]any) []space.PolicyStateEntry {
		return []space.PolicyStateEntry{{Key: key, Value: value}}
	}

	t.Run("with a policy the host does not implement", func(t *testing.T) {
		archive := migrationSpaceMeta(t, archiveFor("unsupported"), map[string]any{"$type": "com.example.policy"}, nil, nil)
		expectErr(t, migrationImportSpaceMeta(t, newAlice, archive), 400, "UnsupportedPolicy")
	})

	t.Run("with policy state the policy does not define", func(t *testing.T) {
		archive := migrationSpaceMeta(t, archiveFor("unrecognized-state"), memberPolicy(nil),
			state("com.example.allowList/"+bob.did, map[string]any{"$type": "com.example.allowList"}), nil)
		res := migrationImportSpaceMeta(t, newAlice, archive)
		expectErr(t, res, 400, "InvalidSpaceMeta")
		if !bytes.Contains([]byte(res.message()), []byte("Unrecognized policy state")) {
			t.Fatalf("message = %q", res.message())
		}
	})

	t.Run("with a member list for a policy that keeps none", func(t *testing.T) {
		archive := migrationSpaceMeta(t, archiveFor("personal-members"), personalPolicy(),
			state(collMember+"/"+bob.did, map[string]any{"$type": collMember, "read": true, "write": true}), nil)
		res := migrationImportSpaceMeta(t, newAlice, archive)
		expectErr(t, res, 400, "InvalidSpaceMeta")
		if !bytes.Contains([]byte(res.message()), []byte("Unrecognized policy state")) {
			t.Fatalf("message = %q", res.message())
		}
	})

	t.Run("that does not parse", func(t *testing.T) {
		expectErr(t, migrationImportSpaceMeta(t, newAlice, []byte{1, 2, 3}), 400, "InvalidSpaceMeta")
	})

	t.Run("with keys out of order", func(t *testing.T) {
		// The exporter writes the sections in order, so a policy state entry
		// after the writer entries is not an archive it could have written.
		meta := migrationSpaceMetaMeta(archiveFor("out-of-order"))
		archive := migrationStar(t, meta, [][2][]byte{
			{[]byte("policy"), migrationCBOR(t, memberPolicy(nil))},
			{[]byte("writer/" + bob.did), migrationStarWriter(t)},
			{[]byte(collMember + "/" + bob.did), migrationCBOR(t, map[string]any{"$type": collMember, "read": true, "write": true})},
		})
		res := migrationImportSpaceMeta(t, newAlice, archive)
		expectErr(t, res, 400, "InvalidSpaceMeta")
		if !bytes.Contains([]byte(res.message()), []byte("section out of order")) {
			t.Fatalf("message = %q", res.message())
		}
	})

	t.Run("with two keys out of order within a section", func(t *testing.T) {
		// The exporter sorts the writer entries, so the one that sorts second
		// may not come first.
		first, second := minMax(alice.did, bob.did)
		meta := migrationSpaceMetaMeta(archiveFor("duplicate-keys"))
		archive := migrationStar(t, meta, [][2][]byte{
			{[]byte("policy"), migrationCBOR(t, memberPolicy(nil))},
			{[]byte("writer/" + second), migrationStarWriter(t)},
			{[]byte("writer/" + first), migrationStarWriter(t)},
		})
		res := migrationImportSpaceMeta(t, newAlice, archive)
		expectErr(t, res, 400, "InvalidSpaceMeta")
		if !bytes.Contains([]byte(res.message()), []byte("out-of-order key")) {
			t.Fatalf("message = %q", res.message())
		}
	})

	t.Run("with the rev key of the pre-November archives", func(t *testing.T) {
		// Before the protocol renamed the writer entry's repoRev to repoRev the
		// archive carried `rev`; a host may not read that as the space revision
		// or drop it.
		rev := nextTID("")
		meta := migrationSpaceMetaMeta(archiveFor("old-rev-key"))
		archive := migrationStar(t, meta, [][2][]byte{
			{[]byte("policy"), migrationCBOR(t, memberPolicy(nil))},
			{[]byte("writer/" + bob.did), migrationCBOR(t, map[string]any{"rev": rev, "data": atdata.Bytes{1}, "spaceRev": rev})},
		})
		res := migrationImportSpaceMeta(t, newAlice, archive)
		expectErr(t, res, 400, "InvalidSpaceMeta")
		if !bytes.Contains([]byte(res.message()), []byte(`unexpected property "rev"`)) {
			t.Fatalf("message = %q", res.message())
		}
	})

	t.Run("without the space meta type", func(t *testing.T) {
		meta := map[string]any{"$type": "atproto-space-repo", "ver": int64(1), "space": archiveFor("wrong-type")}
		archive := migrationStar(t, meta, [][2][]byte{{[]byte("policy"), migrationCBOR(t, memberPolicy(nil))}})
		expectErr(t, migrationImportSpaceMeta(t, newAlice, archive), 400, "InvalidSpaceMeta")
	})

	t.Run("without the STAR content type", func(t *testing.T) {
		archive := migrationExportSpaceMeta(t, alice, createSpace(t, alice, spaceOpts{skey: "content-type"}))
		res := alice.pds.net.do(http.MethodPost, alice.pds.url, "com.atproto.space.importSpaceMeta", nil, archive, alice.auth())
		expectErr(t, res, 400, "InvalidRequest")
	})
}

// TestSpaceMigrationImportScopes covers the OAuth grants the two import methods
// require: create on every collection the archive carries, and both
// manage=create and manage=update for the space's own archive.
func TestSpaceMigrationImportScopes(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	newAlice := pds2.migrationNewHost(t, alice)

	spaceURI := createSpace(t, alice, spaceOpts{})
	mustOK(t, doWrite(alice, spaceURI, writeOpts{collection: testCollection, rkey: "one"}))
	mustOK(t, doWrite(alice, spaceURI, writeOpts{collection: testCollectionAlt, rkey: "two"}))
	meta := migrationExportSpaceMeta(t, alice, spaceURI)
	repo := migrationGetRepo(t, alice, spaceURI)

	scoped := func(scope string) *actor {
		a := *newAlice
		a.oauth = pds2.newOAuthSession(newAlice, scope)
		return &a
	}
	grant := func(params string) string {
		return fmt.Sprintf("atproto space:%s?authority=%s&%s", testSpaceType, alice.did, params)
	}
	collections := "collection=" + testCollection + "&collection=" + testCollectionAlt + "&action=create"

	// importSpaceMeta asks for manage=create and manage=update, since it both
	// creates the space here and sets its configuration.
	onlyCreate := scoped(grant(collections + "&manage=create"))
	res := migrationImportSpaceMeta(t, onlyCreate, meta)
	expectErr(t, res, 403, "InsufficientScope")
	if !bytes.Contains([]byte(res.message()), []byte("manage=update")) {
		t.Fatalf("message = %q, want it to name manage=update", res.message())
	}

	// importRepo asks for create on every collection the archive carries.
	oneCollection := scoped(grant("collection=" + testCollection + "&action=create&manage=create&manage=update"))
	mustOK(t, migrationImportSpaceMeta(t, oneCollection, meta))
	res = migrationImportRepo(t, oneCollection, repo)
	expectErr(t, res, 403, "InsufficientScope")
	if !bytes.Contains([]byte(res.message()), []byte(testCollectionAlt)) {
		t.Fatalf("message = %q, want it to name %s", res.message(), testCollectionAlt)
	}

	// A grant that names an action but no collection confers no write targets at
	// all, so importRepo cannot be covered by one.
	noCollection := scoped(grant("action=create&manage=create&manage=update"))
	mustOK(t, migrationImportSpaceMeta(t, noCollection, meta))
	expectErr(t, migrationImportRepo(t, noCollection, repo), 403, "InsufficientScope")

	// The whole grant covers both.
	both := scoped(grant(collections + "&manage=create&manage=update"))
	mustOK(t, migrationImportSpaceMeta(t, both, meta))
	mustOK(t, migrationImportRepo(t, both, repo))
}
