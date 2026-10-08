package server

// Ported from packages/pds/tests/space/simplespace.test.ts (bluesky-social/
// atproto @ 5b95b2f2): the com.atproto.simplespace policy layer — lifecycle,
// members, config, credential mint gates (client attestation, managing-app
// policy), notify registration, and deletion.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type simplespaceNet struct {
	net                    *spaceNet
	pds1, pds2, pds3       *spacePDS
	alice, dan, bob, carol *actor
}

func newSimplespaceNet(t *testing.T) *simplespaceNet {
	t.Helper()
	n := newSpaceNet(t)
	r := &simplespaceNet{net: n, pds1: n.newPDS(), pds2: n.newPDS(), pds3: n.newPDS()}
	r.alice = r.pds1.createActor("alice") // authority, on pds1
	r.dan = r.pds1.createActor("dan")     // co-located with the authority
	r.bob = r.pds2.createActor("bob")     // on pds2
	r.carol = r.pds3.createActor("carol") // on pds3
	return r
}

// ---- simplespace helpers -------------------------------------------------

// simplespaceJSON renders a body for failure messages.
func simplespaceJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// simplespaceGetConfig reads a space's config as its owner.
func simplespaceGetConfig(t *testing.T, a *actor, sp string) map[string]any {
	t.Helper()
	return mustOK(t, a.get("com.atproto.simplespace.getSpace", map[string]string{"space": sp})).body
}

// simplespaceUnion returns a config body's readPolicy, writePolicy or
// appAccess union.
func simplespaceUnion(t *testing.T, body map[string]any, k string) map[string]any {
	t.Helper()
	v, _ := body[k].(map[string]any)
	if v == nil {
		t.Fatalf("missing %s in %s", k, simplespaceJSON(t, body))
	}
	return v
}

// simplespaceAllowed returns an appAccess allowList's entries.
func simplespaceAllowed(t *testing.T, body map[string]any) []string {
	t.Helper()
	acc := simplespaceUnion(t, body, "appAccess")
	arr, _ := acc["allowed"].([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func simplespaceUpdateSpace(t *testing.T, a *actor, sp string, patch map[string]any) xres {
	t.Helper()
	body := map[string]any{"space": sp}
	for k, v := range patch {
		body[k] = v
	}
	return a.post("com.atproto.simplespace.updateSpace", body)
}

func simplespaceRemoveMember(t *testing.T, owner *actor, sp string, m *actor) {
	t.Helper()
	mustOK(t, owner.post("com.atproto.simplespace.removeMember", map[string]any{"space": sp, "did": m.did}))
}

// simplespaceMint is the exchange on its own: a fresh key binding, an
// optional client attestation, no returned credential wrapper.
func simplespaceMint(t *testing.T, authority *spacePDS, sp, token, attestation string) xres {
	t.Helper()
	return exchange(t, authority, sp, token, newP256Key(t), attestation)
}

// simplespaceExpectFailure asserts a call errored, as the reference's bare
// rejects.toThrow() does.
func simplespaceExpectFailure(t *testing.T, r xres) {
	t.Helper()
	if r.status == 200 {
		t.Fatalf("expected an error, got 200: %s", r.raw)
	}
}

// simplespaceCountRows counts rows matching a where clause.
func simplespaceCountRows(t *testing.T, p *spacePDS, model any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := p.s.db.Client().Where(query, args...).Model(model).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// simplespaceSpaceRow reads a space row straight from storage.
func simplespaceSpaceRow(t *testing.T, p *spacePDS, did, sp string) *models.Space {
	t.Helper()
	var rows []models.Space
	if err := p.s.db.Client().Where("did = ? AND uri = ?", did, sp).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return nil
	}
	return &rows[0]
}

// simplespaceBlobExists reports whether a blob's bytes are still held for an
// account, reading the blobs table as the reference reads its blob store.
func simplespaceBlobExists(t *testing.T, a *actor, cidStr string) bool {
	t.Helper()
	return simplespaceCountRows(t, a.pds, &models.Blob{}, "did = ? AND cid = ?", a.did, mustCid(t, cidStr).Bytes()) > 0
}

// simplespaceUploadBlob uploads raw bytes and returns the blob ref lexicon
// object to embed in a record.
func simplespaceUploadBlob(t *testing.T, a *actor, data []byte) map[string]any {
	t.Helper()
	res := a.pds.net.do("POST", a.pds.url, "com.atproto.repo.uploadBlob", nil, data, map[string]string{
		"Authorization": "Bearer " + a.access,
		"Content-Type":  "application/octet-stream",
	})
	mustOK(t, res)
	blob, _ := res.body["blob"].(map[string]any)
	if blob == nil {
		t.Fatalf("no blob in %s", res.raw)
	}
	return blob
}

func simplespaceBlobLink(t *testing.T, blob map[string]any) string {
	t.Helper()
	ref, _ := blob["ref"].(map[string]any)
	link, _ := ref["$link"].(string)
	if link == "" {
		t.Fatalf("bad blob ref: %v", blob)
	}
	return link
}

// simplespaceWriterDids is the writer set as stored by the authority, read
// through storage as the reference's writerDids does.
func simplespaceWriterDids(t *testing.T, r *simplespaceNet, sp string) []string {
	t.Helper()
	var rows []models.SpaceWriter
	if err := r.pds1.s.db.Client().Where("did = ? AND space = ?", r.alice.did, sp).Order("space_rev asc").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	dids := make([]string, 0, len(rows))
	for _, w := range rows {
		dids = append(dids, w.WriterDid)
	}
	return dids
}

func simplespaceDeleteSpace(t *testing.T, a *actor, sp string) xres {
	t.Helper()
	return a.post("com.atproto.simplespace.deleteSpace", map[string]any{"space": sp})
}

// ---- lifecycle -----------------------------------------------------------

func TestSimplespaceLifecycle(t *testing.T) {
	r := newSimplespaceNet(t)

	t.Run("creates a space anchored on the caller own DID", func(t *testing.T) {
		// There is no `did` param: a space is always under the caller's
		// authority, so there is no way to ask for one under someone else's.
		sp := createSpace(t, r.alice, spaceOpts{})
		if !strings.HasPrefix(sp, "at://"+r.alice.did+"/space/") {
			t.Fatalf("space %s not anchored on %s", sp, r.alice.did)
		}
		listed := mustOK(t, r.alice.get("com.atproto.space.listSpaces", nil)).list("spaces")
		found := false
		for _, s := range listed {
			found = found || s["uri"] == sp
		}
		if !found {
			t.Fatalf("listSpaces misses %s: %s", sp, mustOK(t, r.alice.get("com.atproto.space.listSpaces", nil)).raw)
		}
	})

	t.Run("refuses a duplicate space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		res := r.alice.post("com.atproto.simplespace.createSpace", map[string]any{
			"spaceType":   testSpaceType,
			"skey":        lastSegment(sp),
			"readPolicy":  memberListPolicy(),
			"writePolicy": memberListPolicy(),
			"appAccess":   openAccess(),
		})
		expectErr(t, res, 400, "SpaceAlreadyExists")
	})

	t.Run("refuses a space key that is not a valid record key", func(t *testing.T) {
		res := r.alice.post("com.atproto.simplespace.createSpace", map[string]any{
			"spaceType":   testSpaceType,
			"skey":        "not a valid rkey",
			"readPolicy":  memberListPolicy(),
			"writePolicy": memberListPolicy(),
			"appAccess":   openAccess(),
		})
		if res.status != 400 || !strings.Contains(strings.ToLower(res.message()), "record key") {
			t.Fatalf("want 400 record key error, got %d: %s", res.status, res.raw)
		}
	})

	t.Run("filters spaces by spaceType", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		otherType := "com.example.otherGroup"
		other := createSpace(t, r.alice, spaceOpts{spaceType: otherType})

		listed := mustOK(t, r.alice.get("com.atproto.space.listSpaces", map[string]string{"spaceType": testSpaceType})).list("spaces")
		hasSp, hasOther := false, false
		for _, s := range listed {
			hasSp = hasSp || s["uri"] == sp
			hasOther = hasOther || s["uri"] == other
		}
		if !hasSp || hasOther {
			t.Fatalf("spaceType filter: hasSp=%v hasOther=%v", hasSp, hasOther)
		}

		otherListed := mustOK(t, r.alice.get("com.atproto.space.listSpaces", map[string]string{"spaceType": otherType})).list("spaces")
		if len(otherListed) != 1 || otherListed[0]["uri"] != other {
			t.Fatalf("otherType listing: %v", otherListed)
		}
	})

	t.Run("governs a space written to before createSpace", func(t *testing.T) {
		// Writing to at://me/space/<type>/<skey> materializes a repo but does
		// not create a simplespace: there is no config until the owner asks
		// for one, and no default to guess at.
		skey := "lazy"
		sp := "at://" + r.alice.did + "/space/" + testSpaceType + "/" + skey
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "lazy space"}))

		expectErr(t, r.alice.get("com.atproto.simplespace.getSpace", map[string]string{"space": sp}), 400, "SpaceNotFound")
		expectErr(t, r.alice.post("com.atproto.simplespace.putMember", map[string]any{"space": sp, "did": r.bob.did, "read": true, "write": true}), 400, "SpaceNotFound")

		createSpace(t, r.alice, spaceOpts{skey: skey})
		putMember(t, r.alice, sp, r.bob, true, true)

		got := simplespaceGetConfig(t, r.alice, sp)
		if simplespaceUnion(t, got, "readPolicy")["$type"] != "com.atproto.simplespace.defs#memberListPolicy" {
			t.Fatalf("readPolicy: %s", simplespaceJSON(t, got))
		}
		if simplespaceUnion(t, got, "writePolicy")["$type"] != "com.atproto.simplespace.defs#memberListPolicy" {
			t.Fatalf("writePolicy: %s", simplespaceJSON(t, got))
		}

		// And the records that were already there stay put.
		listed := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did})).list("records")
		if len(listed) != 1 {
			t.Fatalf("records: %v", listed)
		}
	})
}

// ---- members -------------------------------------------------------------

func TestSimplespaceMembers(t *testing.T) {
	r := newSimplespaceNet(t)

	t.Run("adds and removes members, and the owner is not one of them", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		putMember(t, r.alice, sp, r.bob, true, false)

		members := mustOK(t, r.alice.get("com.atproto.simplespace.listMembers", map[string]string{"space": sp})).list("members")
		dids := map[string]bool{}
		for _, m := range members {
			dids[m["did"].(string)] = true
		}
		// Alice is the authority, which is checked against the space uri
		// rather than carried on the member list.
		if dids[r.alice.did] {
			t.Fatal("owner listed as a member")
		}
		if !dids[r.dan.did] || !dids[r.bob.did] {
			t.Fatalf("members: %v", dids)
		}
		for _, m := range members {
			if m["did"] == r.bob.did && (m["read"] != true || m["write"] != false) {
				t.Fatalf("bob access: %v", m)
			}
		}

		simplespaceRemoveMember(t, r.alice, sp, r.bob)
		after := mustOK(t, r.alice.get("com.atproto.simplespace.listMembers", map[string]string{"space": sp})).list("members")
		for _, m := range after {
			if m["did"] == r.bob.did {
				t.Fatalf("bob still a member: %v", after)
			}
		}
	})

	t.Run("refuses membership changes from a non-owner member", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		expectErr(t, r.dan.post("com.atproto.simplespace.putMember", map[string]any{"space": sp, "did": r.carol.did, "read": true, "write": true}), 400, "NotSpaceOwner")
		expectErr(t, r.dan.post("com.atproto.simplespace.removeMember", map[string]any{"space": sp, "did": r.dan.did}), 400, "NotSpaceOwner")
	})

	t.Run("refuses listMembers to a space credential and to a non-owner member", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol, r.dan}})

		// Carol is a member, hosted elsewhere: a credential reads the
		// space's data, but the member list is the authority's own.
		cred := credentialFor(t, r.carol, r.pds1, sp)
		simplespaceExpectFailure(t, cred.get(t, r.pds1, "com.atproto.simplespace.listMembers", map[string]string{"space": sp}))

		// Dan is co-located with the authority, but the space is not his.
		expectErr(t, r.dan.get("com.atproto.simplespace.listMembers", map[string]string{"space": sp}), 400, "NotSpaceOwner")
	})

	t.Run("putMember replaces both access values", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		putMember(t, r.alice, sp, r.bob, true, false)
		putMember(t, r.alice, sp, r.bob, false, true)

		members := mustOK(t, r.alice.get("com.atproto.simplespace.listMembers", map[string]string{"space": sp})).list("members")
		bobs := 0
		for _, m := range members {
			if m["did"] != r.bob.did {
				continue
			}
			bobs++
			if m["read"] != false || m["write"] != true {
				t.Fatalf("bob access: %v", m)
			}
		}
		if bobs != 1 {
			t.Fatalf("bob member rows: %d", bobs)
		}
	})
}

// ---- config --------------------------------------------------------------

func TestSimplespaceConfig(t *testing.T) {
	r := newSimplespaceNet(t)

	t.Run("persists what createSpace was given", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{
			readPolicy:  managingAppPolicy("did:web:example.com#forum"),
			writePolicy: publicPolicy(),
			appAccess:   allowList("app:one", "app:two"),
		})

		got := simplespaceGetConfig(t, r.alice, sp)
		if got["uri"] != sp {
			t.Fatalf("uri: %s", simplespaceJSON(t, got))
		}
		if want := map[string]any{"$type": "com.atproto.simplespace.defs#managingAppPolicy", "managingApp": "did:web:example.com#forum"}; !reflect.DeepEqual(simplespaceUnion(t, got, "readPolicy"), want) {
			t.Fatalf("readPolicy: %s", simplespaceJSON(t, got))
		}
		if want := map[string]any{"$type": "com.atproto.simplespace.defs#publicPolicy"}; !reflect.DeepEqual(simplespaceUnion(t, got, "writePolicy"), want) {
			t.Fatalf("writePolicy: %s", simplespaceJSON(t, got))
		}
		if got := simplespaceAllowed(t, got); len(got) != 2 || got[0] != "app:one" || got[1] != "app:two" {
			t.Fatalf("appAccess allowed: %v", got)
		}
	})

	t.Run("defaults to a member-list, open space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		got := simplespaceGetConfig(t, r.alice, sp)
		if want := map[string]any{"$type": "com.atproto.simplespace.defs#memberListPolicy"}; !reflect.DeepEqual(simplespaceUnion(t, got, "readPolicy"), want) {
			t.Fatalf("readPolicy: %s", simplespaceJSON(t, got))
		}
		if want := map[string]any{"$type": "com.atproto.simplespace.defs#memberListPolicy"}; !reflect.DeepEqual(simplespaceUnion(t, got, "writePolicy"), want) {
			t.Fatalf("writePolicy: %s", simplespaceJSON(t, got))
		}
		if simplespaceUnion(t, got, "appAccess")["$type"] != "com.atproto.simplespace.defs#open" {
			t.Fatalf("appAccess: %s", simplespaceJSON(t, got))
		}
	})

	t.Run("patches readPolicy, writePolicy, and appAccess independently", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})

		mustOK(t, simplespaceUpdateSpace(t, r.alice, sp, map[string]any{"readPolicy": publicPolicy()}))
		mustOK(t, simplespaceUpdateSpace(t, r.alice, sp, map[string]any{"writePolicy": managingAppPolicy("did:web:example.com#forum")}))
		mustOK(t, simplespaceUpdateSpace(t, r.alice, sp, map[string]any{"appAccess": allowList("app:x")}))

		got := simplespaceGetConfig(t, r.alice, sp)
		// The second update left the first alone.
		if simplespaceUnion(t, got, "readPolicy")["$type"] != "com.atproto.simplespace.defs#publicPolicy" {
			t.Fatalf("readPolicy: %s", simplespaceJSON(t, got))
		}
		if want := map[string]any{"$type": "com.atproto.simplespace.defs#managingAppPolicy", "managingApp": "did:web:example.com#forum"}; !reflect.DeepEqual(simplespaceUnion(t, got, "writePolicy"), want) {
			t.Fatalf("writePolicy: %s", simplespaceJSON(t, got))
		}
		if got := simplespaceAllowed(t, got); len(got) != 1 || got[0] != "app:x" {
			t.Fatalf("appAccess allowed: %v", got)
		}
	})

	t.Run("drops managingApp by switching policy", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: managingAppPolicy("did:web:example.com#forum")})
		mustOK(t, simplespaceUpdateSpace(t, r.alice, sp, map[string]any{"readPolicy": memberListPolicy()}))
		got := simplespaceGetConfig(t, r.alice, sp)
		// No stale managingApp left hanging off the new policy.
		if want := map[string]any{"$type": "com.atproto.simplespace.defs#memberListPolicy"}; !reflect.DeepEqual(simplespaceUnion(t, got, "readPolicy"), want) {
			t.Fatalf("readPolicy: %s", simplespaceJSON(t, got))
		}
	})

	t.Run("refuses an update from a non-owner", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		simplespaceExpectFailure(t, r.pds1.post("com.atproto.simplespace.updateSpace", map[string]any{
			"space": sp, "readPolicy": publicPolicy(),
		}, r.bob.auth()))
	})

	t.Run("refuses an unrecognized appAccess variant rather than widening the space", func(t *testing.T) {
		// appAccess is an open union, so an unknown variant is well-formed on
		// the wire. Storing it would mean enforcing something weaker than the
		// owner asked for.
		sp := createSpace(t, r.alice, spaceOpts{appAccess: allowList("app:one")})

		expectErr(t, simplespaceUpdateSpace(t, r.alice, sp, map[string]any{
			"appAccess": map[string]any{"$type": "com.example.denyEverything"},
		}), 400, "UnsupportedAppAccess")

		// ...and the previous setting survives the refusal.
		if got := simplespaceAllowed(t, simplespaceGetConfig(t, r.alice, sp)); len(got) != 1 || got[0] != "app:one" {
			t.Fatalf("appAccess allowed: %v", got)
		}
	})

	t.Run("refuses an unrecognized policy variant", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		expectErr(t, simplespaceUpdateSpace(t, r.alice, sp, map[string]any{
			"writePolicy": map[string]any{"$type": "com.example.whatever"},
		}), 400, "UnsupportedPolicy")
	})

	t.Run("refuses a managingApp that does not name a service", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		res := simplespaceUpdateSpace(t, r.alice, sp, map[string]any{
			"readPolicy": managingAppPolicy("not-a-did-at-all"),
		})
		if res.status != 400 || !strings.Contains(res.message(), "must be a DID") {
			t.Fatalf("want 400 must-be-a-DID, got %d: %s", res.status, res.raw)
		}
	})

	t.Run("serves the config to a member with a space credential", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)

		got := mustOK(t, cred.get(t, r.pds1, "com.atproto.simplespace.getSpace", map[string]string{"space": sp}))
		if got.body["uri"] != sp {
			t.Fatalf("uri: %s", got.raw)
		}
		if simplespaceUnion(t, got.body, "readPolicy")["$type"] != "com.atproto.simplespace.defs#memberListPolicy" {
			t.Fatalf("readPolicy: %s", got.raw)
		}
	})

	t.Run("refuses the config to a credential for another space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{skey: "cfg-wrong", members: []*actor{r.carol}})
		other := createSpace(t, r.alice, spaceOpts{skey: "cfg-wrong-other", members: []*actor{r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, other)

		simplespaceExpectFailure(t, cred.get(t, r.pds1, "com.atproto.simplespace.getSpace", map[string]string{"space": sp}))
	})

	t.Run("refuses the config to another account on an account credential", func(t *testing.T) {
		// Dan is a member and is hosted here, but the config is the
		// authority's own state: an account credential reaches it only for
		// that account's own spaces.
		sp := createSpace(t, r.alice, spaceOpts{skey: "cfg-not-owner", members: []*actor{r.dan}})

		expectErr(t, r.dan.get("com.atproto.simplespace.getSpace", map[string]string{"space": sp}), 400, "NotSpaceOwner")

		// ...and the same member reaches it with a space credential.
		cred := credentialFor(t, r.dan, r.pds1, sp)
		if got := mustOK(t, cred.get(t, r.pds1, "com.atproto.simplespace.getSpace", map[string]string{"space": sp})); got.body["uri"] != sp {
			t.Fatalf("uri: %s", got.raw)
		}
	})

	t.Run("refuses to answer for a space this host does not govern", func(t *testing.T) {
		// pds2 hosts no account for alice, so it holds no config to answer
		// from.
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		cred := credentialFor(t, r.bob, r.pds1, sp)

		// The error names the space rather than leaking it as a missing repo.
		expectErr(t, cred.get(t, r.pds2, "com.atproto.space.listRepos", map[string]string{"space": sp}), 400, "SpaceNotFound")
		simplespaceExpectFailure(t, r.bob.get("com.atproto.simplespace.getSpace", map[string]string{"space": sp}))
	})
}

// ---- credential mint gates ----------------------------------------------

func TestSimplespaceCredentialMintGates(t *testing.T) {
	r := newSimplespaceNet(t)
	hostAud := r.alice.did + "#atproto_space_host"

	t.Run("mints for a non-member when the read policy is public", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: publicPolicy()})
		cred := credentialFor(t, r.carol, r.pds1, sp)
		if cred.credential == "" {
			t.Fatal("no credential minted")
		}
	})

	t.Run("refuses a non-member under member-list read policy", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, simplespaceMint(t, r.pds1, sp, token, ""), 400, "UserNotAuthorized")
	})

	t.Run("refuses a member without read access", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		putMember(t, r.alice, sp, r.carol, false, true)

		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, simplespaceMint(t, r.pds1, sp, token, ""), 400, "UserNotAuthorized")
	})

	t.Run("always admits the authority, whatever the read policy", func(t *testing.T) {
		// The authority is the only party who can reconfigure the space, so
		// it must not be able to lock itself out.
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: managingAppPolicy("did:web:unreachable.invalid#forum")})
		cred := credentialFor(t, r.alice, r.pds1, sp)
		if cred.credential == "" {
			t.Fatal("no credential minted")
		}
	})

	t.Run("refuses when appAccess is an allowList and no attestation is presented", func(t *testing.T) {
		// readPolicy public so the user passes; appAccess allowList wants an
		// attested client_id, which a plain exchange doesn't supply.
		sp := createSpace(t, r.alice, spaceOpts{
			readPolicy: publicPolicy(),
			appAccess:  allowList("https://app.example.com/client-metadata.json"),
		})
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, simplespaceMint(t, r.pds1, sp, token, ""), 400, "AppNotAuthorized")
	})

	t.Run("mints for an allow-listed app that signs with its published key", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: publicPolicy(), appAccess: allowList(app.clientID)})

		token := delegationTokenFor(t, r.carol, sp)
		res := simplespaceMint(t, r.pds1, sp, token, app.attest(t, hostAud, attestOpts{}))
		if res.str("credential") == "" {
			t.Fatalf("no credential minted: %s", res.raw)
		}
	})

	t.Run("refuses an attestation signed by a key the app does not publish", func(t *testing.T) {
		// The forgery the whole check exists to stop: carol claims to be the
		// allow-listed app and signs with a key of her own. The client_id and
		// audience are both exactly right, so only the signature stands in
		// the way.
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: publicPolicy(), appAccess: allowList(app.clientID)})

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		attackerKey, err := jwk.FromRaw(priv)
		if err != nil {
			t.Fatal(err)
		}
		_ = attackerKey.Set(jwk.KeyIDKey, "key-1")
		_ = attackerKey.Set(jwk.AlgorithmKey, jwa.ES256)
		forged := app.attest(t, hostAud, attestOpts{signWith: attackerKey})

		token := delegationTokenFor(t, r.carol, sp)
		res := simplespaceMint(t, r.pds1, sp, token, forged)
		if res.status != 400 || !strings.Contains(res.message(), "Invalid client attestation") {
			t.Fatalf("want 400 Invalid client attestation, got %d: %s", res.status, res.raw)
		}
	})

	t.Run("refuses an attestation addressed to another authority", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: publicPolicy(), appAccess: allowList(app.clientID)})

		token := delegationTokenFor(t, r.carol, sp)
		res := simplespaceMint(t, r.pds1, sp, token, app.attest(t, r.bob.did+"#atproto_space_host", attestOpts{}))
		if res.status != 400 || !strings.Contains(res.message(), "Invalid client attestation") {
			t.Fatalf("want 400 Invalid client attestation, got %d: %s", res.status, res.raw)
		}
	})

	t.Run("refuses an attestation from an app that is not allow-listed", func(t *testing.T) {
		// A genuine attestation, correctly signed — for an app this space
		// never allowed. Verification passing is not the same as being
		// admitted.
		allowed := r.net.newMockClientApp(clientAppOpts{})
		other := r.net.newMockClientApp(clientAppOpts{})
		other.installOn(r.pds1)
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: publicPolicy(), appAccess: allowList(allowed.clientID)})

		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, simplespaceMint(t, r.pds1, sp, token, other.attest(t, hostAud, attestOpts{})), 400, "AppNotAuthorized")
	})

	t.Run("refuses an expired attestation", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := createSpace(t, r.alice, spaceOpts{readPolicy: publicPolicy(), appAccess: allowList(app.clientID)})

		token := delegationTokenFor(t, r.carol, sp)
		res := simplespaceMint(t, r.pds1, sp, token, app.attest(t, hostAud, attestOpts{expiresIn: -120}))
		if res.status != 400 || !strings.Contains(res.message(), "Invalid client attestation") {
			t.Fatalf("want 400 Invalid client attestation, got %d: %s", res.status, res.raw)
		}
	})

	// The managing-app hook: the authority asks a third-party app whether a
	// user may join. Everything here is about trusting that answer — and
	// about what happens when there isn't one.
	spaceWith := func(t *testing.T, app string) string {
		t.Helper()
		return createSpace(t, r.alice, spaceOpts{
			readPolicy:  managingAppPolicy(app),
			writePolicy: managingAppPolicy(app),
		})
	}
	forum := func(t *testing.T, authorized *bool) *mockService {
		t.Helper()
		return r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			if authorized == nil {
				return 500, map[string]any{"error": "InternalError"}
			}
			return 200, map[string]any{"authorized": *authorized}
		})
	}

	t.Run("admits a user the managing app authorizes", func(t *testing.T) {
		app := forum(t, boolp(true))
		sp := spaceWith(t, app.serviceRef())

		cred := credentialFor(t, r.carol, r.pds1, sp)
		if cred.credential == "" {
			t.Fatal("no credential minted")
		}

		// It was actually consulted, and told who was asking.
		asked := app.callsTo("com.atproto.simplespace.checkUserAccess")
		if len(asked) != 1 {
			t.Fatalf("checkUserAccess calls: %d", len(asked))
		}
		if asked[0].body["space"] != sp || asked[0].body["user"] != r.carol.did || asked[0].body["access"] != "read" {
			t.Fatalf("checkUserAccess body: %v", asked[0].body)
		}
		// Addressed with service auth from the authority, so the app can
		// tell who is asking it.
		if !strings.HasPrefix(asked[0].auth, "Bearer ") {
			t.Fatalf("checkUserAccess auth: %q", asked[0].auth)
		}
	})

	t.Run("refuses a user the managing app declines", func(t *testing.T) {
		app := forum(t, boolp(false))
		sp := spaceWith(t, app.serviceRef())

		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, simplespaceMint(t, r.pds1, sp, token, ""), 400, "UserNotAuthorized")
	})

	t.Run("denies when the managing app errors", func(t *testing.T) {
		// Failing open would hand out credentials for exactly the spaces that
		// asked for the strictest gate.
		app := forum(t, nil)
		sp := spaceWith(t, app.serviceRef())

		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, simplespaceMint(t, r.pds1, sp, token, ""), 400, "UserNotAuthorized")
	})

	t.Run("denies when the managing app cannot be resolved", func(t *testing.T) {
		// Same reasoning as an error response: an unreachable gate is a
		// closed one.
		sp := spaceWith(t, "did:web:nonexistent.invalid#forum")
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, simplespaceMint(t, r.pds1, sp, token, ""), 400, "UserNotAuthorized")
	})

	t.Run("records a writer the managing app admits", func(t *testing.T) {
		app := forum(t, boolp(true))
		sp := spaceWith(t, app.serviceRef())

		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "admitted by the managing app"}))
		var dids []string
		if !awaitCond(t, func() bool {
			dids = simplespaceWriterDids(t, r, sp)
			for _, d := range dids {
				if d == r.bob.did {
					return true
				}
			}
			return false
		}) {
			t.Fatalf("writer set never included bob: %v", dids)
		}
		asked := app.callsTo("com.atproto.simplespace.checkUserAccess")
		found := false
		for _, c := range asked {
			found = found || (c.body["space"] == sp && c.body["user"] == r.bob.did && c.body["access"] == "write")
		}
		if !found {
			t.Fatalf("no write checkUserAccess call: %v", asked)
		}
	})
}

// ---- notify registration --------------------------------------------------

func TestSimplespaceNotifyRegistration(t *testing.T) {
	r := newSimplespaceNet(t)
	const lxmNotifyWrite = "com.atproto.space.notifyWrite"

	t.Run("registers, forwards writes, and stops once withdrawn", func(t *testing.T) {
		syncer := r.net.newMockService("atproto_space_syncer", nil)
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)

		reg := mustOK(t, cred.post(t, r.pds1, "com.atproto.space.registerNotify", map[string]any{"space": sp, "service": syncer.serviceRef()}))
		// The registration expires, and the caller is told when: a syncer has
		// to renew rather than assume it stays registered forever.
		if reg.str("expiresAt") == "" {
			t.Fatalf("no expiresAt: %s", reg.raw)
		}

		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "forwarded"}))
		// The authority's fan-out is queued so the writer's PDS isn't kept
		// waiting.
		if !awaitCond(t, func() bool { return len(syncer.callsTo(lxmNotifyWrite)) > 0 }) {
			t.Fatal("write was never forwarded")
		}
		r.net.waitSpaceJobs()

		delivered := syncer.callsTo(lxmNotifyWrite)
		if len(delivered) == 0 {
			t.Fatal("no deliveries")
		}
		if delivered[0].body["space"] != sp || delivered[0].body["repo"] != r.bob.did {
			t.Fatalf("delivery body: %v", delivered[0].body)
		}

		// Withdrawn: no further deliveries.
		mustOK(t, cred.post(t, r.pds1, "com.atproto.space.unregisterNotify", map[string]any{"space": sp, "service": syncer.serviceRef()}))
		before := len(syncer.callsTo(lxmNotifyWrite))
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "not forwarded"}))
		r.net.waitSpaceJobs()
		time.Sleep(300 * time.Millisecond)
		if got := len(syncer.callsTo(lxmNotifyWrite)); got != before {
			t.Fatalf("deliveries after unregistering: %d -> %d", before, got)
		}

		// Unregistering again is idempotent.
		mustOK(t, cred.post(t, r.pds1, "com.atproto.space.unregisterNotify", map[string]any{"space": sp, "service": syncer.serviceRef()}))
	})

	t.Run("stops delivering to a registration past its expiry, and resumes on renewal", func(t *testing.T) {
		syncer := r.net.newMockService("atproto_space_syncer", nil)
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)

		mustOK(t, cred.post(t, r.pds1, "com.atproto.space.registerNotify", map[string]any{"space": sp, "service": syncer.serviceRef()}))

		// Expire it rather than waiting out the TTL. No endpoint does this,
		// so it reaches into storage deliberately.
		if err := r.pds1.s.db.Exec(context.Background(),
			"UPDATE space_credential_recipients SET expires_at = ? WHERE did = ? AND space = ?",
			nil, "2000-01-01T00:00:00.000Z", r.alice.did, sp,
		).Error; err != nil {
			t.Fatal(err)
		}

		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "after expiry"}))
		r.net.waitSpaceJobs()
		time.Sleep(300 * time.Millisecond)
		if got := len(syncer.callsTo(lxmNotifyWrite)); got != 0 {
			t.Fatalf("delivered past expiry: %d", got)
		}

		// Renewing brings it back — the row was withheld, not dropped.
		mustOK(t, cred.post(t, r.pds1, "com.atproto.space.registerNotify", map[string]any{"space": sp, "service": syncer.serviceRef()}))
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "after renewal"}))
		if !awaitCond(t, func() bool { return len(syncer.callsTo(lxmNotifyWrite)) > 0 }) {
			t.Fatal("write was never forwarded after renewal")
		}
		r.net.waitSpaceJobs()
		if got := len(syncer.callsTo(lxmNotifyWrite)); got == 0 {
			t.Fatal("no deliveries after renewal")
		}
	})

	t.Run("refuses a service that cannot be resolved", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)
		expectErr(t, cred.post(t, r.pds1, "com.atproto.space.registerNotify", map[string]any{
			"space":   sp,
			"service": "did:web:nonexistent.invalid#syncer",
		}), 400, "ServiceNotResolvable")
	})
}

// ---- deletion -------------------------------------------------------------

func TestSimplespaceDeletion(t *testing.T) {
	r := newSimplespaceNet(t)

	t.Run("purges the authority own repo and keeps a tombstone", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		blob := simplespaceUploadBlob(t, r.alice, []byte("space blob for deletion"))
		blobCid := simplespaceBlobLink(t, blob)
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "doomed", record: map[string]any{
			"$type": testCollection,
			"text":  "owner record",
			"image": blob,
		}}))
		if !simplespaceBlobExists(t, r.alice, blobCid) {
			t.Fatal("blob missing before deletion")
		}

		mustOK(t, simplespaceDeleteSpace(t, r.alice, sp))

		// The row survives as a tombstone, so getSpaceCredential can keep
		// answering SpaceDeleted; everything it held is gone.
		if row := simplespaceSpaceRow(t, r.pds1, r.alice.did, sp); row == nil || row.DeletedAt == nil {
			t.Fatalf("no tombstone: %+v", row)
		}
		if n := simplespaceCountRows(t, r.pds1, &models.SpaceRecord{}, "did = ? AND space = ?", r.alice.did, sp); n != 0 {
			t.Fatalf("records survived: %d", n)
		}
		if n := simplespaceCountRows(t, r.pds1, &models.SimplespaceMember{}, "did = ? AND space = ?", r.alice.did, sp); n != 0 {
			t.Fatalf("members survived: %d", n)
		}
		if simplespaceBlobExists(t, r.alice, blobCid) {
			t.Fatal("blob survived deletion")
		}

		expectErr(t, r.alice.get("com.atproto.simplespace.getSpace", map[string]string{"space": sp}), 400, "SpaceNotFound")

		// Idempotent.
		mustOK(t, simplespaceDeleteSpace(t, r.alice, sp))
	})

	t.Run("answers SpaceDeleted on credential renewal", func(t *testing.T) {
		// The durable drop signal: a syncer that missed notifySpaceDeleted
		// learns the space is gone here, and can tell it apart from an
		// authority that is merely down.
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		token := delegationTokenFor(t, r.carol, sp)

		mustOK(t, simplespaceDeleteSpace(t, r.alice, sp))

		expectErr(t, simplespaceMint(t, r.pds1, sp, token, ""), 400, "SpaceDeleted")
	})

	t.Run("notifies registered syncers", func(t *testing.T) {
		syncer := r.net.newMockService("atproto_space_syncer", nil)
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)
		mustOK(t, cred.post(t, r.pds1, "com.atproto.space.registerNotify", map[string]any{"space": sp, "service": syncer.serviceRef()}))

		mustOK(t, simplespaceDeleteSpace(t, r.alice, sp))
		r.net.waitSpaceJobs()

		delivered := syncer.callsTo("com.atproto.space.notifySpaceDeleted")
		if len(delivered) != 1 {
			t.Fatalf("notifySpaceDeleted deliveries: %d", len(delivered))
		}
		if delivered[0].body["space"] != sp {
			t.Fatalf("notifySpaceDeleted body: %v", delivered[0].body)
		}
	})

	t.Run("leaves a member repo untouched", func(t *testing.T) {
		// A member's PDS is never notified: the records are the member's own,
		// and it is the application's job to tell them the space is gone.
		// What deletion takes away is the ability to get a credential to
		// read them.
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "member write"}))

		mustOK(t, simplespaceDeleteSpace(t, r.alice, sp))
		r.net.waitSpaceJobs()

		if row := simplespaceSpaceRow(t, r.pds2, r.bob.did, sp); row == nil || row.DeletedAt != nil {
			t.Fatalf("member space row: %+v", row)
		}
		if n := simplespaceCountRows(t, r.pds2, &models.SpaceRecord{}, "did = ? AND space = ?", r.bob.did, sp); n != 1 {
			t.Fatalf("member records: %d", n)
		}
	})

	t.Run("allows re-creating a deleted space, with fresh config", func(t *testing.T) {
		skey := "recreate"
		sp := createSpace(t, r.alice, spaceOpts{skey: skey, readPolicy: publicPolicy(), writePolicy: publicPolicy()})
		mustOK(t, simplespaceDeleteSpace(t, r.alice, sp))

		recreated := createSpace(t, r.alice, spaceOpts{skey: skey})
		if recreated != sp {
			t.Fatalf("recreated as %s, want %s", recreated, sp)
		}

		// Reset, not revived: the deleted space's public policies must not
		// carry over into the new one.
		got := simplespaceGetConfig(t, r.alice, sp)
		if simplespaceUnion(t, got, "readPolicy")["$type"] != "com.atproto.simplespace.defs#memberListPolicy" {
			t.Fatalf("readPolicy: %s", simplespaceJSON(t, got))
		}
		if simplespaceUnion(t, got, "writePolicy")["$type"] != "com.atproto.simplespace.defs#memberListPolicy" {
			t.Fatalf("writePolicy: %s", simplespaceJSON(t, got))
		}

		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "after recreation"}))
	})
}
