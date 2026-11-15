package server

// Ported from packages/pds/tests/space/policy.test.ts in bluesky-social/atproto
// at d4def6e9 (November 12, 2026): lifecycle, memberspace policy state,
// migration, published policy/member records, personalspace, credential gates,
// managedspace, and deletion.
//
// The reference's "notify registration" describe is deliberately excluded: it
// is ported by the notifications area. The deletion race named "refuses a
// registration made as the space is deleted" injects a mock into the
// reference actorStore between credential construction and registration;
// Cocoon exposes no equivalent request-local interposition hook. The durable
// SpaceDeleted answer and the store's refusal to register a deleted space are
// covered without that artificial interleaving. Cocoon has no app passwords,
// lexicon catalog, or reference background-queue/clock implementation to mock.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type spacePolicyNet struct {
	net                    *spaceNet
	pds1, pds2, pds3       *spacePDS
	alice, dan, bob, carol *actor
}

func newSpacePolicyNet(t *testing.T) *spacePolicyNet {
	t.Helper()
	n := newSpaceNet(t)
	r := &spacePolicyNet{net: n, pds1: n.newPDS(), pds2: n.newPDS(), pds3: n.newPDS()}
	r.alice = r.pds1.createActor("alice") // authority, on pds1
	r.dan = r.pds1.createActor("dan")     // co-located with the authority
	r.bob = r.pds2.createActor("bob")     // on pds2
	r.carol = r.pds3.createActor("carol") // on pds3
	return r
}

// ---- policy-specific helpers ---------------------------------------------

func spacePolicyGet(a *actor, spaceURI string) xres {
	return a.get("com.atproto.space.getSpace", map[string]string{"space": spaceURI})
}

func spacePolicyUpdate(a *actor, spaceURI string, policy map[string]any) xres {
	return a.post("com.atproto.space.updateSpace", map[string]any{"space": spaceURI, "policy": policy})
}

func spacePolicyDelete(a *actor, spaceURI string) xres {
	return a.post("com.atproto.space.deleteSpace", map[string]any{"space": spaceURI})
}

func spacePolicyListMembers(a *actor, spaceURI string) xres {
	return a.get("com.atproto.memberspace.listMembers", map[string]string{"space": spaceURI})
}

// spacePolicyMint is authorizeSpaceSync on its own, with a fresh key binding.
func spacePolicyMint(t *testing.T, authority *spacePDS, spaceURI, token, attestation string) xres {
	t.Helper()
	return exchange(t, authority, spaceURI, token, newP256Key(t), attestation)
}

func spacePolicyExpectFailure(t *testing.T, r xres) {
	t.Helper()
	if r.status == 200 {
		t.Fatalf("expected an error, got 200: %s", r.raw)
	}
}

func spacePolicyExpectMessage(t *testing.T, r xres, status int, contains string) {
	t.Helper()
	if r.status != status || !strings.Contains(r.message(), contains) {
		t.Fatalf("want %d with message containing %q, got %d: %s", status, contains, r.status, r.raw)
	}
}

func spacePolicyCountRows(t *testing.T, p *spacePDS, model any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := p.s.db.Client().Where(query, args...).Model(model).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func spacePolicySpaceRow(t *testing.T, p *spacePDS, did, spaceURI string) *models.Space {
	t.Helper()
	row, err := p.s.spaceStore(nil, did).getSpace(spaceURI)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func spacePolicyUploadBlob(t *testing.T, a *actor, data []byte) (map[string]any, string) {
	t.Helper()
	res := a.pds.net.do(http.MethodPost, a.pds.url, "com.atproto.repo.uploadBlob", nil, data, map[string]string{
		"Authorization": "Bearer " + a.access,
		"Content-Type":  "application/octet-stream",
	})
	mustOK(t, res)
	blob, _ := res.body["blob"].(map[string]any)
	ref, _ := blob["ref"].(map[string]any)
	link, _ := ref["$link"].(string)
	if blob == nil || link == "" {
		t.Fatalf("bad upload response: %s", res.raw)
	}
	return blob, link
}

func spacePolicyBlobExists(t *testing.T, a *actor, cidString string) bool {
	t.Helper()
	return spacePolicyCountRows(t, a.pds, &models.Blob{}, "did = ? AND cid = ?", a.did, mustCid(t, cidString).Bytes()) > 0
}

// spacePolicyWriterDIDs is the authority's active writer set, read through
// storage like the reference's writerDids helper.
func spacePolicyWriterDIDs(t *testing.T, r *spacePolicyNet, spaceURI string) []string {
	t.Helper()
	var rows []models.SpaceWriter
	if err := r.pds1.s.db.Client().Where("did = ? AND space = ? AND removed_at IS NULL", r.alice.did, spaceURI).
		Order("space_rev asc").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.WriterDid)
	}
	return out
}

func spacePolicyAwaitWriter(t *testing.T, r *spacePolicyNet, spaceURI, did string) []string {
	t.Helper()
	var dids []string
	if !awaitCond(t, func() bool {
		dids = spacePolicyWriterDIDs(t, r, spaceURI)
		for _, got := range dids {
			if got == did {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("writer set never included %s: %v", did, dids)
	}
	return dids
}

// spacePolicySyncer adds the reference MockService's automatic registration
// confirmation while leaving all other responses configurable.
func spacePolicySyncer(r *spacePolicyNet, respond func(*http.Request, mockCall) (int, any)) *mockService {
	return r.net.newMockService("atproto_space_syncer", func(req *http.Request, call mockCall) (int, any) {
		if call.lxm == lxmConfirmRegistration {
			return 200, map[string]any{"challenge": call.body["challenge"]}
		}
		if respond != nil {
			return respond(req, call)
		}
		return 200, map[string]any{}
	})
}

func spacePolicyUpdates(m *mockService) []map[string]any {
	calls := m.callsTo(lxmNotifySpaceUpdate)
	out := make([]map[string]any, 0, len(calls))
	for _, call := range calls {
		update, _ := call.body["update"].(map[string]any)
		out = append(out, update)
	}
	return out
}

func spacePolicyPublished(t *testing.T, a *actor, spaceURI, collection string) []map[string]any {
	t.Helper()
	params := map[string]string{"space": spaceURI, "repo": a.did, "collection": collection}
	return mustOK(t, a.get("com.atproto.space.listRecords", params)).list("records")
}

func spacePolicyPublishedMembers(t *testing.T, a *actor, spaceURI string) []map[string]any {
	t.Helper()
	records := spacePolicyPublished(t, a, spaceURI, collMember)
	sort.Slice(records, func(i, j int) bool { return records[i]["rkey"].(string) < records[j]["rkey"].(string) })
	return records
}

func spacePolicyServiceAuthLXM(t *testing.T, auth string) string {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("malformed service auth: %q", auth)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	lxm, _ := claims["lxm"].(string)
	return lxm
}

// ---- lifecycle ------------------------------------------------------------

func TestSpacePolicyLifecycle(t *testing.T) {
	r := newSpacePolicyNet(t)

	// Reference: lifecycle / "creates a space anchored on the caller own DID".
	t.Run("creates a space anchored on the caller own DID", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		if !strings.HasPrefix(sp, "at://"+r.alice.did+"/space/") {
			t.Fatalf("space %s not anchored on %s", sp, r.alice.did)
		}
		listed := mustOK(t, r.alice.get("com.atproto.space.listSpaces", nil)).list("spaces")
		found := false
		for _, listedSpace := range listed {
			found = found || listedSpace["space"] == sp
		}
		if !found {
			t.Fatalf("listSpaces misses %s: %v", sp, listed)
		}
	})

	// Reference: lifecycle / "refuses a duplicate space".
	t.Run("refuses a duplicate space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		res := r.alice.post("com.atproto.space.createSpace", map[string]any{
			"spaceType": testSpaceType,
			"skey":      lastSegment(sp),
			"policy":    memberPolicy(nil),
		})
		expectErr(t, res, 400, "SpaceAlreadyExists")
	})

	// Reference: lifecycle / "refuses a space key that is not a valid record key".
	t.Run("refuses a space key that is not a valid record key", func(t *testing.T) {
		res := r.alice.post("com.atproto.space.createSpace", map[string]any{
			"spaceType": testSpaceType,
			"skey":      "not a valid rkey",
			"policy":    memberPolicy(nil),
		})
		if res.status != 400 || !strings.Contains(strings.ToLower(res.message()), "record key") {
			t.Fatalf("want 400 record key error, got %d: %s", res.status, res.raw)
		}
	})

	// Reference: lifecycle / "filters spaces by spaceType".
	t.Run("filters spaces by spaceType", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		otherType := "com.example.otherGroup"
		other := createSpace(t, r.alice, spaceOpts{spaceType: otherType})
		listed := mustOK(t, r.alice.get("com.atproto.space.listSpaces", map[string]string{"spaceType": testSpaceType})).list("spaces")
		hasSpace, hasOther := false, false
		for _, listedSpace := range listed {
			hasSpace = hasSpace || listedSpace["space"] == sp
			hasOther = hasOther || listedSpace["space"] == other
		}
		if !hasSpace || hasOther {
			t.Fatalf("spaceType filter: hasSpace=%v hasOther=%v", hasSpace, hasOther)
		}
		otherListed := mustOK(t, r.alice.get("com.atproto.space.listSpaces", map[string]string{"spaceType": otherType})).list("spaces")
		if len(otherListed) != 1 || otherListed[0]["space"] != other {
			t.Fatalf("otherType listing: %v", otherListed)
		}
	})

	// Reference: lifecycle / "lists the state of the caller's repo in each space".
	t.Run("lists the state of the caller repo in each space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		empty := createSpace(t, r.alice, spaceOpts{skey: "list-state-empty"})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "from the authority"}))
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "from a member"}))
		spacePolicyAwaitWriter(t, r, sp, r.bob.did)

		viewOf := func(a *actor, target string) map[string]any {
			t.Helper()
			listed := mustOK(t, a.get("com.atproto.space.listSpaces", map[string]string{"spaceDid": r.alice.did})).list("spaces")
			for _, listedSpace := range listed {
				if listedSpace["space"] == target {
					return listedSpace
				}
			}
			return nil
		}
		for _, a := range []*actor{r.alice, r.bob} {
			state := repoState(t, a, sp)
			if state == nil || state.Rev == nil {
				t.Fatalf("no repo state for %s", a.did)
			}
			hash, err := space.LtHashFromState(state.SetHash)
			if err != nil {
				t.Fatal(err)
			}
			digest := hash.Digest()
			view := viewOf(a, sp)
			wantData := map[string]any{"$bytes": base64.RawStdEncoding.EncodeToString(digest[:])}
			if view == nil || view["repoRev"] != *state.Rev || !reflect.DeepEqual(view["data"], wantData) {
				t.Fatalf("listed state for %s: got %v, want rev %s data %v", a.did, view, *state.Rev, wantData)
			}
		}

		// Only the authority sequences the space, so only its listing has a
		// space revision.
		writerRev, err := r.pds1.s.spaceStore(nil, r.alice.did).getSpaceRev(sp)
		if err != nil {
			t.Fatal(err)
		}
		if got := viewOf(r.alice, sp)["spaceRev"]; got != writerRev {
			t.Fatalf("authority spaceRev %v, want %s", got, writerRev)
		}
		if got, present := viewOf(r.bob, sp)["spaceRev"]; present {
			t.Fatalf("member unexpectedly has spaceRev %v", got)
		}
		if got := viewOf(r.alice, empty); !reflect.DeepEqual(got, map[string]any{"space": empty}) {
			t.Fatalf("unwritten space listing: %v", got)
		}
	})

	// Reference: lifecycle / "refuses an authority write until createSpace".
	t.Run("refuses an authority write until createSpace", func(t *testing.T) {
		skey := "lazy"
		sp := "at://" + r.alice.did + "/space/" + testSpaceType + "/" + skey
		expectErr(t, doWrite(r.alice, sp, writeOpts{text: "too early"}), 400, "SpaceNotFound")
		createSpace(t, r.alice, spaceOpts{skey: skey})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "lazy space"}))
		listed := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did})).list("records")
		if len(listed) != 1 {
			t.Fatalf("records: %v", listed)
		}
	})

	// Baseline-policy round trips exercise createSpace, updateSpace, getSpace,
	// and deleteSpace for each policy supported by Cocoon.
	t.Run("round trips each baseline policy through lifecycle methods", func(t *testing.T) {
		cases := []struct {
			name                    string
			initial, updated, after map[string]any
		}{
			{
				name: "personalspace", initial: personalPolicy(), updated: personalPolicy(),
				after: personalPolicy(),
			},
			{
				name:    "memberspace",
				initial: memberPolicy(map[string]any{"publicRead": true, "allowedApps": []string{"app:x"}, "publishMembers": true}),
				updated: memberPolicy(map[string]any{"publicWrite": true}),
				after:   memberPolicy(map[string]any{"publicRead": false, "publicWrite": true, "publishPolicy": false, "publishMembers": false}),
			},
			{
				name:    "managedspace",
				initial: managedPolicy("did:web:example.com#forum", nil),
				updated: managedPolicy("did:web:example.com#other", map[string]any{"publishPolicy": true}),
				after:   managedPolicy("did:web:example.com#other", map[string]any{"publishPolicy": true}),
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				sp := createSpace(t, r.alice, spaceOpts{policy: tc.initial})
				mustOK(t, spacePolicyUpdate(r.alice, sp, tc.updated))
				got := mustOK(t, spacePolicyGet(r.alice, sp))
				if got.str("space") != sp || !reflect.DeepEqual(got.body["policy"], tc.after) {
					t.Fatalf("getSpace: got %s, want policy %#v", got.raw, tc.after)
				}
				mustOK(t, spacePolicyDelete(r.alice, sp))
				expectErr(t, spacePolicyGet(r.alice, sp), 400, "SpaceNotFound")
			})
		}
	})
}

// ---- memberspace members --------------------------------------------------

func TestSpacePolicyMembers(t *testing.T) {
	r := newSpacePolicyNet(t)

	// Reference: memberspace members / "adds and removes members, and the authority is not one of them".
	t.Run("adds and removes members and the authority is not one", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		putMember(t, r.alice, sp, r.bob, true, false)
		members := mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members")
		dids := map[string]bool{}
		for _, member := range members {
			dids[member["did"].(string)] = true
			if member["did"] == r.bob.did && (member["read"] != true || member["write"] != false) {
				t.Fatalf("bob access: %v", member)
			}
		}
		if dids[r.alice.did] || !dids[r.dan.did] || !dids[r.bob.did] {
			t.Fatalf("members: %v", members)
		}
		removeMember(t, r.alice, sp, r.bob)
		for _, member := range mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members") {
			if member["did"] == r.bob.did {
				t.Fatalf("bob still a member: %v", member)
			}
		}
	})

	// Reference: memberspace members / "refuses membership changes from a member other than the authority".
	t.Run("refuses membership changes from non-authorities", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		expectErr(t, putMemberRes(r.dan, sp, r.carol, true, true), 400, "NotAuthorized")
		expectErr(t, r.dan.post("com.atproto.memberspace.removeMembers", map[string]any{"space": sp, "dids": []string{r.dan.did}}), 400, "NotAuthorized")
	})

	// Reference: memberspace members / "refuses listMembers to a space credential and to a member other than the authority".
	t.Run("refuses listMembers to credential and non-authority", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol, r.dan}})
		cred := credentialFor(t, r.carol, r.pds1, sp)
		spacePolicyExpectFailure(t, cred.get(t, r.pds1, "com.atproto.memberspace.listMembers", map[string]string{"space": sp}))
		expectErr(t, spacePolicyListMembers(r.dan, sp), 400, "NotAuthorized")
	})

	// Reference: memberspace members / "putMembers replaces both access values".
	t.Run("putMembers replaces both access values", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		putMember(t, r.alice, sp, r.bob, true, false)
		putMember(t, r.alice, sp, r.bob, false, true)
		members := mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members")
		if len(members) != 1 || members[0]["did"] != r.bob.did || members[0]["read"] != false || members[0]["write"] != true {
			t.Fatalf("members after replacement: %v", members)
		}
	})

	// Reference: memberspace members / "refuses member methods on a space under another policy".
	t.Run("refuses member methods under another policy", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: personalPolicy()})
		expectErr(t, putMemberRes(r.alice, sp, r.bob, true, true), 400, "PolicyMismatch")
		expectErr(t, r.alice.post("com.atproto.memberspace.removeMembers", map[string]any{"space": sp, "dids": []string{r.bob.did}}), 400, "PolicyMismatch")
		expectErr(t, spacePolicyListMembers(r.alice, sp), 400, "PolicyMismatch")
	})

	// Reference: memberspace members / "removeMembers drops the member from the writer set".
	t.Run("removeMembers drops member from writer set", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{text: "from a member"}))
		if got := spacePolicyWriterDIDs(t, r, sp); !reflect.DeepEqual(got, []string{r.dan.did}) {
			t.Fatalf("writers before removal: %v", got)
		}
		removeMember(t, r.alice, sp, r.dan)
		if got := spacePolicyWriterDIDs(t, r, sp); len(got) != 0 {
			t.Fatalf("writers after removal: %v", got)
		}
	})

	// Reference: memberspace members / "putMembers drops the member from the writer set when it revokes write".
	t.Run("putMembers drops writer only when revoking write", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{text: "from a member"}))
		putMember(t, r.alice, sp, r.dan, true, true)
		if got := spacePolicyWriterDIDs(t, r, sp); !reflect.DeepEqual(got, []string{r.dan.did}) {
			t.Fatalf("writers after retaining write: %v", got)
		}
		putMember(t, r.alice, sp, r.dan, true, false)
		if got := spacePolicyWriterDIDs(t, r, sp); len(got) != 0 {
			t.Fatalf("writers after revoking write: %v", got)
		}
	})

	// Reference: memberspace members / "tells registered syncers of the writers a member change removes".
	t.Run("tells syncers which writers member changes remove", func(t *testing.T) {
		syncer := spacePolicySyncer(r, nil)
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan, r.bob, r.carol}})
		credentialWithNotify(t, r.carol, r.pds1, sp, &notifyReg{endpoint: syncer.url, token: "notify-token"})
		mustOK(t, doWrite(r.dan, sp, writeOpts{text: "from a member"}))
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "from a member"}))
		putMember(t, r.alice, sp, r.dan, true, false)
		removeMember(t, r.alice, sp, r.bob)
		r.net.waitSpaceJobs()

		var removed []string
		for _, update := range spacePolicyUpdates(syncer) {
			if update["$type"] == typeRepoRemoved {
				removed = append(removed, update["repo"].(string))
			}
		}
		sort.Strings(removed)
		want := []string{r.bob.did, r.dan.did}
		sort.Strings(want)
		if !reflect.DeepEqual(removed, want) {
			t.Fatalf("repoRemoved writers: got %v, want %v", removed, want)
		}
	})

	// Reference: memberspace members / "applies a batch of member changes in a single commit".
	t.Run("applies member batches in one commit", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishMembers": true})})
		memberOps := func() []map[string]any {
			t.Helper()
			res := mustOK(t, r.alice.get("com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": r.alice.did}))
			var out []map[string]any
			for _, op := range res.list("ops") {
				if op["collection"] == collMember {
					out = append(out, op)
				}
			}
			return out
		}
		mustOK(t, r.alice.post("com.atproto.memberspace.putMembers", map[string]any{
			"space": sp,
			"members": []map[string]any{
				{"did": r.bob.did, "read": true, "write": true},
				{"did": r.carol.did, "read": true, "write": false},
			},
		}))
		added := memberOps()
		if len(added) != 2 || added[0]["rev"] != added[1]["rev"] {
			t.Fatalf("member additions were not one commit: %v", added)
		}
		mustOK(t, r.alice.post("com.atproto.memberspace.removeMembers", map[string]any{"space": sp, "dids": []string{r.bob.did, r.carol.did}}))
		var removed []map[string]any
		for _, op := range memberOps() {
			if op["cid"] == nil {
				removed = append(removed, op)
			}
		}
		if len(removed) != 2 || removed[0]["rev"] != removed[1]["rev"] {
			t.Fatalf("member removals were not one commit: %v", removed)
		}
		if got := mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members"); len(got) != 0 {
			t.Fatalf("members after removeMembers: %v", got)
		}
	})

	// Reference: memberspace members / "takes the last entry for a member listed twice".
	t.Run("takes last entry for duplicate member", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishMembers": true})})
		mustOK(t, r.alice.post("com.atproto.memberspace.putMembers", map[string]any{
			"space": sp,
			"members": []map[string]any{
				{"did": r.bob.did, "read": true, "write": true},
				{"did": r.bob.did, "read": true, "write": false},
			},
		}))
		members := mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members")
		want := []map[string]any{{"did": r.bob.did, "read": true, "write": false}}
		if !reflect.DeepEqual(members, want) {
			t.Fatalf("last duplicate did not win: got %v, want %v", members, want)
		}
	})

	// Reference: memberspace members / "ignores a DID that is not a member, leaving it in the writer set".
	t.Run("ignores non-member leaving writer set alone", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publicWrite": true})})
		mustOK(t, doWrite(r.dan, sp, writeOpts{text: "from a non-member"}))
		if got := spacePolicyWriterDIDs(t, r, sp); !reflect.DeepEqual(got, []string{r.dan.did}) {
			t.Fatalf("writers before ignored removal: %v", got)
		}
		removeMember(t, r.alice, sp, r.dan)
		if got := spacePolicyWriterDIDs(t, r, sp); !reflect.DeepEqual(got, []string{r.dan.did}) {
			t.Fatalf("non-member writer was removed: %v", got)
		}
	})

	// Batch and cursor limits are endpoints of the same memberspace surface.
	t.Run("limits member batches to one hundred", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		put := make([]map[string]any, maxMemberBatch+1)
		dids := make([]string, maxMemberBatch+1)
		for i := range put {
			put[i] = map[string]any{"did": r.bob.did, "read": true, "write": true}
			dids[i] = r.bob.did
		}
		expectErr(t, r.alice.post("com.atproto.memberspace.putMembers", map[string]any{"space": sp, "members": put}), 400, "InvalidRequest")
		expectErr(t, r.alice.post("com.atproto.memberspace.removeMembers", map[string]any{"space": sp, "dids": dids}), 400, "InvalidRequest")
		if got := mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members"); len(got) != 0 {
			t.Fatalf("over-limit batch changed members: %v", got)
		}
	})

	t.Run("rejects malformed listMembers cursor", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		expectErr(t, r.alice.get("com.atproto.memberspace.listMembers", map[string]string{"space": sp, "limit": "1", "cursor": "not-a-did"}), 400, "InvalidCursor")
	})
}

// ---- policy state and migration -------------------------------------------

func TestSpacePolicyConfiguration(t *testing.T) {
	r := newSpacePolicyNet(t)

	// Reference: policy / "persists what createSpace was given".
	t.Run("persists managedspace createSpace policy", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: managedPolicy("did:web:example.com#forum", nil)})
		got := mustOK(t, spacePolicyGet(r.alice, sp))
		want := managedPolicy("did:web:example.com#forum", map[string]any{"publishPolicy": false})
		if got.str("space") != sp || !reflect.DeepEqual(got.body["policy"], want) {
			t.Fatalf("got %s, want %#v", got.raw, want)
		}
	})

	// Reference: policy / "fills in the defaults of an omitted configuration".
	t.Run("fills memberspace defaults", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(nil)})
		got := mustOK(t, spacePolicyGet(r.alice, sp))
		want := memberPolicy(map[string]any{"publicRead": false, "publicWrite": false, "publishPolicy": false, "publishMembers": false})
		if !reflect.DeepEqual(got.body["policy"], want) {
			t.Fatalf("got %#v, want %#v", got.body["policy"], want)
		}
	})

	// Reference: policy / "replaces the policy wholesale on update".
	t.Run("replaces policy wholesale on update", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{
			"publicRead": true, "allowedApps": []string{"app:x"}, "publishMembers": true,
		})})
		mustOK(t, spacePolicyUpdate(r.alice, sp, memberPolicy(map[string]any{"publicWrite": true})))
		got := mustOK(t, spacePolicyGet(r.alice, sp))
		want := memberPolicy(map[string]any{"publicRead": false, "publicWrite": true, "publishPolicy": false, "publishMembers": false})
		if !reflect.DeepEqual(got.body["policy"], want) {
			t.Fatalf("got %#v, want %#v", got.body["policy"], want)
		}
	})

	// Reference: policy / "keeps the member list across a configuration change".
	t.Run("keeps member list across configuration change", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		mustOK(t, spacePolicyUpdate(r.alice, sp, memberPolicy(map[string]any{"publicRead": true})))
		members := mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members")
		if len(members) != 1 || members[0]["did"] != r.bob.did {
			t.Fatalf("members after update: %v", members)
		}
	})

	// Reference: policy / "refuses an update from an account other than the authority".
	t.Run("refuses lifecycle management by non-authorities", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		expectErr(t, spacePolicyUpdate(r.bob, sp, memberPolicy(map[string]any{"publicRead": true})), 400, "NotAuthorized")
		expectErr(t, spacePolicyGet(r.dan, sp), 400, "NotAuthorized")
		expectErr(t, spacePolicyDelete(r.bob, sp), 400, "NotAuthorized")
	})

	// Reference: policy / "refuses an unrecognized policy".
	t.Run("refuses unrecognized policy", func(t *testing.T) {
		unknown := map[string]any{"$type": "com.example.whatever"}
		expectErr(t, r.alice.post("com.atproto.space.createSpace", map[string]any{"spaceType": testSpaceType, "skey": "unsupported-create", "policy": unknown}), 400, "UnsupportedPolicy")
		sp := createSpace(t, r.alice, spaceOpts{})
		expectErr(t, spacePolicyUpdate(r.alice, sp, unknown), 400, "UnsupportedPolicy")
	})

	// Reference: policy / "refuses a managingApp that does not name a service".
	for _, managingApp := range []string{"not-a-did-at-all", "did:web:example.com"} {
		t.Run("refuses managingApp without service "+managingApp, func(t *testing.T) {
			sp := createSpace(t, r.alice, spaceOpts{})
			spacePolicyExpectMessage(t, spacePolicyUpdate(r.alice, sp, managedPolicy(managingApp, nil)), 400, "must be a did#serviceId reference")
		})
	}

	// Reference: policy / "refuses the policy to a member with a space credential".
	t.Run("refuses policy to space credential", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)
		spacePolicyExpectFailure(t, cred.get(t, r.pds1, "com.atproto.space.getSpace", map[string]string{"space": sp}))
	})

	// Reference: policy / "refuses to answer for a space this host does not govern".
	t.Run("refuses to answer for space host does not govern", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		cred := credentialFor(t, r.bob, r.pds1, sp)
		expectErr(t, cred.get(t, r.pds2, "com.atproto.space.listWriters", map[string]string{"space": sp}), 400, "SpaceNotFound")
		spacePolicyExpectFailure(t, spacePolicyGet(r.bob, sp))
	})
}

func TestSpacePolicyMigration(t *testing.T) {
	r := newSpacePolicyNet(t)

	// Reference: policy migration / "discards the member list, and migrating back does not restore it".
	t.Run("discards member list permanently across migration", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		mustOK(t, spacePolicyUpdate(r.alice, sp, personalPolicy()))
		mustOK(t, spacePolicyUpdate(r.alice, sp, memberPolicy(nil)))
		if got := mustOK(t, spacePolicyListMembers(r.alice, sp)).list("members"); len(got) != 0 {
			t.Fatalf("members restored after migrating back: %v", got)
		}
		token := delegationTokenFor(t, r.bob, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceNotFound")
	})
}

// ---- publishing to readers ------------------------------------------------

func TestSpacePolicyPublishing(t *testing.T) {
	r := newSpacePolicyNet(t)

	// Reference: publishing to readers / "publishes the policy to readers".
	t.Run("publishes policy to readers", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishPolicy": true}), members: []*actor{r.carol}})
		policy := mustOK(t, spacePolicyGet(r.alice, sp)).body["policy"]
		cred := credentialFor(t, r.carol, r.pds1, sp)
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did, "collection": collPolicy}))
		records := res.list("records")
		want := map[string]any{"$type": collPolicy, "policy": policy}
		if len(records) != 1 || records[0]["rkey"] != "self" || !reflect.DeepEqual(records[0]["value"], want) {
			t.Fatalf("published policy: got %v, want value %#v", records, want)
		}
	})

	// Reference: publishing to readers / "keeps the published policy in sync, and withdraws it when unpublished".
	t.Run("syncs and withdraws published policy", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: managedPolicy("did:web:example.com#forum", map[string]any{"publishPolicy": true})})
		mustOK(t, spacePolicyUpdate(r.alice, sp, memberPolicy(map[string]any{"publicRead": true, "publishPolicy": true})))
		records := spacePolicyPublished(t, r.alice, sp, collPolicy)
		want := map[string]any{"$type": collPolicy, "policy": mustOK(t, spacePolicyGet(r.alice, sp)).body["policy"]}
		if len(records) != 1 || !reflect.DeepEqual(records[0]["value"], want) {
			t.Fatalf("updated policy: got %v, want %#v", records, want)
		}
		mustOK(t, spacePolicyUpdate(r.alice, sp, memberPolicy(nil)))
		if got := spacePolicyPublished(t, r.alice, sp, collPolicy); len(got) != 0 {
			t.Fatalf("unpublished policy survived: %v", got)
		}
	})

	// Reference: publishing to readers / "publishes the member list, keyed by member DID".
	t.Run("publishes member list keyed by DID", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishMembers": true})})
		putMember(t, r.alice, sp, r.bob, true, true)
		putMember(t, r.alice, sp, r.carol, true, true)
		putMember(t, r.alice, sp, r.carol, true, false)
		removeMember(t, r.alice, sp, r.bob)
		records := spacePolicyPublishedMembers(t, r.alice, sp)
		want := map[string]any{"$type": collMember, "read": true, "write": false}
		if len(records) != 1 || records[0]["rkey"] != r.carol.did || !reflect.DeepEqual(records[0]["value"], want) {
			t.Fatalf("published members: %v", records)
		}
	})

	// Reference: publishing to readers / "leaves the port of a localhost did:web unencoded in its record key".
	t.Run("unencodes localhost port in member record key", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishMembers": true})})
		did := "did:web:localhost%3A2583"
		mustOK(t, r.alice.post("com.atproto.memberspace.putMembers", map[string]any{
			"space": sp, "members": []map[string]any{{"did": did, "read": true, "write": true}},
		}))
		records := spacePolicyPublishedMembers(t, r.alice, sp)
		if len(records) != 1 || records[0]["rkey"] != "did:web:localhost:2583" {
			t.Fatalf("localhost member rkey: %v", records)
		}
		mustOK(t, r.alice.post("com.atproto.memberspace.removeMembers", map[string]any{"space": sp, "dids": []string{did}}))
		if got := spacePolicyPublishedMembers(t, r.alice, sp); len(got) != 0 {
			t.Fatalf("localhost member survived removal: %v", got)
		}
	})

	// Reference: publishing to readers / "publishes or withdraws the whole member list when publishMembers changes".
	t.Run("publishes and withdraws whole member list on config change", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		if got := spacePolicyPublishedMembers(t, r.alice, sp); len(got) != 0 {
			t.Fatalf("members unexpectedly published: %v", got)
		}
		mustOK(t, spacePolicyUpdate(r.alice, sp, memberPolicy(map[string]any{"publishMembers": true})))
		records := spacePolicyPublishedMembers(t, r.alice, sp)
		gotDIDs := make([]string, 0, len(records))
		for _, record := range records {
			gotDIDs = append(gotDIDs, record["rkey"].(string))
		}
		wantDIDs := []string{r.bob.did, r.carol.did}
		sort.Strings(wantDIDs)
		if !reflect.DeepEqual(gotDIDs, wantDIDs) {
			t.Fatalf("published members: got %v, want %v", gotDIDs, wantDIDs)
		}
		mustOK(t, spacePolicyUpdate(r.alice, sp, memberPolicy(nil)))
		if got := spacePolicyPublishedMembers(t, r.alice, sp); len(got) != 0 {
			t.Fatalf("withdrawn members survived: %v", got)
		}
	})

	// Reference: publishing to readers / "withdraws the published member list on migration".
	t.Run("withdraws published member list on migration", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishMembers": true}), members: []*actor{r.bob}})
		mustOK(t, spacePolicyUpdate(r.alice, sp, personalPolicy()))
		if got := spacePolicyPublishedMembers(t, r.alice, sp); len(got) != 0 {
			t.Fatalf("members survived migration: %v", got)
		}
	})

	// Reference: publishing to readers / "keeps the published records when the authority clears its repo".
	t.Run("keeps published records when authority clears repo", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{
			policy: memberPolicy(map[string]any{"publishPolicy": true, "publishMembers": true}), members: []*actor{r.bob},
		})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "own"}))
		mustOK(t, clearRecords(r.alice, sp))
		records := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did})).list("records")
		collections := make([]string, 0, len(records))
		for _, record := range records {
			collections = append(collections, record["collection"].(string))
		}
		sort.Strings(collections)
		want := []string{collMember, collPolicy}
		sort.Strings(want)
		if !reflect.DeepEqual(collections, want) {
			t.Fatalf("collections after clear: got %v, want %v", collections, want)
		}
		expectSetHashMatchesStore(t, r.alice, sp)
		before := repoState(t, r.alice, sp)
		mustOK(t, clearRecords(r.alice, sp))
		if after := repoState(t, r.alice, sp); !reflect.DeepEqual(after, before) {
			t.Fatalf("clearing only published records changed repo: before=%+v after=%+v", before, after)
		}
	})

	// Reference: publishing to readers / "notifies the space of what it publishes".
	t.Run("notifies space of published records", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishPolicy": true})})
		if got := spacePolicyAwaitWriter(t, r, sp, r.alice.did); !reflect.DeepEqual(got, []string{r.alice.did}) {
			t.Fatalf("published authority not the only writer: %v", got)
		}
	})

	// Reference: publishing to readers / "refuses direct writes of published records".
	t.Run("refuses direct writes of published records", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publishPolicy": true}), members: []*actor{r.bob}})
		record := map[string]any{"$type": collPolicy, "policy": personalPolicy()}
		refused := func(res xres) {
			t.Helper()
			spacePolicyExpectMessage(t, res, 400, "cannot be written directly")
		}
		refused(doPut(r.alice, sp, writeOpts{collection: collPolicy, rkey: "self", record: record}))
		refused(doWrite(r.bob, sp, writeOpts{collection: collMember, rkey: r.carol.did, record: map[string]any{"$type": collMember, "read": true, "write": true}}))
		refused(r.bob.post("com.atproto.space.applyWrites", map[string]any{
			"space": sp, "repo": r.bob.did,
			"writes": []map[string]any{{
				"$type": "com.atproto.space.applyWrites#create", "collection": collPolicy, "rkey": "self", "value": record,
			}},
		}))
		refused(doPut(r.alice, sp, writeOpts{collection: collPolicy, rkey: "self", record: record, validate: boolp(false)}))
		refused(doDel(r.alice, sp, collPolicy, "self"))
		if got := spacePolicyPublished(t, r.alice, sp, collPolicy); len(got) != 1 {
			t.Fatalf("direct delete withdrew published policy: %v", got)
		}
	})
}

// ---- personalspace --------------------------------------------------------

func TestSpacePolicyPersonalspace(t *testing.T) {
	r := newSpacePolicyNet(t)

	// Reference: personalspace policy / "authorizes only the authority to read".
	t.Run("authorizes only authority to read", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: personalPolicy()})
		if cred := credentialFor(t, r.alice, r.pds1, sp); cred.credential == "" {
			t.Fatal("authority did not receive a credential")
		}
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceNotFound")
	})

	// Reference: personalspace policy / "tracks no writer but the authority".
	t.Run("tracks no writer but authority", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: personalPolicy()})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "my bookmark"}))
		// Bob still owns his write locally; only the authority refuses its
		// notification, so no syncer discovers it.
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "not tracked"}))
		r.net.waitSpaceJobs()
		if got := spacePolicyWriterDIDs(t, r, sp); !reflect.DeepEqual(got, []string{r.alice.did}) {
			t.Fatalf("personalspace writer set: %v", got)
		}
	})
}

// ---- credential mint gates ------------------------------------------------

func TestSpacePolicyCredentialMintGates(t *testing.T) {
	r := newSpacePolicyNet(t)
	hostAud := space.SpaceHostAud(r.alice.did)

	// Reference: credential mint gates / "mints for a non-member when read access is public".
	t.Run("mints for non-member when public read", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publicRead": true})})
		if cred := credentialFor(t, r.carol, r.pds1, sp); cred.credential == "" {
			t.Fatal("no credential minted")
		}
	})

	// Reference: credential mint gates / "mints without a delegation token when read access is public".
	t.Run("public read mints without delegation token", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publicRead": true})})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "for anyone"}))
		cred := publicCredential(t, r.pds1, sp, "")
		res := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}))
		if got := res.list("records"); len(got) != 1 {
			t.Fatalf("public records: %v", got)
		}
	})

	// Reference: credential mint gates / "hides a memberspace space from a request without a delegation token"
	// and the equivalent personalspace case.
	for _, tc := range []struct {
		name   string
		policy map[string]any
	}{{"memberspace", memberPolicy(nil)}, {"personalspace", personalPolicy()}} {
		t.Run("hides "+tc.name+" without delegation token", func(t *testing.T) {
			sp := createSpace(t, r.alice, spaceOpts{policy: tc.policy})
			expectErr(t, spacePolicyMint(t, r.pds1, sp, "", ""), 400, "SpaceNotFound")
		})
	}

	// Reference: credential mint gates / "hides a space from a request without a delegation token before checking the app".
	t.Run("account check precedes public request app check", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"allowedApps": []string{"https://app.example.com/client-metadata.json"}})})
		expectErr(t, spacePolicyMint(t, r.pds1, sp, "", ""), 400, "SpaceNotFound")
	})

	// Reference: credential mint gates / "refuses a request without a delegation token or attestation when apps are restricted".
	t.Run("public restricted app requires attestation without token", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publicRead": true, "allowedApps": []string{"https://app.example.com/client-metadata.json"}})})
		expectErr(t, spacePolicyMint(t, r.pds1, sp, "", ""), 400, "AppNotAuthorized")
	})

	// Reference: credential mint gates / "hides the space from a non-member when read access is not public".
	t.Run("hides space from non-member", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceNotFound")
	})

	// Reference: credential mint gates / "hides the space from a non-member before checking the app".
	t.Run("non-member check precedes app check", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"allowedApps": []string{"https://app.example.com/client-metadata.json"}})})
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceNotFound")
	})

	// Reference: credential mint gates / "hides the space from a member without read access".
	t.Run("hides space from member without read", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{})
		putMember(t, r.alice, sp, r.carol, false, true)
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceNotFound")
	})

	// Reference: credential mint gates / "always admits the authority, whatever the policy".
	t.Run("always admits authority", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: managedPolicy("did:web:unreachable.invalid#forum", nil)})
		if cred := credentialFor(t, r.alice, r.pds1, sp); cred.credential == "" {
			t.Fatal("authority did not receive a credential")
		}
	})

	// Reference: credential mint gates / "refuses when apps are restricted and no attestation is presented".
	t.Run("restricted app requires attestation", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publicRead": true, "allowedApps": []string{"https://app.example.com/client-metadata.json"}})})
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "AppNotAuthorized")
	})

	spaceFor := func(t *testing.T, app *mockClientApp) string {
		t.Helper()
		return createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publicRead": true, "allowedApps": []string{app.clientID}})})
	}

	// Reference: credential mint gates / client attestation / "mints for an allow-listed app that signs with its published key".
	t.Run("mints for allow-listed attested app", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := spaceFor(t, app)
		token := delegationTokenFor(t, r.carol, sp)
		res := spacePolicyMint(t, r.pds1, sp, token, app.attest(t, hostAud, attestOpts{}))
		if mustOK(t, res).str("credential") == "" {
			t.Fatalf("no credential: %s", res.raw)
		}
	})

	// Reference: credential mint gates / client attestation / "refuses an attestation signed by a key the app does not publish".
	t.Run("refuses attestation signed by unpublished key", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := spaceFor(t, app)
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
		spacePolicyExpectMessage(t, spacePolicyMint(t, r.pds1, sp, token, forged), 400, "Invalid client attestation")
	})

	// Reference: credential mint gates / client attestation / "refuses an attestation addressed to another authority".
	t.Run("refuses attestation for another authority", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := spaceFor(t, app)
		token := delegationTokenFor(t, r.carol, sp)
		res := spacePolicyMint(t, r.pds1, sp, token, app.attest(t, space.SpaceHostAud(r.bob.did), attestOpts{}))
		spacePolicyExpectMessage(t, res, 400, "Invalid client attestation")
	})

	// Reference: credential mint gates / client attestation / "refuses an attestation from an app that is not allow-listed".
	t.Run("refuses attestation from non-allow-listed app", func(t *testing.T) {
		allowed := r.net.newMockClientApp(clientAppOpts{})
		other := r.net.newMockClientApp(clientAppOpts{})
		other.installOn(r.pds1)
		sp := spaceFor(t, allowed)
		token := delegationTokenFor(t, r.carol, sp)
		res := spacePolicyMint(t, r.pds1, sp, token, other.attest(t, hostAud, attestOpts{}))
		expectErr(t, res, 400, "AppNotAuthorized")
	})

	// Reference: credential mint gates / client attestation / "mints for an allow-listed app without a delegation token".
	t.Run("mints for attested app without token", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := spaceFor(t, app)
		cred := publicCredential(t, r.pds1, sp, app.attest(t, hostAud, attestOpts{}))
		if cred.credential == "" {
			t.Fatal("no credential minted")
		}
	})

	// Reference: credential mint gates / client attestation / "refuses an expired attestation".
	t.Run("refuses expired attestation", func(t *testing.T) {
		app := r.net.newMockClientApp(clientAppOpts{})
		app.installOn(r.pds1)
		sp := spaceFor(t, app)
		token := delegationTokenFor(t, r.carol, sp)
		res := spacePolicyMint(t, r.pds1, sp, token, app.attest(t, hostAud, attestOpts{expiresIn: -120}))
		spacePolicyExpectMessage(t, res, 400, "Invalid client attestation")
	})
}

// ---- managedspace ---------------------------------------------------------

func TestSpacePolicyManagedspace(t *testing.T) {
	r := newSpacePolicyNet(t)
	spaceWith := func(t *testing.T, app string) string {
		t.Helper()
		return createSpace(t, r.alice, spaceOpts{policy: managedPolicy(app, nil)})
	}

	// Reference: managedspace policy / "admits a user the managing app authorizes".
	t.Run("admits user managing app authorizes", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 200, map[string]any{"read": true, "write": true}
		})
		sp := spaceWith(t, app.serviceRef())
		if cred := credentialFor(t, r.carol, r.pds1, sp); cred.credential == "" {
			t.Fatal("no credential minted")
		}
		asked := app.callsTo(lxmCheckAccess)
		if len(asked) != 1 || !reflect.DeepEqual(asked[0].body, map[string]any{"space": sp, "repo": r.carol.did}) {
			t.Fatalf("checkAccess calls: %v", asked)
		}
		if !strings.HasPrefix(asked[0].auth, "Bearer ") || spacePolicyServiceAuthLXM(t, asked[0].auth) != lxmCheckAccess {
			t.Fatalf("checkAccess service auth: %q", asked[0].auth)
		}
		if _, hasClientID := asked[0].body["clientId"]; hasClientID {
			t.Fatalf("unattested read unexpectedly sent clientId: %v", asked[0].body)
		}
	})

	// Reference: managedspace policy / "asks the managing app about a request with no delegation token".
	t.Run("checks public request with optional repo omitted", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 200, map[string]any{"read": true, "write": false}
		})
		sp := spaceWith(t, app.serviceRef())
		if cred := publicCredential(t, r.pds1, sp, ""); cred.credential == "" {
			t.Fatal("no credential minted")
		}
		asked := app.callsTo(lxmCheckAccess)
		if len(asked) != 1 || !reflect.DeepEqual(asked[0].body, map[string]any{"space": sp}) {
			t.Fatalf("checkAccess without delegation token: %v", asked)
		}
	})

	// The GET check carries an attested client_id only for credential reads;
	// notifyRepoUpdate has no app identity and so never supplies one.
	t.Run("sends clientId on attested reads but not writes", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 200, map[string]any{"read": true, "write": true}
		})
		client := r.net.newMockClientApp(clientAppOpts{})
		client.installOn(r.pds1)
		sp := spaceWith(t, app.serviceRef())
		token := delegationTokenFor(t, r.carol, sp)
		res := spacePolicyMint(t, r.pds1, sp, token, client.attest(t, space.SpaceHostAud(r.alice.did), attestOpts{}))
		mustOK(t, res)
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "managed write"}))
		spacePolicyAwaitWriter(t, r, sp, r.bob.did)
		asked := app.callsTo(lxmCheckAccess)
		if len(asked) != 2 {
			t.Fatalf("checkAccess calls: %v", asked)
		}
		readWant := map[string]any{"space": sp, "repo": r.carol.did, "clientId": client.clientID}
		writeWant := map[string]any{"space": sp, "repo": r.bob.did}
		if !reflect.DeepEqual(asked[0].body, readWant) || !reflect.DeepEqual(asked[1].body, writeWant) {
			t.Fatalf("checkAccess bodies: read=%v write=%v", asked[0].body, asked[1].body)
		}
	})

	// Reference: managedspace policy / "refuses a user the managing app declines".
	t.Run("refuses user managing app declines", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 200, map[string]any{"read": false, "write": false}
		})
		sp := spaceWith(t, app.serviceRef())
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceNotFound")
		expectErr(t, spacePolicyMint(t, r.pds1, sp, "", ""), 400, "SpaceNotFound")
	})

	// Reference: managedspace policy / "fails without a credential when the managing app errors".
	t.Run("managing app error is upstream failure not refusal", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 500, map[string]any{"error": "InternalError"}
		})
		sp := spaceWith(t, app.serviceRef())
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 502, "UpstreamFailure")
	})

	// Reference: managedspace policy / "fails without a credential when the managing app cannot be resolved".
	t.Run("unresolvable managing app is upstream failure", func(t *testing.T) {
		sp := spaceWith(t, "did:web:nonexistent.invalid#forum")
		token := delegationTokenFor(t, r.carol, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 502, "UpstreamFailure")
	})

	// Reference: managedspace policy / "keeps a registration through a managing app outage, and withdraws it on refusal".
	t.Run("keeps registration through outage and withdraws on refusal", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 200, map[string]any{"read": true, "write": true}
		})
		syncer := spacePolicySyncer(r, nil)
		sp := spaceWith(t, app.serviceRef())
		reg := &notifyReg{endpoint: syncer.url, token: "notify-token"}
		credentialWithNotify(t, r.carol, r.pds1, sp, reg)
		if got := spacePolicyCountRows(t, r.pds1, &models.SpaceNotifyRegistration{}, "did = ? AND space = ?", r.alice.did, sp); got != 1 {
			t.Fatalf("registrations after authorization: %d", got)
		}

		app.setRespond(func(*http.Request, mockCall) (int, any) { return 500, map[string]any{"error": "InternalError"} })
		res := exchangeWith(t, r.pds1, sp, delegationTokenFor(t, r.carol, sp), newP256Key(t), "", reg)
		expectErr(t, res, 502, "UpstreamFailure")
		if got := spacePolicyCountRows(t, r.pds1, &models.SpaceNotifyRegistration{}, "did = ? AND space = ?", r.alice.did, sp); got != 1 {
			t.Fatalf("outage withdrew registration: %d", got)
		}

		app.setRespond(func(*http.Request, mockCall) (int, any) { return 200, map[string]any{"read": false, "write": false} })
		res = exchangeWith(t, r.pds1, sp, delegationTokenFor(t, r.carol, sp), newP256Key(t), "", reg)
		expectErr(t, res, 400, "SpaceNotFound")
		if got := spacePolicyCountRows(t, r.pds1, &models.SpaceNotifyRegistration{}, "did = ? AND space = ?", r.alice.did, sp); got != 0 {
			t.Fatalf("refused authorization retained registration: %d", got)
		}
	})

	// Reference: managedspace policy / "retries a write notification through a managing app outage".
	t.Run("retries write notification through outage", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 500, map[string]any{"error": "InternalError"}
		})
		sp := spaceWith(t, app.serviceRef())
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "retry me"}))
		pending := func() int64 {
			return spacePolicyCountRows(t, r.pds2, &models.SpaceNotificationRetry{}, "repo = ? AND space = ?", r.bob.did, sp)
		}
		if got := pending(); got != 1 {
			t.Fatalf("pending notifications after outage: %d", got)
		}
		for _, did := range spacePolicyWriterDIDs(t, r, sp) {
			if did == r.bob.did {
				t.Fatal("authority recorded write before managing app admission")
			}
		}

		app.setRespond(func(*http.Request, mockCall) (int, any) { return 200, map[string]any{"read": false, "write": true} })
		if err := r.pds2.s.db.Exec(context.Background(), "UPDATE space_notification_retries SET retry_at = 0 WHERE repo = ? AND space = ?", nil, r.bob.did, sp).Error; err != nil {
			t.Fatal(err)
		}
		r.pds2.s.retrySpaceNotifications(context.Background())
		if got := pending(); got != 0 {
			t.Fatalf("pending notifications after retry: %d", got)
		}
		spacePolicyAwaitWriter(t, r, sp, r.bob.did)
	})

	// Reference: managedspace policy / "records a writer the managing app admits, even one it does not let read".
	t.Run("records admitted writer who cannot read", func(t *testing.T) {
		app := r.net.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			return 200, map[string]any{"read": false, "write": true}
		})
		sp := spaceWith(t, app.serviceRef())
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "admitted by the managing app"}))
		spacePolicyAwaitWriter(t, r, sp, r.bob.did)
		asked := app.callsTo(lxmCheckAccess)
		if len(asked) == 0 || !reflect.DeepEqual(asked[0].body, map[string]any{"space": sp, "repo": r.bob.did}) {
			t.Fatalf("checkAccess calls: %v", asked)
		}
		token := delegationTokenFor(t, r.bob, sp)
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceNotFound")
	})
}

// ---- deletion -------------------------------------------------------------

func TestSpacePolicyDeletion(t *testing.T) {
	r := newSpacePolicyNet(t)

	// Reference: deletion / "purges the authority own repo and keeps a tombstone".
	t.Run("purges authority repo and keeps tombstone", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		blob, blobCID := spacePolicyUploadBlob(t, r.alice, []byte("space blob for deletion"))
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "doomed", record: map[string]any{
			"$type": testCollection, "text": "authority record", "image": blob,
		}}))
		if !spacePolicyBlobExists(t, r.alice, blobCID) {
			t.Fatal("blob missing before deletion")
		}
		mustOK(t, spacePolicyDelete(r.alice, sp))

		row := spacePolicySpaceRow(t, r.pds1, r.alice.did, sp)
		if row == nil || row.DeletedAt == nil {
			t.Fatalf("no tombstone: %+v", row)
		}
		if got := spacePolicyCountRows(t, r.pds1, &models.SpacePolicy{}, "did = ? AND uri = ?", r.alice.did, sp); got != 0 {
			t.Fatalf("policies survived: %d", got)
		}
		if got := spacePolicyCountRows(t, r.pds1, &models.SpaceRecord{}, "did = ? AND space = ?", r.alice.did, sp); got != 0 {
			t.Fatalf("records survived: %d", got)
		}
		if got := spacePolicyCountRows(t, r.pds1, &models.MemberspaceMember{}, "did = ? AND space = ?", r.alice.did, sp); got != 0 {
			t.Fatalf("members survived: %d", got)
		}
		if spacePolicyBlobExists(t, r.alice, blobCID) {
			t.Fatal("blob survived deletion")
		}
		expectErr(t, spacePolicyGet(r.alice, sp), 400, "SpaceNotFound")
		mustOK(t, spacePolicyDelete(r.alice, sp))

		// The store-level guard behind the reference's deletion-race case:
		// removed state cannot be resurrected by a late registration.
		var xe *xrpcError
		err := r.pds1.s.spaceStore(nil, r.alice.did).putNotifyRegistration(sp, "https://syncer.example.com", "late", isoTime(time.Now().Add(time.Hour)))
		if !errors.As(err, &xe) || xe.Name != "SpaceDeleted" {
			t.Fatalf("late registration error: %v", err)
		}
	})

	// Reference: deletion / "answers SpaceDeleted on reauthorization".
	t.Run("answers SpaceDeleted on reauthorization", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		token := delegationTokenFor(t, r.carol, sp)
		mustOK(t, spacePolicyDelete(r.alice, sp))
		expectErr(t, spacePolicyMint(t, r.pds1, sp, token, ""), 400, "SpaceDeleted")
	})

	// Reference: deletion / "answers SpaceDeleted to a request without a delegation token".
	t.Run("answers SpaceDeleted without delegation token", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{policy: memberPolicy(map[string]any{"publicRead": true})})
		mustOK(t, spacePolicyDelete(r.alice, sp))
		expectErr(t, spacePolicyMint(t, r.pds1, sp, "", ""), 400, "SpaceDeleted")
	})

	// Reference: deletion / "answers SpaceDeleted regardless of the request authorization".
	t.Run("answers SpaceDeleted before request authorization", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, spacePolicyDelete(r.alice, sp))
		expectErr(t, spacePolicyMint(t, r.pds1, sp, "not-a-delegation-token", ""), 400, "SpaceDeleted")
	})

	// Reference: deletion / "notifies registered syncers, including lapsed registrations".
	t.Run("notifies registered syncers including lapsed", func(t *testing.T) {
		syncer := spacePolicySyncer(r, nil)
		lapsed := spacePolicySyncer(r, nil)
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		for _, service := range []*mockService{syncer, lapsed} {
			credentialWithNotify(t, r.carol, r.pds1, sp, &notifyReg{endpoint: service.url, token: "notify-token"})
		}
		if err := r.pds1.s.db.Exec(context.Background(),
			"UPDATE space_notify_registrations SET expires_at = ? WHERE did = ? AND space = ? AND endpoint = ?", nil,
			"2000-01-01T00:00:00.000Z", r.alice.did, sp, lapsed.url,
		).Error; err != nil {
			t.Fatal(err)
		}
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "before deletion"}))
		r.net.waitSpaceJobs()
		if !awaitCond(t, func() bool {
			updates := spacePolicyUpdates(lapsed)
			return len(updates) == 1 && updates[0]["$type"] == typeRegistrationExpired
		}) {
			t.Fatalf("lapsed registration did not receive its expiry notice: %v", spacePolicyUpdates(lapsed))
		}
		mustOK(t, spacePolicyDelete(r.alice, sp))
		r.net.waitSpaceJobs()
		for _, service := range []*mockService{syncer, lapsed} {
			service := service
			if !awaitCond(t, func() bool {
				calls := service.callsTo(lxmNotifySpaceUpdate)
				if len(calls) == 0 {
					return false
				}
				update, _ := calls[len(calls)-1].body["update"].(map[string]any)
				return update["$type"] == typeSpaceDeleted
			}) {
				t.Fatalf("deletion was not delivered to %s", service.url)
			}
		}

		for _, service := range []*mockService{syncer, lapsed} {
			calls := service.callsTo(lxmNotifySpaceUpdate)
			if len(calls) == 0 {
				t.Fatalf("no space updates for %s", service.url)
			}
			last := calls[len(calls)-1]
			want := map[string]any{"$type": typeSpaceDeleted}
			if last.body["space"] != sp || last.body["token"] != "notify-token" || !reflect.DeepEqual(last.body["update"], want) {
				t.Fatalf("deletion notice: %v", last.body)
			}
			if last.auth != "" {
				t.Fatalf("space deletion unexpectedly used service auth: %q", last.auth)
			}
		}
		updates := spacePolicyUpdates(lapsed)
		if len(updates) != 2 || updates[0]["$type"] != typeRegistrationExpired || !reflect.DeepEqual(updates[1], map[string]any{"$type": typeSpaceDeleted}) {
			t.Fatalf("lapsed registration updates: %v", updates)
		}
	})

	// Reference: deletion / "leaves a member repo untouched".
	t.Run("leaves member repo untouched", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "member write"}))
		mustOK(t, spacePolicyDelete(r.alice, sp))
		r.net.waitSpaceJobs()
		if row := spacePolicySpaceRow(t, r.pds2, r.bob.did, sp); row == nil || row.DeletedAt != nil {
			t.Fatalf("member space row: %+v", row)
		}
		if got := spacePolicyCountRows(t, r.pds2, &models.SpaceRecord{}, "did = ? AND space = ?", r.bob.did, sp); got != 1 {
			t.Fatalf("member records after deletion: %d", got)
		}
	})

	// Reference: deletion / "allows re-creating a deleted space, with a fresh policy".
	t.Run("recreates deleted space with fresh policy", func(t *testing.T) {
		const skey = "recreate"
		sp := createSpace(t, r.alice, spaceOpts{skey: skey, policy: memberPolicy(map[string]any{"publicRead": true, "publicWrite": true})})
		mustOK(t, spacePolicyDelete(r.alice, sp))
		if recreated := createSpace(t, r.alice, spaceOpts{skey: skey}); recreated != sp {
			t.Fatalf("recreated as %s, want %s", recreated, sp)
		}
		got := mustOK(t, spacePolicyGet(r.alice, sp))
		policy, _ := got.body["policy"].(map[string]any)
		if policy["publicRead"] != false || policy["publicWrite"] != false {
			t.Fatalf("old public access survived recreation: %v", got.body["policy"])
		}
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "after recreation"}))
	})
}
