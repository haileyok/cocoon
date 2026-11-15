package server

// Ported from packages/pds/tests/space-scope.test.ts
// (bluesky-social/atproto @ d4def6e9).
//
// The reference unit-tests assertSpaceRead (api/com/atproto/space/util.ts)
// with synthesized auth outputs. Cocoon applies the same rule in
// server/space_util.go (assertSpaceRead) inside spaceReadAuth, reached through
// the read endpoints, so each reference case becomes a
// com.atproto.space.getRecord read of the caller's own repo versus another
// member's repo:
//
//   - oauthAuth(scope) -> createOAuthActor(name, scope), as an app the user
//     granted it to would be;
//   - accessAuth()     -> createActor(name), a legacy session;
//   - credentialAuth() -> credentialFor, the credential chain the reference
//     builds in _space.ts;
//   - a throw           -> the 400 RepoNotFound the reference's
//     InvalidRequestError('RepoNotFound') surfaces as, or, for a credential
//     scoped to another space, InvalidCredential.
//
// assertSpaceRead runs before any record is looked up, so the reads are of a
// record that does not exist: what distinguishes a permitted read from a
// refused one is the error that comes back — RecordNotFound ("could not locate
// record") means assertSpaceRead passed, RepoNotFound ("could not find repo")
// means it threw. Both are 400s, the same deliberate indirection the
// reference's `Could not find repo` error documents.
//
// Following the reference's intent: an account reads only its own repo in a
// space however wide its grant; a space credential reads any repo in its own
// space and no other.
//
// The second suite here, TestSpaceScopeManagementGrants, has no counterpart in
// the reference tests: the November 12 implementation added `manage=` grants to
// the space lifecycle methods, and only the space type's declared collections
// (auth.test.ts) and clearRecords' per-collection delete (also auth.test.ts)
// are covered there. It is kept in this file because it is scope enforcement,
// not protocol behavior.

import (
	"net/http"
	"testing"
)

// scopeRead makes one com.atproto.space.getRecord read of the named repo.
func scopeRead(a *actor, sp, repo string) xres {
	return a.get("com.atproto.space.getRecord", map[string]string{
		"space": sp, "repo": repo, "collection": testCollection, "rkey": "absent",
	})
}

// scopeReadOK asserts a read got past assertSpaceRead: the only error it may
// come back with is the missing record's.
func scopeReadOK(t *testing.T, r xres) {
	t.Helper()
	if r.status == 403 && r.errName() == "InsufficientScope" {
		t.Fatalf("read was refused for scope, not for repo: %s", r.raw)
	}
	if r.status == 400 && r.errName() == "RepoNotFound" {
		t.Fatalf("read was refused as another repo: %s", r.raw)
	}
	if r.status == 400 && r.errName() != "RecordNotFound" {
		t.Fatalf("unexpected read failure: %s", r.raw)
	}
	if r.status != 400 {
		t.Fatalf("unexpected read result: %d %s", r.status, r.raw)
	}
}

// scopeReadRefused asserts a read was refused as another member's repo.
func scopeReadRefused(t *testing.T, r xres) {
	t.Helper()
	expectErr(t, r, 400, "RepoNotFound")
	if want := "Could not find repo for DID"; len(r.message()) < len(want) || r.message()[:len(want)] != want {
		t.Fatalf("want a %q message, got %q", want, r.message())
	}
}

func TestSpaceScopeAssertSpaceRead(t *testing.T) {
	n := newSpaceNet(t)
	authority := n.newPDS()
	owner := authority.createActor("owner")   // the space authority, on its own host
	member := authority.createActor("member") // another member's repo to reach

	sp := createSpace(t, owner, spaceOpts{members: []*actor{member}})

	t.Run("reads the caller's own repo with only read_self", func(t *testing.T) {
		user := authority.createOAuthActor("readself", "space:"+testSpaceType+"?authority=*&action=read_self")
		scopeReadOK(t, scopeRead(user, sp, user.did))
	})

	t.Run("refuses another repo with only read_self", func(t *testing.T) {
		user := authority.createOAuthActor("otherrepo", "space:"+testSpaceType+"?authority=*&action=read_self")
		scopeReadOK(t, scopeRead(user, sp, user.did))
		scopeReadRefused(t, scopeRead(user, sp, owner.did))
	})

	t.Run("refuses another repo even with whole-space read", func(t *testing.T) {
		// `read` covers the caller's own repo and buys a delegation token;
		// reaching another member's repo takes a credential the authority
		// issued.
		user := authority.createOAuthActor("wholeread", "space:"+testSpaceType+"?authority=*&action=read")
		scopeReadOK(t, scopeRead(user, sp, user.did))
		scopeReadRefused(t, scopeRead(user, sp, owner.did))
	})

	t.Run("refuses another repo on a legacy access token", func(t *testing.T) {
		// Legacy tokens skip the scope check, so the self-only rule is the only
		// thing standing between one account and another member's repo.
		user := authority.createActor("legacy")
		scopeReadOK(t, scopeRead(user, sp, user.did))
		scopeReadRefused(t, scopeRead(user, sp, owner.did))
	})

	t.Run("read_self is not narrowed by collection", func(t *testing.T) {
		user := authority.createOAuthActor("collread", "space:"+testSpaceType+"?authority=*&action=read_self&collection=com.atmoboards.thread")
		scopeReadOK(t, scopeRead(user, sp, user.did))
	})

	t.Run("a space credential reads any repo in its own space", func(t *testing.T) {
		// Mint the credential as a member the authority admits, then use it to
		// read the authority's own repo: the reader's identity is the
		// credential, not the account that exchanged for it. A credential
		// scoped to this space does not reach another space's repos, including
		// the same authority's.
		cred := credentialFor(t, member, authority, sp)
		scopeReadOK(t, cred.get(t, authority, "com.atproto.space.getRecord", map[string]string{
			"space": sp, "repo": owner.did, "collection": testCollection, "rkey": "absent",
		}))
		otherSpace := createSpace(t, owner, spaceOpts{skey: "other-space"})
		authExpectMsg(t, cred.get(t, authority, "com.atproto.space.getRecord", map[string]string{
			"space": otherSpace, "repo": owner.did, "collection": testCollection, "rkey": "absent",
		}), 400, "InvalidCredential", "not scoped to this space")
	})
}

// scopeRawPost posts an archive as a, with an explicit content type:
// importRepo and importSpaceMeta take STAR archives rather than JSON, so the
// JSON request helpers cannot drive them.
func scopeRawPost(t *testing.T, a *actor, nsid, contentType string, body []byte) xres {
	t.Helper()
	path := "/xrpc/" + nsid
	headers := map[string]string{"Content-Type": contentType}
	if a.oauth == nil {
		for k, v := range a.auth() {
			headers[k] = v
		}
		return a.pds.net.do(http.MethodPost, a.pds.url, nsid, nil, body, headers)
	}
	htu := "https://" + a.pds.s.config.Hostname + path
	var res xres
	for i := 0; i < 2; i++ {
		headers["Authorization"] = "DPoP " + a.oauth.token
		headers["DPoP"] = a.oauth.proof(t, http.MethodPost, htu)
		res = a.pds.net.do(http.MethodPost, a.pds.url, nsid, nil, body, headers)
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

// TestSpaceScopeManagementGrants covers the space lifecycle methods' OAuth
// grants, which the November 12 implementation checks and no reference test
// exercises: `manage=create` to create or import a space, `manage=update` to
// change it, its member list or its writer set, `manage=delete` to delete it,
// `read_self` for the authority's own state, and per-collection record grants
// for the archives it imports.
func TestSpaceScopeManagementGrants(t *testing.T) {
	n := newSpaceNet(t)
	authority := n.newPDS()
	alice := authority.createActor("alice") // the space authority
	dan := authority.createActor("dan")     // a member, for putMembers and removeWriter

	// A grant naming alice's own authority, as one issued for her spaces would
	// after self resolution.
	grant := func(params string) string {
		return "atproto space:" + testSpaceType + "?authority=" + alice.did + "&" + params
	}

	t.Run("creates a space only with manage=create", func(t *testing.T) {
		body := map[string]any{"spaceType": testSpaceType, "skey": "oauth-create", "policy": memberPolicy(nil)}
		expectErr(t, authOAuth(alice, grant("manage=update")).post("com.atproto.space.createSpace", body), 403, "InsufficientScope")
		mustOK(t, authOAuth(alice, grant("manage=create")).post("com.atproto.space.createSpace", body))
	})

	t.Run("updates a space only with manage=update", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		body := map[string]any{"space": sp, "policy": memberPolicy(map[string]any{"publicRead": true})}

		expectErr(t, authOAuth(alice, grant("manage=create")).post("com.atproto.space.updateSpace", body), 403, "InsufficientScope")
		mustOK(t, authOAuth(alice, grant("manage=update")).post("com.atproto.space.updateSpace", body))

		// The policy really changed, so the grant gated the write rather than
		// the call being a no-op.
		got := mustOK(t, alice.get("com.atproto.space.getSpace", map[string]string{"space": sp}))
		if policy, _ := got.body["policy"].(map[string]any); policy["publicRead"] != true {
			t.Fatalf("policy not updated: %s", got.raw)
		}
	})

	t.Run("deletes a space only with manage=delete", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "oauth-delete"})
		body := map[string]any{"space": sp}

		expectErr(t, authOAuth(alice, grant("manage=update")).post("com.atproto.space.deleteSpace", body), 403, "InsufficientScope")
		mustOK(t, authOAuth(alice, grant("manage=delete")).post("com.atproto.space.deleteSpace", body))
		n.waitSpaceJobs()
	})

	t.Run("manages the member list and writer set only with manage=update", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})

		expectErr(t, putMemberRes(authOAuth(alice, grant("manage=create")), sp, dan, true, false), 403, "InsufficientScope")
		expectErr(t, removeWriter(authOAuth(alice, grant("manage=create")), sp, dan), 403, "InsufficientScope")
		expectErr(t, authOAuth(alice, grant("manage=create")).post("com.atproto.memberspace.removeMembers",
			map[string]any{"space": sp, "dids": []string{dan.did}}), 403, "InsufficientScope")

		oa := authOAuth(alice, grant("manage=update"))
		mustOK(t, putMemberRes(oa, sp, dan, true, false))
		mustOK(t, removeWriter(oa, sp, dan))
		mustOK(t, oa.post("com.atproto.memberspace.removeMembers", map[string]any{"space": sp, "dids": []string{dan.did}}))
	})

	t.Run("reads the authority's own state on read_self", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "state"}))

		// A write grant confers no read of the policy, and the export is the
		// authority's own state too.
		writeOnly := authOAuth(alice, grant("collection=*&action=create"))
		expectErr(t, writeOnly.get("com.atproto.space.getSpace", map[string]string{"space": sp}), 403, "InsufficientScope")
		expectErr(t, writeOnly.get("com.atproto.space.exportSpaceMeta", map[string]string{"space": sp}), 403, "InsufficientScope")

		reader := authOAuth(alice, grant("action=read_self"))
		got := mustOK(t, reader.get("com.atproto.space.getSpace", map[string]string{"space": sp}))
		if policy, _ := got.body["policy"].(map[string]any); policy["$type"] != memberspacePolicy {
			t.Fatalf("unexpected policy: %s", got.raw)
		}
		mustOK(t, reader.get("com.atproto.space.exportSpaceMeta", map[string]string{"space": sp}))
	})

	t.Run("imports space meta with manage=create and manage=update", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{members: []*actor{dan}})
		archive := mustOK(t, alice.get("com.atproto.space.exportSpaceMeta", map[string]string{"space": sp})).raw

		// Importing both creates the space on this host and sets its
		// configuration, so it asks for both grants.
		for _, params := range []string{"manage=create", "manage=update"} {
			res := scopeRawPost(t, authOAuth(alice, grant(params)), "com.atproto.space.importSpaceMeta", starContentType, archive)
			expectErr(t, res, 403, "InsufficientScope")
		}
		mustOK(t, scopeRawPost(t, authOAuth(alice, grant("manage=create&manage=update")), "com.atproto.space.importSpaceMeta", starContentType, archive))
	})

	t.Run("imports a repo with create on every collection it carries", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{skey: "archive-import"})
		mustOK(t, doWrite(alice, sp, writeOpts{collection: testCollection, rkey: "archived"}))
		mustOK(t, doWrite(alice, sp, writeOpts{collection: testCollectionAlt, rkey: "archived"}))
		archive := mustOK(t, alice.get("com.atproto.space.getRepo", map[string]string{"space": sp, "repo": alice.did})).raw

		for _, params := range []string{
			// An update grant does not let an archive in: importRepo creates.
			"collection=*&action=update",
			// Nor does a create grant for only one of the two collections.
			"collection=" + testCollection + "&action=create",
		} {
			res := scopeRawPost(t, authOAuth(alice, grant(params)), "com.atproto.space.importRepo", starContentType, archive)
			expectErr(t, res, 403, "InsufficientScope")
		}
		mustOK(t, scopeRawPost(t, authOAuth(alice, grant("collection=*&action=create")), "com.atproto.space.importRepo", starContentType, archive))
	})

	t.Run("names the space type with the spaceType parameter", func(t *testing.T) {
		// The November 12 alpha renamed the named space type parameter from
		// `type` to `spaceType`, for a grant that names it instead of taking it
		// positionally (`space:<type>?...`). A grant using the old name, or the
		// positional form written as an empty positional plus the named one, is
		// not a space grant at all.
		sp := createSpace(t, alice, spaceOpts{skey: "named-type"})
		named := authOAuth(alice, "atproto space?spaceType="+testSpaceType+"&authority="+alice.did+"&collection=*&action=create")
		mustOK(t, doWrite(named, sp, writeOpts{rkey: "named-type"}))

		for name, scope := range map[string]string{
			"the old type parameter": "atproto space?type=" + testSpaceType + "&authority=" + alice.did + "&collection=*&action=create",
			"an empty positional":    "atproto space:?spaceType=" + testSpaceType + "&authority=" + alice.did + "&collection=*&action=create",
		} {
			if res := doWrite(authOAuth(alice, scope), sp, writeOpts{rkey: "unnamed-type"}); res.status != 403 || res.errName() != "InsufficientScope" {
				t.Errorf("%s: want 403 InsufficientScope, got %d: %s", name, res.status, res.raw)
			}
		}
	})
}
