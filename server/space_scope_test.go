package server

import (
	"testing"
)

// Ported from packages/pds/tests/space-scope.test.ts
// (bluesky-social/atproto 5b95b2f2).
//
// The reference unit-tests assertSpaceRead (api/com/atproto/space/util.ts)
// with synthesized auth outputs. Cocoon applies the same rule in
// server/space_util.go (assertSpaceRead) inside spaceReadAuth, reached through
// the read endpoints, so each reference case becomes a
// com.atproto.space.getRecord read of the caller's own repo versus another
// member's repo:
//
//   - oauthAuth(scope)  -> createOAuthActor(name, scope), as an app the user
//     granted it to would be;
//   - accessAuth()      -> createActor(name), a legacy app-password session;
//   - credentialAuth() -> credentialFor, the credential chain the reference
//     builds in _space.ts;
//   - a throw           -> the 400 RepoNotFound the reference's
//     InvalidRequestError('RepoNotFound') surfaces as.
//
// assertSpaceRead runs before any record is looked up, so the reads are of a
// record that does not exist: what distinguishes a permitted read from a
// refused one is the error that comes back — RecordNotFound ("could not
// locate record") means assertSpaceRead passed, RepoNotFound ("could not find
// repo") means it threw. Both are 400s, the same deliberate indirection the
// reference's `Could not find repo` error documents.
//
// Following the reference's intent: an account reads only its own repo in a
// space however wide its grant; a space credential reads any repo in its own
// space and no other.

// scopeRead makes one com.atproto.space.getRecord read of the named repo.
func scopeRead(a *actor, sp, repo string) xres {
	return a.get("com.atproto.space.getRecord", map[string]string{
		"space": sp, "repo": repo, "collection": testCollection, "rkey": "absent",
	})
}

// scopeReadOK asserts a read got past assertSpaceRead: any error but
// RepoNotFound means the permission check itself passed.
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
}

// scopeReadRefused asserts a read was refused as another member's repo.
func scopeReadRefused(t *testing.T, r xres) {
	t.Helper()
	expectErr(t, r, 400, "RepoNotFound")
	if want := "Could not find repo for DID"; len(r.message()) < len(want) || r.message()[:len(want)] != want {
		t.Fatalf("want a %q message, got %q", want, r.message())
	}
}

func TestAssertSpaceRead(t *testing.T) {
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
		// thing standing between an app password and another member's repo.
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
		expectErr(t, cred.get(t, authority, "com.atproto.space.getRecord", map[string]string{
			"space": otherSpace, "repo": owner.did, "collection": testCollection, "rkey": "absent",
		}), 400, "InvalidCredential")
	})
}
