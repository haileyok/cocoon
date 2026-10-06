package server

import "testing"

// Smoke tests for the Spaces test network itself.
func TestSpaceHarnessCredentialAndOAuth(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	bob := pds2.createActor("bob")

	sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
	mustOK(t, doWrite(alice, sp, writeOpts{rkey: "a"}))

	cred := credentialFor(t, bob, pds1, sp)
	got := cred.get(t, pds1, "com.atproto.space.getRecord", map[string]string{"space": sp, "repo": alice.did, "collection": testCollection, "rkey": "a"})
	mustOK(t, got)

	app := pds2.createOAuthActor("carol", "atproto space:"+testSpaceType+"?authority=*&collection=*")
	mustOK(t, doWrite(app, sp, writeOpts{rkey: "c"}))
	narrow := pds2.createOAuthActor("dave", "atproto space:"+testSpaceType+"?authority=*&action=read")
	expectErr(t, doWrite(narrow, sp, writeOpts{rkey: "d"}), 403, "InsufficientScope")
}
