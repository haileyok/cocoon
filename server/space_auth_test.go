package server

// Ported from packages/pds/tests/space/auth.test.ts in the reference PDS
// (bluesky-social/atproto @ d4def6e9): who may read what, and on whose
// authority.
//
// Two credential kinds reach a space. An account's own token (OAuth or legacy)
// reads only that account's own repo — a repo host has no member list to
// consult. A space credential, which only the authority mints and only after
// deciding the holder may read the space, reads any repo in it. The exchange
// between them is the delegation token.
//
// Reference cases that do not apply to Cocoon, and why:
//   - 'refuses to mint a delegation token on an app password (privileged:
//     false/true)': Cocoon has no app passwords, so there is no second
//     credential kind to refuse.
//   - 'persists revocations for an hour including clock skew, and prunes
//     expired entries' and 'keeps the revocation when background cleanup
//     fails': both mock Date.now and the reference's background queue to move
//     the clock and force a cleanup failure. Cocoon keeps revocations in
//     revoked_space_credentials with an absolute expiry and prunes them inside
//     addRevokedSpaceCredentials; neither the clock nor the prune is
//     injectable, and asserting on direct storage writes would test the
//     assertion rather than the PDS.
//   - 'refuses space records as takedown subjects' and 'reports a space record
//     as not taken down': com.atproto.admin.* takes repo subjects only in
//     Cocoon (any other subject is UnsupportedSubject), and space records have
//     no admin takedown state to report.
//   - 'lets an admin read any space repo, including a taken-down one' and
//     'lets a taken-down account export its spaces': neither applies — no admin
//     credential reaches a space read in Cocoon (the reference's admin_token),
//     and com.atproto.server.createSession has no allowTakendown, so a
//     taken-down account cannot obtain the session those cases use.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
)

// authSpaceTypeCollections are the collections com.example.group declares, the
// reference's SPACE_TYPE_COLLECTIONS.
var authSpaceTypeCollections = []string{"com.example.groupNote", "com.example.groupPost"}

// The network the reference suite builds in beforeAll: three PDSes, alice the
// authority and dan co-located with her on pds1, bob on pds2, carol on pds3.
type authNet struct {
	net              *spaceNet
	pds1, pds2, pds3 *spacePDS
	alice, dan       *actor
	bob, carol       *actor
}

func newAuthNet(t *testing.T) *authNet {
	t.Helper()
	n := newSpaceNet(t)
	a := &authNet{net: n, pds1: n.newPDS(), pds2: n.newPDS(), pds3: n.newPDS()}
	a.alice = a.pds1.createActor("alice") // authority
	a.dan = a.pds1.createActor("dan")     // co-located with the authority
	a.bob = a.pds2.createActor("bob")
	a.carol = a.pds3.createActor("carol")
	return a
}

// authClaims decodes a compact JWT's payload.
func authClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact jwt: %s", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func authJti(t *testing.T, token string) string {
	t.Helper()
	jti, _ := authClaims(t, token)["jti"].(string)
	if jti == "" {
		t.Fatalf("no jti in %s", token)
	}
	return jti
}

// authKeyDid is a P-256 key's did:key.
func authKeyDid(t *testing.T, key *atcrypto.PrivateKeyP256) string {
	t.Helper()
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub.DIDKey()
}

// authExpectMsg asserts a status, an optional XRPC error name, and a message
// substring, for the reference's rejects.toThrow(/.../) assertions.
func authExpectMsg(t *testing.T, r xres, status int, name, substr string) {
	t.Helper()
	if r.status != status || (name != "" && r.errName() != name) || !strings.Contains(r.message(), substr) {
		t.Fatalf("want %d %s with message containing %q, got %d: %s", status, name, substr, r.status, r.raw)
	}
}

// authRevoke sends notifyCredentialsRevoked to target as signer, with service
// auth addressed to aud, as the reference's revoke() does (target: bob's PDS).
func authRevoke(t *testing.T, target *spacePDS, signer *actor, spaceURI string, jtis []string, aud, lxm string) xres {
	t.Helper()
	if lxm == "" {
		lxm = "com.atproto.space.notifyCredentialsRevoked"
	}
	tok, err := mintServiceAuth(signer.key, signer.did, aud, lxm, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return target.post("com.atproto.space.notifyCredentialsRevoked",
		map[string]any{"space": spaceURI, "credentials": jtis},
		map[string]string{"Authorization": "Bearer " + tok})
}

// authRawGet issues a raw GET with explicit header values, so a header can be
// repeated, as the reference's node:http request does.
func authRawGet(t *testing.T, base, nsid string, params map[string]string, h http.Header) xres {
	t.Helper()
	v := url.Values{}
	for k, x := range params {
		v.Set(k, x)
	}
	req, err := http.NewRequest(http.MethodGet, base+"/xrpc/"+nsid+"?"+v.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = h
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := xres{status: resp.StatusCode, raw: raw, header: resp.Header}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

// authOAuth returns a copy of a acting over a fresh OAuth session with scope,
// as the reference's asOAuth stub does for the same actor.
func authOAuth(a *actor, scope string) *actor {
	c := *a
	c.oauth = a.pds.newOAuthSession(a, scope)
	return &c
}

// authDeactivate deactivates an account, as com.atproto.server.deactivateAccount
// and the reference's deactivateAccount do.
func authDeactivate(t *testing.T, a *actor, on bool) {
	t.Helper()
	if err := a.pds.s.db.Exec(context.Background(), "UPDATE repos SET deactivated = ? WHERE did = ?", nil, on, a.did).Error; err != nil {
		t.Fatal(err)
	}
}

// authSpaceTypes publishes com.example.group's declaration, as the reference
// network's lexicon authority does.
type authSpaceTypes struct{}

func (authSpaceTypes) ResolveSpaceCollections(ctx context.Context, nsid string) ([]string, error) {
	if nsid == testSpaceType {
		return authSpaceTypeCollections, nil
	}
	return nil, fmt.Errorf("no space type declaration for %s", nsid)
}

func TestSpaceAuthRepoBoundary(t *testing.T) {
	r := newAuthNet(t)

	// N/A in Cocoon: the reference's "refuses to mint a delegation token on an
	// app password (privileged: false/true)" cases — Cocoon has no app
	// passwords, so there is no credential kind to refuse.

	t.Run("refuses a co-located non-member reading a member repo", func(t *testing.T) {
		// Alice and dan share pds1. Dan is not a member; the membership gate
		// lives in authorizeSpaceSync, so the read methods have to refuse him
		// on their own rather than assuming an unauthorized caller never got
		// this far.
		sp := createSpace(t, r.alice, spaceOpts{})
		mustOK(t, doWrite(r.alice, sp, writeOpts{rkey: "private", text: "members only"}))

		reads := []xres{
			r.dan.get("com.atproto.space.getRecord", map[string]string{"space": sp, "repo": r.alice.did, "collection": testCollection, "rkey": "private"}),
			r.dan.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}),
			r.dan.get("com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": r.alice.did}),
			r.dan.get("com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did}),
		}
		for _, res := range reads {
			// Deliberately the same error an absent repo gets: whether a given
			// account holds a repo in a space the caller can't read is not the
			// caller's business.
			expectErr(t, res, 400, "RepoNotFound")
		}

		v := url.Values{}
		v.Set("space", sp)
		v.Set("repo", r.alice.did)
		carRes := r.net.do(http.MethodGet, r.pds1.url, "com.atproto.space.getRepo", v, nil, r.dan.auth())
		if carRes.status != 400 {
			t.Fatalf("want 400, got %d: %s", carRes.status, carRes.raw)
		}

		// Alice reads her own repo in the same space, so the refusal is about
		// the repo boundary rather than the space being unreadable.
		own := mustOK(t, r.alice.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}))
		if len(own.list("records")) != 1 {
			t.Fatalf("%s", own.raw)
		}
	})
}

func TestSpaceAuthCredentials(t *testing.T) {
	r := newAuthNet(t)

	t.Run("reads another member repo across PDSes", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "for the record"}))

		// Read on pds2 with a credential minted on pds1: neither is the
		// authority.
		cred := credentialFor(t, r.carol, r.pds1, sp)
		claims := authClaims(t, cred.credential)
		exp, _ := claims["exp"].(float64)
		iat, _ := claims["iat"].(float64)
		if exp-iat != 600 {
			t.Fatalf("credential lifetime %v", exp-iat)
		}
		list := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.bob.did, "collection": testCollection}))
		if len(list.list("records")) != 1 {
			t.Fatalf("%s", list.raw)
		}
		rec := mustOK(t, cred.get(t, r.pds2, "com.atproto.space.getRecord", map[string]string{"space": sp, "repo": r.bob.did, "collection": testCollection, "rkey": list.list("records")[0]["rkey"].(string)}))
		if v, _ := rec.body["value"].(map[string]any); v["text"] != "for the record" {
			t.Fatalf("%s", rec.raw)
		}
	})

	// describe('HTTP message signature binding')
	t.Run("refuses a credential presented as a bearer token", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "bound"}))

		cred := credentialFor(t, r.carol, r.pds1, sp)
		res := r.pds1.get("com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did}, map[string]string{"Authorization": "Bearer " + cred.credential})
		if res.status < 400 {
			t.Fatalf("accepted a credential as a bearer token: %s", res.raw)
		}
		mustOK(t, cred.get(t, r.pds1, "com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did}))
	})

	t.Run("refuses a credential without a signature", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)

		res := r.pds1.get("com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did}, map[string]string{"Authorization": "Atproto-Space-Credential " + cred.credential})
		expectErr(t, res, 401, "BadSpaceSignature")
	})

	t.Run("recognizes the credential scheme regardless of case", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{}))
		cred := credentialFor(t, r.carol, r.pds1, sp)
		headers, err := space.CreateSpaceSigHeaders(cred.key, "atproto-space-credential "+cred.credential, r.alice.did)
		if err != nil {
			t.Fatal(err)
		}
		mustOK(t, r.pds1.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}, headers))
	})

	// RFC 9421 labels carry no meaning, so the request signature is identified
	// by its tag: the same signature under another label is still accepted.
	t.Run("finds the signature by its tag under any label", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{}))
		cred := credentialFor(t, r.carol, r.pds1, sp)
		headers := cred.headers(t, r.alice.did)
		headers["signature-input"] = strings.Replace(headers["signature-input"], "sig=", "relabeled=", 1)
		headers["signature"] = strings.Replace(headers["signature"], "sig=", "relabeled=", 1)
		mustOK(t, r.pds1.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}, headers))
	})

	// The reference's it.each rows. Repeated atproto-space-audience and
	// authorization fields are refused (the verifier requires exactly one of
	// each); repeated Signature-Input and Signature fields combine, since a
	// message may carry several signatures.
	t.Run("responds 401 to repeated atproto-space-audience fields", func(t *testing.T) {
		authRepeatedHeaderCase(t, r, "atproto-space-audience", "", 401)
	})
	t.Run("responds 200 to repeated signature-input fields", func(t *testing.T) {
		authRepeatedHeaderCase(t, r, "signature-input", `other=("authorization");keyid="other"`, 200)
	})
	t.Run("responds 200 to repeated signature fields", func(t *testing.T) {
		authRepeatedHeaderCase(t, r, "signature", "other=:YWJj:", 200)
	})
	// Also from the reference's table in the October 22 alpha, which the
	// November 12 suite dropped; the verifier still requires one field.
	t.Run("responds 401 to repeated authorization fields", func(t *testing.T) {
		authRepeatedHeaderCase(t, r, "authorization", "", 401)
	})

	t.Run("refuses a credential presented with a key of the holder own", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "not yours to read"}))

		cred := credentialFor(t, r.carol, r.pds1, sp)
		rebound := &spaceCredential{credential: cred.credential, key: newP256Key(t), dir: cred.dir}
		res := rebound.get(t, r.pds1, "com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did})
		authExpectMsg(t, res, 401, "BadSpaceSignature", "invalid HTTP message signature")
	})

	t.Run("refuses a signature addressed to another account (remote)", func(t *testing.T) {
		authWrongAudienceCase(t, r, r.bob)
	})
	t.Run("refuses a signature addressed to another account (co-located)", func(t *testing.T) {
		authWrongAudienceCase(t, r, r.dan)
	})

	t.Run("requires the space authority as audience for space-host requests", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		cred := credentialFor(t, r.bob, r.pds1, sp)
		headers := cred.headers(t, r.bob.did)
		expectErr(t, r.pds1.get("com.atproto.space.listWriters", map[string]string{"space": sp}, headers), 401, "BadSpaceAudience")
	})

	t.Run("reuses a signature for the same audience across requests", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{}))
		cred := credentialFor(t, r.carol, r.pds1, sp)
		headers := cred.headers(t, r.alice.did)
		for i := 0; i < 2; i++ {
			mustOK(t, r.pds1.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}, headers))
		}
		mustOK(t, r.pds1.get("com.atproto.space.listBlobs", map[string]string{"space": sp, "repo": r.alice.did}, headers))
		mustOK(t, r.pds1.get("com.atproto.space.listWriters", map[string]string{"space": sp}, headers))
	})

	t.Run("reuses one credential across many hosts, each with its own audience signature", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "on the authority"}))
		mustOK(t, doWrite(r.bob, sp, writeOpts{text: "on pds2"}))

		cred := credentialFor(t, r.carol, r.pds1, sp)
		for _, host := range []struct {
			pds  *spacePDS
			repo string
		}{{r.pds1, r.alice.did}, {r.pds2, r.bob.did}} {
			res := mustOK(t, cred.get(t, host.pds, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": host.repo}))
			if len(res.list("records")) != 1 {
				t.Fatalf("%s", res.raw)
			}
		}
	})

	t.Run("is scoped to one space", func(t *testing.T) {
		target := createSpace(t, r.alice, spaceOpts{skey: "cred-target", members: []*actor{r.carol}})
		other := createSpace(t, r.alice, spaceOpts{skey: "cred-other"})
		mustOK(t, doWrite(r.alice, target, writeOpts{text: "scoped"}))

		cred := credentialFor(t, r.carol, r.pds1, target)
		ok := mustOK(t, cred.get(t, r.pds1, "com.atproto.space.getLatestCommit", map[string]string{"space": target, "repo": r.alice.did}))
		if ok.body["commit"] == nil {
			t.Fatalf("%s", ok.raw)
		}
		expectErr(t, cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": other, "repo": r.alice.did}), 400, "InvalidCredential")
	})

	t.Run("refuses a space credential where only the account's own session is accepted", func(t *testing.T) {
		// getSpace answers the authority's own state (the policy), so it is one
		// of the methods a space credential does not reach: it is registered
		// with the session middlewares rather than the space-read one.
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		cred := credentialFor(t, r.carol, r.pds1, sp)

		res := r.pds1.get("com.atproto.space.getSpace", map[string]string{"space": sp}, cred.headers(t, r.alice.did))
		// As the reference does, answered as an unexpected authorization type.
		if res.status != 400 || res.errName() != "InvalidToken" {
			t.Fatalf("want 400 InvalidToken for a space credential on getSpace, got %d: %s", res.status, res.raw)
		}
		mustOK(t, r.alice.get("com.atproto.space.getSpace", map[string]string{"space": sp}))
	})

	t.Run("refuses one the space authority did not issue", func(t *testing.T) {
		// Carol self-signs a credential for one of alice's spaces. It verifies
		// against her own signing key, so nothing but the iss/authority check
		// stands between her and the space. Alice writes first, so the read
		// would otherwise succeed — the rejection has to come from auth.
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{text: "forgery target"}))

		// A credential alice did issue reads it fine.
		valid := credentialFor(t, r.carol, r.pds1, sp)
		mustOK(t, valid.get(t, r.pds1, "com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did}))

		key := newP256Key(t)
		forged, err := space.CreateSpaceToken(space.TokenCredential, space.CreateTokenOpts{
			Iss:   r.carol.did,
			Sub:   sp,
			KeyID: authKeyDid(t, key),
		}, r.carol.key)
		if err != nil {
			t.Fatal(err)
		}
		asForged := &spaceCredential{credential: forged, key: key, dir: r.net.dir}

		res := asForged.get(t, r.pds1, "com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did})
		authExpectMsg(t, res, 401, "BadJwtIss", "issuer is not the space authority")

		// listWriters authorizes off the credential too, on a separate path.
		res = asForged.get(t, r.pds1, "com.atproto.space.listWriters", map[string]string{"space": sp})
		authExpectMsg(t, res, 401, "BadJwtIss", "issuer is not the space authority")
	})

	t.Run("refuses one for a revoked member", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		// Carol mints a delegation token while she is still a member.
		token := delegationTokenFor(t, r.carol, sp)
		// Alice removes her before she can redeem it.
		removeMember(t, r.alice, sp, r.carol)

		// The refusal is answered as an absent space, so it discloses nothing
		// about the space to an account that no longer has access to it.
		expectErr(t, exchange(t, r.pds1, sp, token, newP256Key(t), ""), 400, "SpaceNotFound")
	})
}

// authRepeatedHeaderCase ports the reference's "responds $expectedStatus to
// repeated $name fields" rows: a request whose named header is repeated. The
// reference sends these with node:http so the client cannot collapse them.
func authRepeatedHeaderCase(t *testing.T, r *authNet, name, extra string, expectedStatus int) {
	t.Helper()
	sp := createSpace(t, r.alice, spaceOpts{})
	mustOK(t, doWrite(r.alice, sp, writeOpts{}))
	cred := credentialFor(t, r.alice, r.pds1, sp)
	credHeaders := cred.headers(t, r.alice.did)

	h := http.Header{}
	for k, v := range credHeaders {
		h.Set(k, v)
	}
	dup := extra
	if dup == "" {
		dup = credHeaders[name]
	}
	h.Add(name, dup)

	res := authRawGet(t, r.pds1.url, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}, h)
	if res.status != expectedStatus {
		t.Fatalf("repeated %s: want %d, got %d: %s", name, expectedStatus, res.status, res.raw)
	}
	// A refusal is the verifier's, not an unrelated failure of the request.
	if expectedStatus == 401 && res.errName() != "BadSpaceSignature" {
		t.Fatalf("repeated %s: want BadSpaceSignature, got %s", name, res.raw)
	}
}

func authWrongAudienceCase(t *testing.T, r *authNet, other *actor) {
	t.Helper()
	sp := createSpace(t, r.alice, spaceOpts{members: []*actor{other, r.carol}})
	mustOK(t, doWrite(r.alice, sp, writeOpts{}))
	cred := credentialFor(t, r.carol, r.pds1, sp)
	headers := cred.headers(t, other.did)

	expectErr(t, r.pds1.get("com.atproto.space.getLatestCommit", map[string]string{"space": sp, "repo": r.alice.did}, headers), 401, "BadSpaceAudience")
}

func TestSpaceAuthCredentialRevocation(t *testing.T) {
	r := newAuthNet(t)

	// N/A in Cocoon: the reference's "persists revocations for an hour
	// including clock skew, and prunes expired entries" and "keeps the
	// revocation when background cleanup fails" cases — they mock Date.now and
	// the background queue, which Cocoon's storage layer does not expose.

	t.Run("revokes a batch idempotently on a remote repo host", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob, r.carol}})
		mustOK(t, doWrite(r.alice, sp, writeOpts{}))
		mustOK(t, doWrite(r.bob, sp, writeOpts{}))
		first := credentialFor(t, r.carol, r.pds1, sp)
		second := credentialFor(t, r.carol, r.pds1, sp)
		untouched := credentialFor(t, r.carol, r.pds1, sp)
		credentials := []string{authJti(t, first.credential), authJti(t, second.credential)}

		mustOK(t, first.get(t, r.pds2, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.bob.did}))

		mustOK(t, authRevoke(t, r.pds2, r.alice, sp, credentials, r.bob.did, ""))
		mustOK(t, authRevoke(t, r.pds2, r.alice, sp, []string{credentials[0], credentials[0], credentials[1]}, r.bob.did, ""))

		for _, cred := range []*spaceCredential{first, second} {
			expectErr(t, cred.get(t, r.pds2, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.bob.did}), 401, "CredentialRevoked")
		}
		mustOK(t, untouched.get(t, r.pds2, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.bob.did}))
		// A revocation is the repo host's; the authority heard nothing of it.
		mustOK(t, first.get(t, r.pds1, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.alice.did}))
		mustOK(t, r.bob.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.bob.did}))

		var n int64
		if err := r.pds2.s.db.Client().Model(&models.RevokedSpaceCredential{}).Where("space = ?", sp).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Fatalf("want 2 revoked rows, got %d", n)
		}
	})

	t.Run("requires service auth from the authority addressed to a local repo and method", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		cred := credentialFor(t, r.bob, r.pds1, sp)
		credentials := []string{authJti(t, cred.credential)}

		authExpectMsg(t, authRevoke(t, r.pds2, r.bob, sp, credentials, r.bob.did, ""), 403, "Forbidden", "not the space authority")
		authExpectMsg(t, authRevoke(t, r.pds2, r.alice, sp, credentials, r.alice.did, ""), 403, "Forbidden", "audience does not match")
		authExpectMsg(t, authRevoke(t, r.pds2, r.alice, sp, credentials, r.pds2.s.config.Did, ""), 403, "Forbidden", "audience does not match")
		if res := authRevoke(t, r.pds2, r.alice, sp, credentials, r.bob.did, "com.atproto.space.notifyRepoUpdate"); res.status < 400 {
			t.Fatalf("accepted a notifyRepoUpdate lxm: %s", res.raw)
		}
		if res := r.pds2.post("com.atproto.space.notifyCredentialsRevoked", map[string]any{"space": sp, "credentials": credentials}, r.alice.auth()); res.status < 400 {
			t.Fatalf("accepted a session in place of service auth: %s", res.raw)
		}
		revoked, err := r.pds2.s.isSpaceCredentialRevoked(context.Background(), sp, credentials[0])
		if err != nil {
			t.Fatal(err)
		}
		if revoked {
			t.Fatal("credential recorded as revoked")
		}
	})

	t.Run("scopes revocations to the space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.bob}})
		other := createSpace(t, r.alice, spaceOpts{skey: "other-revocation-space"})
		mustOK(t, doWrite(r.bob, sp, writeOpts{}))
		cred := credentialFor(t, r.bob, r.pds1, sp)
		mustOK(t, authRevoke(t, r.pds2, r.alice, other, []string{authJti(t, cred.credential)}, r.bob.did, ""))
		mustOK(t, cred.get(t, r.pds2, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.bob.did}))
	})
}

func TestSpaceAuthDelegationTokens(t *testing.T) {
	r := newAuthNet(t)

	t.Run("are useless at a host that does not govern the space", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		token := delegationTokenFor(t, r.carol, sp)
		key := newP256Key(t)

		// The same token, presented to bob's PDS instead of alice's. The
		// audience is derived from the token's own sub, so it still matches —
		// what stops this is that pds2 hosts no account for alice and so
		// holds no space to mint against. The error names the space rather
		// than leaking that as a missing repo.
		expectErr(t, exchange(t, r.pds2, sp, token, key, ""), 400, "SpaceNotFound")
	})

	t.Run("binds the credential to the requested key", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		token := delegationTokenFor(t, r.carol, sp)
		key := newP256Key(t)

		res := mustOK(t, exchange(t, r.pds1, sp, token, key, ""))
		cnf, _ := authClaims(t, res.str("credential"))["cnf"].(map[string]any)
		if cnf == nil || cnf["kid"] != authKeyDid(t, key) {
			t.Fatalf("cnf %v", cnf)
		}
	})

	t.Run("refuses to bind the credential to a key that is not P-256", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		token := delegationTokenFor(t, r.carol, sp)
		k256, err := atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := k256.PublicKey()
		res := r.pds1.post("com.atproto.space.authorizeSpaceSync", map[string]any{"space": sp, "credentialKey": pub.DIDKey(), "delegationToken": token}, nil)
		authExpectMsg(t, res, 400, "InvalidRequest", "P-256")
	})

	t.Run("are refused when the audience names another authority", func(t *testing.T) {
		// Minted by hand, because getDelegationToken always addresses the
		// space's own authority. Only the aud differs from a token that would
		// be honoured.
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		misaddressed, err := space.CreateSpaceToken(space.TokenDelegation, space.CreateTokenOpts{
			Iss: r.carol.did,
			Sub: sp,
			Aud: space.SpaceHostAud(r.bob.did),
		}, r.carol.key)
		if err != nil {
			t.Fatal(err)
		}
		authExpectMsg(t, exchange(t, r.pds1, sp, misaddressed, newP256Key(t), ""), 400, "InvalidDelegationToken", "audience does not match the space authority")
	})

	t.Run("are single-use — a replayed jti is refused", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		token := delegationTokenFor(t, r.carol, sp)
		exchangeOnce := func() xres {
			return exchange(t, r.pds1, sp, token, newP256Key(t), "")
		}
		mustOK(t, exchangeOnce())
		authExpectMsg(t, exchangeOnce(), 400, "InvalidDelegationToken", "already been used")
	})

	t.Run("are refused for a space other than their subject", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{skey: "deleg-sub", members: []*actor{r.carol}})
		other := createSpace(t, r.alice, spaceOpts{skey: "deleg-sub-other", members: []*actor{r.carol}})
		token := delegationTokenFor(t, r.carol, sp)

		expectErr(t, exchange(t, r.pds1, other, token, newP256Key(t), ""), 400, "InvalidDelegationToken")
	})

	// Ported from packages/pds/tests/space/policy.test.ts ("answers SpaceDeleted
	// regardless of the request authorization"), kept here because it pins the
	// order authorizeSpaceSync answers in: a deleted space is reported before
	// the delegation token or attestation is looked at, so a syncer that missed
	// the deletion notice learns the space is gone whatever it holds.
	t.Run("answers SpaceDeleted regardless of the request authorization", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.carol}})
		mustOK(t, r.alice.post("com.atproto.space.deleteSpace", map[string]any{"space": sp}))
		r.net.waitSpaceJobs()

		expectErr(t, exchange(t, r.pds1, sp, "not-a-delegation-token", newP256Key(t), ""), 400, "SpaceDeleted")
	})
}

func TestSpaceAuthTakedowns(t *testing.T) {
	r := newAuthNet(t)

	t.Run("stops serving permissioned records for a taken-down account", func(t *testing.T) {
		// A takedown covers everything the account holds, permissioned data
		// included.
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan, r.carol}})
		mustOK(t, doWrite(r.dan, sp, writeOpts{text: "before takedown"}))

		cred := credentialFor(t, r.carol, r.pds1, sp)
		readOps := func() xres {
			return cred.get(t, r.pds1, "com.atproto.space.listRepoOps", map[string]string{"space": sp, "repo": r.dan.did})
		}
		if len(mustOK(t, readOps()).list("ops")) != 1 {
			t.Fatal("expected one op")
		}

		takedown(t, r.dan, true)
		expectErr(t, readOps(), 400, "RepoTakendown")
		takedown(t, r.dan, false)

		// Gated, not deleted.
		if len(mustOK(t, readOps()).list("ops")) != 1 {
			t.Fatal("expected one op after the takedown lifted")
		}
	})

	t.Run("stops accepting permissioned writes from a taken-down account", func(t *testing.T) {
		sp := createSpace(t, r.alice, spaceOpts{members: []*actor{r.dan}})
		write := func() xres { return doWrite(r.dan, sp, writeOpts{text: "during takedown"}) }

		takedown(t, r.dan, true)
		authExpectMsg(t, write(), 401, "AccountTakedown", "taken down")
		// Minting a read credential is gated on the same status.
		authExpectMsg(t, r.dan.get("com.atproto.space.getDelegationToken", map[string]string{"space": sp}), 401, "AccountTakedown", "taken down")
		takedown(t, r.dan, false)

		mustOK(t, write())
	})

	t.Run("stops minting credentials and listing writers for a taken-down authority", func(t *testing.T) {
		erin := r.pds1.createActor("erin")
		sp := createSpace(t, erin, spaceOpts{members: []*actor{r.dan}})
		cred := credentialFor(t, r.dan, r.pds1, sp)
		listWriters := func() xres {
			return cred.get(t, r.pds1, "com.atproto.space.listWriters", map[string]string{"space": sp})
		}
		mustOK(t, listWriters())

		takedown(t, erin, true)
		// A credential already issued stays valid: it is verified against the
		// authority's key, which a takedown does not withdraw. What stops is
		// minting a new one and reading the writer set the authority hosts.
		mustOK(t, cred.get(t, r.pds1, "com.atproto.space.listRecords", map[string]string{"space": sp, "repo": r.dan.did}))
		expectErr(t, exchange(t, r.pds1, sp, delegationTokenFor(t, r.dan, sp), newP256Key(t), ""), 400, "RepoTakendown")
		expectErr(t, listWriters(), 400, "RepoTakendown")
		takedown(t, erin, false)

		cred = credentialFor(t, r.dan, r.pds1, sp)
		if cred.credential == "" {
			t.Fatal("no credential minted after the takedown lifted")
		}
	})

	t.Run("stops minting public credentials for a taken-down authority", func(t *testing.T) {
		frank := r.pds1.createActor("frank")
		sp := createSpace(t, frank, spaceOpts{policy: memberPolicy(map[string]any{"publicRead": true})})
		// A public space mints a credential with no delegation token at all.
		publicCredential(t, r.pds1, sp, "")

		takedown(t, frank, true)
		expectErr(t, exchange(t, r.pds1, sp, "", newP256Key(t), ""), 400, "RepoTakendown")
		takedown(t, frank, false)
	})

	t.Run("stops minting credentials for a deactivated authority", func(t *testing.T) {
		gina := r.pds1.createActor("gina")
		sp := createSpace(t, gina, spaceOpts{members: []*actor{r.dan}})

		authDeactivate(t, gina, true)
		expectErr(t, exchange(t, r.pds1, sp, delegationTokenFor(t, r.dan, sp), newP256Key(t), ""), 400, "RepoDeactivated")
		authDeactivate(t, gina, false)

		if cred := credentialFor(t, r.dan, r.pds1, sp); cred.credential == "" {
			t.Fatal("no credential minted after reactivation")
		}
	})

	t.Run("stops a taken-down authority managing its spaces", func(t *testing.T) {
		hank := r.pds1.createActor("hank")
		sp := createSpace(t, hank, spaceOpts{members: []*actor{r.dan}})
		calls := []func() xres{
			func() xres {
				return hank.post("com.atproto.space.createSpace", map[string]any{"spaceType": testSpaceType, "skey": "second", "policy": memberPolicy(nil)})
			},
			func() xres {
				return hank.post("com.atproto.space.updateSpace", map[string]any{"space": sp, "policy": memberPolicy(nil)})
			},
			func() xres {
				return hank.post("com.atproto.space.deleteSpace", map[string]any{"space": sp})
			},
			func() xres { return removeWriter(hank, sp, r.dan) },
			func() xres { return putMemberRes(hank, sp, r.bob, true, true) },
			func() xres {
				return hank.post("com.atproto.memberspace.removeMembers", map[string]any{"space": sp, "dids": []string{r.dan.did}})
			},
		}

		takedown(t, hank, true)
		for i, call := range calls {
			if res := call(); res.status != 401 || res.errName() != "AccountTakedown" {
				t.Errorf("call %d: want 401 AccountTakedown, got %d: %s", i, res.status, res.raw)
			}
		}
		takedown(t, hank, false)

		// The same calls are accepted once the takedown is lifted.
		mustOK(t, hank.post("com.atproto.space.updateSpace", map[string]any{"space": sp, "policy": memberPolicy(nil)}))
	})

	t.Run("stops a deactivated authority creating spaces", func(t *testing.T) {
		ian := r.pds1.createActor("ian")

		authDeactivate(t, ian, true)
		res := ian.post("com.atproto.space.createSpace", map[string]any{"spaceType": testSpaceType, "skey": "deactivated", "policy": memberPolicy(nil)})
		expectErr(t, res, 401, "AccountDeactivated")
		authDeactivate(t, ian, false)

		mustOK(t, ian.post("com.atproto.space.createSpace", map[string]any{"spaceType": testSpaceType, "skey": "reactivated", "policy": memberPolicy(nil)}))
	})
}

func TestSpaceAuthOAuthScopes(t *testing.T) {
	// OAuth scope enforcement, end to end. The reference stubs the OAuth
	// verifier; here the sessions are real DPoP-bound token rows whose scope
	// is checked by the real handlers. The reference's network runs with a
	// lexicon authority so a bare space:<type> grant can be expanded; here the
	// last case installs a declaration resolver instead.

	n := newSpaceNet(t)
	pds1 := n.newPDS()
	alice := pds1.createActor("alice") // authority, on pds1
	dan := pds1.createActor("dan")     // co-located with the authority

	// A grant naming alice's authority explicitly, as one issued for her
	// spaces would after self resolution. atproto is the base scope every
	// token carries; without it the request is refused before any space
	// check.
	grant := func(params string) string {
		return "atproto space:" + testSpaceType + "?authority=" + alice.did + "&" + params
	}

	t.Run("enforces the collection a grant names on a write", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		allowed, forbidden := authSpaceTypeCollections[0], authSpaceTypeCollections[1]

		oa := authOAuth(alice, grant("collection="+allowed+"&action=create"))
		mustOK(t, doWrite(oa, sp, writeOpts{collection: allowed, rkey: "ok"}))

		// Same space, same action, a collection the grant doesn't name.
		expectErr(t, doWrite(oa, sp, writeOpts{collection: forbidden, rkey: "no"}), 403, "InsufficientScope")
	})

	t.Run("enforces the action a grant names", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		collection := authSpaceTypeCollections[0]
		// Seed a record to delete, outside the restricted grant.
		mustOK(t, doWrite(alice, sp, writeOpts{collection: collection, rkey: "seeded"}))

		oa := authOAuth(alice, grant("collection="+collection+"&action=create"))
		expectErr(t, doDel(oa, sp, collection, "seeded"), 403, "InsufficientScope")
	})

	t.Run("requires delete on every collection a clear removes", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		first, second := authSpaceTypeCollections[0], authSpaceTypeCollections[1]
		mustOK(t, doWrite(alice, sp, writeOpts{collection: first, rkey: "first"}))
		mustOK(t, doWrite(alice, sp, writeOpts{collection: second, rkey: "second"}))

		// A grant that covers one of the two collections is not enough: a
		// clear removes records from every collection, so it needs delete on
		// all of them.
		expectErr(t, clearRecords(authOAuth(alice, grant("collection="+first+"&action=delete")), sp), 403, "InsufficientScope")
		kept := mustOK(t, alice.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": alice.did}))
		if len(kept.list("records")) != 2 {
			t.Fatalf("%s", kept.raw)
		}

		mustOK(t, clearRecords(authOAuth(alice, grant("collection="+first+"&collection="+second+"&action=delete")), sp))
	})

	t.Run("resolves putRecord to update rather than demanding create too", func(t *testing.T) {
		// putRecord is create-or-update, so it asks for whichever this write
		// is: an app granted only update must be able to overwrite, without
		// also needing create.
		sp := createSpace(t, alice, spaceOpts{})
		collection := authSpaceTypeCollections[0]
		mustOK(t, doWrite(alice, sp, writeOpts{collection: collection, rkey: "self", text: "first"}))

		oa := authOAuth(alice, grant("collection="+collection+"&action=update"))
		mustOK(t, doPut(oa, sp, writeOpts{collection: collection, rkey: "self", text: "second"}))

		// ...but not create one that doesn't exist yet.
		expectErr(t, doPut(oa, sp, writeOpts{collection: collection, rkey: "fresh"}), 403, "InsufficientScope")
	})

	t.Run("refuses a space of a type the grant does not name", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{spaceType: "com.example.otherGroup"})

		oa := authOAuth(alice, grant("collection=*&action=create"))
		expectErr(t, doWrite(oa, sp, writeOpts{rkey: "wrong-type"}), 403, "InsufficientScope")
	})

	t.Run("refuses a space under an authority the grant does not name", func(t *testing.T) {
		// A grant naming alice as authority must not reach a space governed
		// by someone else. Dan is co-located with alice on the authority PDS,
		// so this isolates the authority check from any cross-PDS concern.
		danSpace := createSpace(t, dan, spaceOpts{skey: "dan-governed"})
		oa := authOAuth(dan, grant("collection=*&action=create"))
		expectErr(t, doWrite(oa, danSpace, writeOpts{rkey: "other-authority"}), 403, "InsufficientScope")
	})

	t.Run("reads own repo on read_self, and refuses whole-space read", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		mustOK(t, doWrite(alice, sp, writeOpts{rkey: "mine"}))

		oa := authOAuth(alice, grant("action=read_self"))
		own := mustOK(t, oa.get("com.atproto.space.listRecords", map[string]string{"space": sp, "repo": alice.did}))
		if len(own.list("records")) != 1 {
			t.Fatalf("%s", own.raw)
		}

		// read_self buys no delegation token: that is the whole-space read
		// grant.
		expectErr(t, oa.get("com.atproto.space.getDelegationToken", map[string]string{"space": sp}), 403, "InsufficientScope")
	})

	t.Run("exchanges a whole-space read grant for a delegation token", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		oa := authOAuth(alice, grant("action=read"))
		res := mustOK(t, oa.get("com.atproto.space.getDelegationToken", map[string]string{"space": sp}))
		if res.str("token") == "" {
			t.Fatalf("%s", res.raw)
		}
	})

	t.Run("requires a wildcard grant to list spaces unfiltered", func(t *testing.T) {
		sp := createSpace(t, alice, spaceOpts{})
		// listSpaces has no one space to check against, so the filters are
		// the target: an unfiltered listing is a request to see everything.
		oa := authOAuth(alice, grant("action=read_self"))
		expectErr(t, oa.get("com.atproto.space.listSpaces", nil), 403, "InsufficientScope")

		// Narrowed to what the grant covers, it is allowed.
		listed := mustOK(t, oa.get("com.atproto.space.listSpaces", map[string]string{"spaceType": testSpaceType, "spaceDid": alice.did}))
		found := false
		for _, s := range listed.list("spaces") {
			found = found || s["space"] == sp
		}
		if !found {
			t.Fatalf("listing misses %s: %s", sp, listed.raw)
		}

		expectErr(t, oa.get("com.atproto.space.listSpaces", map[string]string{"spaceType": "com.example.otherGroup", "spaceDid": alice.did}), 403, "InsufficientScope")
	})

	t.Run("materializes the space type declared collections into a bare grant", func(t *testing.T) {
		// The seam this suite exists for. A bare space:<type> names no
		// collections, so on its own it confers no write targets at all; the
		// provider expands it from the space type's declaration at issuance,
		// resolving self to the user. This asserts the expansion is one the
		// PDS then accepts.
		pds1.s.spaceTypes = authSpaceTypes{}
		expanded := pds1.s.expandScopes(context.Background(), "atproto space:"+testSpaceType, alice.did)
		for _, collection := range authSpaceTypeCollections {
			if !strings.Contains(expanded, "collection="+collection) {
				t.Fatalf("expanded scope misses %s: %s", collection, expanded)
			}
		}
		if !strings.Contains(expanded, "authority="+alice.did) {
			t.Fatalf("expanded scope misses the resolved authority: %s", expanded)
		}

		sp := createSpace(t, alice, spaceOpts{})
		oa := authOAuth(alice, "atproto space:"+testSpaceType)
		for _, collection := range authSpaceTypeCollections {
			mustOK(t, doWrite(oa, sp, writeOpts{collection: collection, rkey: "decl-" + lastSegment(collection)}))
		}
		// A collection the space type never declared stays out of reach.
		expectErr(t, doWrite(oa, sp, writeOpts{rkey: "undeclared"}), 403, "InsufficientScope")
	})
}
