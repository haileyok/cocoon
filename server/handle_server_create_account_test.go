package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/identity"
)

// TestCreateAccountInitializesRepoForExistingDID asserts an account created
// via the existing-DID flow gets a genesis repo commit and #identity/#sync
// events, same as the flow where cocoon mints the DID itself.
func TestCreateAccountInitializesRepoForExistingDID(t *testing.T) {
	s := newTestServer(t)

	persister, err := NewDbPersister(s.db.Client(), time.Hour)
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}
	s.evtman = events.NewEventManager(persister)

	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	const did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	const handle = "alice.pds.test"

	cache := identity.NewMemCache(10)
	if err := cache.PutDoc(did, &identity.DidDoc{
		Id: did,
		VerificationMethods: []identity.DidDocVerificationMethod{
			{
				Id:                 did + "#atproto",
				Type:               "Multikey",
				Controller:         did,
				PublicKeyMultibase: pub.Multibase(),
			},
		},
	}); err != nil {
		t.Fatalf("seed passport cache: %v", err)
	}
	s.passport = identity.NewPassport(nil, cache)

	tok := mintServiceAuthToken(t, k.Bytes(), did, s.config.Did, "com.atproto.server.createAccount", time.Now().Add(time.Minute))

	body, err := json.Marshal(map[string]string{
		"handle":   handle,
		"email":    "alice@test.invalid",
		"password": "correct-horse-battery-staple",
		"did":      did,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createAccount", string(body), map[string]string{
		"authorization": "Bearer " + tok,
	})

	if err := s.handleCreateAccount(c); err != nil {
		t.Fatalf("handleCreateAccount: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	urepo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	if urepo.Repo.Rev == "" {
		t.Fatal("repo has no rev after account creation via the existing-DID flow")
	}
	if len(urepo.Repo.Root) == 0 {
		t.Fatal("repo has no root after account creation via the existing-DID flow")
	}

	types := eventTypesFor(t, s, did)
	for _, want := range []string{"identity", "sync"} {
		if !contains(types, want) {
			t.Fatalf("missing %q event after account creation; got %v", want, types)
		}
	}
}
