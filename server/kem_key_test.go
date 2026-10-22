package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
)

// #atproto_kem keys (the reference's createAccount.ts,
// getRecommendedDidCredentials.ts, submitPlcOperation.ts and
// kem-key-backfill.ts at bluesky-social/atproto ac0c9f15, with cases from
// plc-operations.test.ts and space/kem-key-backfill.test.ts).

func kemDidKeyOf(t *testing.T, s *Server, did string) string {
	t.Helper()
	repo := mustRepoActor(t, s, did)
	k, err := accountKemDIDKey(repo.Repo)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKemKeyAtAccountCreation(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)

	acct, code, body := createAccountWithRecoveryKey(t, s, map[string]any{
		"handle":   "kem.pds.test",
		"email":    "kem@test.invalid",
		"password": "correct-horse-battery-staple",
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", code, body)
	}
	kem := kemDidKeyOf(t, s, acct.Did)
	if kem == "" {
		t.Fatal("account has no kem key")
	}
	pub, err := atcrypto.ParsePublicDIDKey(kem)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*atcrypto.PublicKeyP256); !ok {
		t.Fatalf("kem key is not P-256: %s", kem)
	}
	if len(p.ops) != 1 || p.ops[0].VerificationMethods["atproto_kem"] != kem {
		t.Fatalf("genesis op does not publish the kem key: %+v", p.ops)
	}
	if p.ops[0].VerificationMethods["atproto"] == kem {
		t.Fatal("kem key reuses the signing key")
	}
}

func TestKemKeyRecommendedDidCredentials(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)

	c, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.identity.getRecommendedDidCredentials", "", nil)
	c.Set("repo", mustRepoActor(t, s, acct.Did))
	if err := s.handleGetRecommendedDidCredentials(c); err != nil {
		t.Fatal(err)
	}
	var creds plc.DidCredentials
	if err := json.Unmarshal(rec.Body.Bytes(), &creds); err != nil {
		t.Fatal(err)
	}
	if want := kemDidKeyOf(t, s, acct.Did); want == "" || creds.VerificationMethods["atproto_kem"] != want {
		t.Fatalf("recommended %v, want atproto_kem %s", creds.VerificationMethods, want)
	}

	// An account without a KEM key yet gets none recommended.
	if err := s.db.Exec(context.Background(), "UPDATE repos SET kem_key = NULL WHERE did = ?", nil, acct.Did).Error; err != nil {
		t.Fatal(err)
	}
	c, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.identity.getRecommendedDidCredentials", "", nil)
	c.Set("repo", mustRepoActor(t, s, acct.Did))
	if err := s.handleGetRecommendedDidCredentials(c); err != nil {
		t.Fatal(err)
	}
	creds = plc.DidCredentials{}
	_ = json.Unmarshal(rec.Body.Bytes(), &creds)
	if _, ok := creds.VerificationMethods["atproto_kem"]; ok {
		t.Fatalf("recommended a kem key the account does not have: %v", creds.VerificationMethods)
	}
}

func TestSubmitPlcOpChecksKemKey(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	required := s.requiredCreds(t, acct)

	op := func(methods map[string]string) plc.Operation {
		return plc.Operation{
			Type:                "plc_operation",
			VerificationMethods: methods,
			RotationKeys:        required.RotationKeys,
			AlsoKnownAs:         required.AlsoKnownAs,
			Services:            required.Services,
			Sig:                 "test-sig",
		}
	}
	other, _ := atcrypto.GeneratePrivateKeyP256()
	otherPub, _ := other.PublicKey()
	for name, methods := range map[string]map[string]string{
		"missing": {"atproto": required.VerificationMethods["atproto"]},
		"other":   {"atproto": required.VerificationMethods["atproto"], "atproto_kem": otherPub.DIDKey()},
	} {
		code, body := callSubmitPlcOp(t, s, acct, op(methods))
		if code != http.StatusBadRequest {
			t.Fatalf("%s kem key: got %d %s", name, code, body)
		}
		var res map[string]string
		_ = json.Unmarshal([]byte(body), &res)
		if res["message"] != "Incorrect KEM key" {
			t.Fatalf("%s kem key: %s", name, body)
		}
	}
	if code, body := callSubmitPlcOp(t, s, acct, op(required.VerificationMethods)); code != http.StatusOK {
		t.Fatalf("matching kem key: got %d %s", code, body)
	}
}

func TestKemKeyBackfill(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	p := newPlcTestServer(t)
	plcClient := s.attachPlcClient(t, p)
	rotationKey, err := plcClient.RotationKeyDID()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	ours := s.createTestAccount(t, "ours.pds.test")
	movedAway := s.createTestAccount(t, "moved.pds.test")
	done := s.createTestAccount(t, "done.pds.test")
	doneKem := kemDidKeyOf(t, s, done.Did)
	if err := s.db.Exec(ctx, "UPDATE repos SET kem_key = NULL WHERE did IN (?, ?)", nil, ours.Did, movedAway.Did).Error; err != nil {
		t.Fatal(err)
	}

	// The PLC stand-in serves one audit log for every DID: first one this PDS
	// can update, then one naming another PDS.
	p.log = identity.DidAuditLog{{
		Did: ours.Did, Cid: "bafyprev",
		Operation: identity.DidLogEntry{
			RotationKeys:        []string{rotationKey},
			VerificationMethods: map[string]string{"atproto": "did:key:zQ3shtCGgFrAtUwdiHRYzKQqNUNiLNGoXjSaMfZxNhbRvbbRS"},
			AlsoKnownAs:         []string{"at://ours.pds.test"},
			Services:            map[string]identity.OperationService{"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: plcClient.PdsEndpoint()}},
		},
	}}
	if err := s.backfillKemKey(ctx, ours.Did); err != nil {
		t.Fatal(err)
	}
	oursKem := kemDidKeyOf(t, s, ours.Did)
	if oursKem == "" || len(p.ops) != 1 {
		t.Fatalf("kem %q, ops %d", oursKem, len(p.ops))
	}
	op := p.ops[0]
	if op.VerificationMethods["atproto_kem"] != oursKem || op.VerificationMethods["atproto"] == "" || op.Prev == nil || *op.Prev != "bafyprev" || op.Sig == "" {
		t.Fatalf("published op %+v", op)
	}

	p.log[0].Operation.Services = map[string]identity.OperationService{"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: "https://elsewhere.example"}}
	failed, err := s.backfillKemKeys(ctx)
	if err != nil || failed != 0 {
		t.Fatalf("backfill: %d failed, %v", failed, err)
	}
	if kemDidKeyOf(t, s, movedAway.Did) == "" {
		t.Fatal("an account this PDS can't publish for still gets a key to publish itself")
	}
	if len(p.ops) != 1 {
		t.Fatalf("published for an account on another PDS: %d ops", len(p.ops))
	}
	if kemDidKeyOf(t, s, ours.Did) != oursKem || kemDidKeyOf(t, s, done.Did) != doneKem {
		t.Fatal("backfill replaced an existing key")
	}

	// A failed publish leaves the account for a later run.
	retry := s.createTestAccount(t, "retry.pds.test")
	if err := s.db.Exec(ctx, "UPDATE repos SET kem_key = NULL WHERE did = ?", nil, retry.Did).Error; err != nil {
		t.Fatal(err)
	}
	p.log[0].Operation.Services = map[string]identity.OperationService{"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: plcClient.PdsEndpoint()}}
	p.status = http.StatusBadRequest
	if failed, _ := s.backfillKemKeys(ctx); failed != 1 || kemDidKeyOf(t, s, retry.Did) != "" {
		t.Fatalf("failed %d, key %q", failed, kemDidKeyOf(t, s, retry.Did))
	}
	var n int64
	s.db.Client().Model(&models.Repo{}).Where("kem_key IS NULL").Count(&n)
	if n != 1 {
		t.Fatalf("%d accounts without keys", n)
	}
}
