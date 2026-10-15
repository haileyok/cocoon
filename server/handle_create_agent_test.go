package server

import (
	"context"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
)

// TestCreateAgent wires a test server like the create-account tests do (test
// PLC server, evtman) and runs CreateAgent, checking:
//   - the genesis PLC op puts the recovery key FIRST in rotationKeys
//   - the account has a placeholder email and an empty repo: CreateAgent
//     writes no records of its own
//   - a taken handle and an invalid recovery key fail
func TestCreateAgent(t *testing.T) {
	recovery, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	recoveryPub, err := recovery.PublicKey()
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	recoveryDidKey := recoveryPub.DIDKey()

	setup := func(t *testing.T) (*Server, *plcTestServer) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)
		s.evtman = newTestEvtman(t)
		s.repoman = NewRepoMan(s)
		return s, p
	}

	t.Run("creates the account with the recovery key first", func(t *testing.T) {
		s, p := setup(t)
		res, err := s.CreateAgent(context.Background(), CreateAgentArgs{
			Handle:      "assistant.agents.pds.test",
			RecoveryKey: recoveryDidKey,
		})
		if err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}
		if len(p.ops) != 1 {
			t.Fatalf("expected one genesis PLC op, got %d", len(p.ops))
		}
		if keys := p.ops[0].RotationKeys; len(keys) != 2 || keys[0] != recoveryDidKey {
			t.Fatalf("recovery key must be first of %v", keys)
		}
		if res.Did == "" || res.Handle != "assistant.agents.pds.test" {
			t.Fatalf("unexpected result: %+v", res)
		}
		agentRepo := mustRepoActor(t, s, res.Did)
		if agentRepo.Repo.Email != "assistant.agents.pds.test@agents.invalid" {
			t.Fatalf("agent email = %q, want placeholder", agentRepo.Repo.Email)
		}
		if len(agentRepo.Repo.Root) == 0 {
			t.Fatal("agent has no genesis repo")
		}
		var n int64
		if err := s.db.Client().Model(&models.Record{}).Where("did = ?", res.Did).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("CreateAgent wrote %d records; it should write none", n)
		}

		// the handle is now taken
		if _, err := s.CreateAgent(context.Background(), CreateAgentArgs{Handle: "assistant.agents.pds.test", RecoveryKey: recoveryDidKey}); err == nil {
			t.Fatal("created a second account with the same handle")
		}
	})

	t.Run("without a recovery key", func(t *testing.T) {
		s, p := setup(t)
		if _, err := s.CreateAgent(context.Background(), CreateAgentArgs{Handle: "plain.agents.pds.test"}); err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}
		if keys := p.ops[0].RotationKeys; len(keys) != 1 {
			t.Fatalf("want only the PDS's rotation key, got %v", keys)
		}
	})

	t.Run("invalid recovery key rejected", func(t *testing.T) {
		s, p := setup(t)
		if _, err := s.CreateAgent(context.Background(), CreateAgentArgs{
			Handle:      "bad.agents.pds.test",
			RecoveryKey: "not-a-did-key",
		}); err == nil {
			t.Fatal("expected error for invalid recovery key")
		}
		if len(p.ops) != 0 {
			t.Fatal("a PLC op was sent for an invalid recovery key")
		}
	})
}
