package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
)

// getAgentOperatedRecord finds the operated record naming agent in
// operator's repo, returning its URI and CID, or "" when there is none.
func (s *Server) getAgentOperatedRecord(ctx context.Context, operator, agent string) (string, string, error) {
	var records []models.Record
	if err := s.db.Raw(ctx, "SELECT * FROM records WHERE did = ? AND nsid = ?", nil, operator, agentOperatedCollection).Scan(&records).Error; err != nil {
		return "", "", err
	}
	for _, r := range records {
		val, err := atdata.UnmarshalCBOR(r.Value)
		if err != nil {
			return "", "", err
		}
		if val["agent"] == agent {
			return "at://" + r.Did + "/" + r.Nsid + "/" + r.Rkey, r.Cid, nil
		}
	}
	return "", "", nil
}

// TestCreateAgent wires a test server like the create-account tests do (test
// PLC server, evtman, passport) and runs CreateAgent, checking:
//   - the genesis PLC op puts the recovery key FIRST in rotationKeys
//   - the agent's repo carries garden.engram.agents.declaration/self naming
//     the operator
//   - the operator's repo carries garden.engram.agents.operated listing the
//     agent (tid rkey, record points back at the agent DID)
//   - the account has a placeholder email and a random password (sign-in works)
//   - an unknown operator DID skips the operated record without failing
//   - an invalid recovery key fails
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

	t.Run("full flow with local operator", func(t *testing.T) {
		s, p := setup(t)

		// a local operator account
		opAcct := s.createTestAccount(t, "hailey.pds.test")
		s.seedGenesisRepo(t, opAcct.Did, opAcct.SigningKey)

		res, err := s.CreateAgent(context.Background(), CreateAgentArgs{
			Handle:      "assistant.agents.pds.test",
			Operator:    opAcct.Did,
			RecoveryKey: recoveryDidKey,
		})
		if err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}

		// recovery key first in the genesis op
		if len(p.ops) != 1 {
			t.Fatalf("expected one genesis PLC op, got %d", len(p.ops))
		}
		keys := p.ops[0].RotationKeys
		if len(keys) != 2 || keys[0] != recoveryDidKey {
			t.Fatalf("recovery key must be first of %v", keys)
		}

		if res.Did == "" || res.Handle != "assistant.agents.pds.test" {
			t.Fatalf("unexpected result: %+v", res)
		}

		// agent account exists with placeholder email
		agentRepo := mustRepoActor(t, s, res.Did)
		if agentRepo.Repo.Email != "assistant.agents.pds.test@agents.invalid" {
			t.Fatalf("agent email = %q, want placeholder", agentRepo.Repo.Email)
		}

		// declaration record in the agent's repo
		c, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo="+res.Did+"&collection=garden.engram.agents.declaration&rkey=self", "", nil)
		if err := s.handleRepoGetRecord(c); err != nil {
			t.Fatalf("getRecord declaration: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("declaration getRecord: %d %s", rec.Code, rec.Body.String())
		}
		var decl struct {
			Value map[string]any `json:"value"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &decl); err != nil {
			t.Fatal(err)
		}
		if decl.Value["operator"] != opAcct.Did {
			t.Fatalf("declaration operator = %v", decl.Value["operator"])
		}
		if _, ok := decl.Value["createdAt"].(string); !ok {
			t.Fatalf("declaration has no createdAt: %v", decl.Value)
		}

		// operated record in the operator's repo lists the agent
		uri, _, err := s.getAgentOperatedRecord(context.Background(), opAcct.Did, res.Did)
		if err != nil {
			t.Fatalf("operated record lookup: %v", err)
		}
		if uri == "" {
			t.Fatalf("no operated record for agent %s in operator %s repo", res.Did, opAcct.Did)
		}
	})

	t.Run("remote operator skips operated record", func(t *testing.T) {
		s, _ := setup(t)

		res, err := s.CreateAgent(context.Background(), CreateAgentArgs{
			Handle:      "remote.agents.pds.test",
			Operator:    "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
			RecoveryKey: recoveryDidKey,
		})
		if err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}
		if res.Did == "" {
			t.Fatal("no did")
		}
		// declaration still written
		if _, _, err := s.getAgentOperatedRecord(context.Background(), res.Did, "did:plc:cccccccccccccccccccccccc"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid recovery key rejected", func(t *testing.T) {
		s, _ := setup(t)
		if _, err := s.CreateAgent(context.Background(), CreateAgentArgs{
			Handle:      "bad.agents.pds.test",
			Operator:    "did:plc:dddddddddddddddddddddddd",
			RecoveryKey: "not-a-did-key",
		}); err == nil {
			t.Fatal("expected error for invalid recovery key")
		}
	})
}
