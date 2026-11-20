package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/haileyok/cocoon/plc"
)

// createAccount's alsoKnownAs lands in the genesis PLC operation after the
// at:// handle, so an agent's ident.link declaration
// (https://ident.link/agent-of/<principal>) is in its DID document from the
// first operation, signed by the PDS, with no second operation and no key of
// the operator's online.
func TestCreateAccountAlsoKnownAs(t *testing.T) {
	agentOf := plc.IdentLinkAgentOfPrefix + "did:plc:principal"

	t.Run("extra entries follow the handle in the genesis op", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		_, code, body := createAccountWithRecoveryKey(t, s, map[string]any{
			"handle":      "agent.pds.test",
			"email":       "agent@test.invalid",
			"password":    "correct-horse-battery-staple",
			"alsoKnownAs": []string{agentOf, agentOf},
		})
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", code, body)
		}
		if len(p.ops) != 1 {
			t.Fatalf("expected one genesis PLC op, got %d", len(p.ops))
		}
		aka := p.ops[0].AlsoKnownAs
		if len(aka) != 2 || aka[0] != "at://agent.pds.test" || aka[1] != agentOf {
			t.Fatalf("alsoKnownAs = %v, want [at://agent.pds.test %s]", aka, agentOf)
		}
	})

	t.Run("bad entries are rejected before anything is created", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)
		s.config.RequireInvite = true
		code := "agents-invite"
		s.insertInviteCode(t, code, 1)

		for _, bad := range [][]string{
			{"at://other.pds.test"},
			{plc.IdentLinkAgentOfPrefix + "not-a-did"},
			{"http://example.com"},
		} {
			_, status, body := createAccountWithRecoveryKey(t, s, map[string]any{
				"handle":      "agent.pds.test",
				"email":       "agent@test.invalid",
				"password":    "correct-horse-battery-staple",
				"inviteCode":  code,
				"alsoKnownAs": bad,
			})
			if status != http.StatusBadRequest {
				t.Errorf("alsoKnownAs %v: expected 400, got %d: %s", bad, status, body)
			}
		}
		if len(p.ops) != 0 {
			t.Fatalf("a rejected request submitted %d PLC ops", len(p.ops))
		}
		// The invite's one use is still there.
		_, status, body := createAccountWithRecoveryKey(t, s, map[string]any{
			"handle":      "agent.pds.test",
			"email":       "agent@test.invalid",
			"password":    "correct-horse-battery-staple",
			"inviteCode":  code,
			"alsoKnownAs": []string{agentOf},
		})
		if status != http.StatusOK {
			t.Fatalf("rejected requests used up the invite: %d %s", status, body)
		}
	})

	t.Run("CreateAgent publishes the declaration too", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)
		s.evtman = s.newTestEvtman(t)
		s.repoman = NewRepoMan(s)

		if _, err := s.CreateAgent(context.Background(), CreateAgentArgs{
			Handle:      "helper.agents.pds.test",
			AlsoKnownAs: []string{agentOf},
		}); err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}
		aka := p.ops[0].AlsoKnownAs
		if len(aka) != 2 || aka[1] != agentOf {
			t.Fatalf("alsoKnownAs = %v", aka)
		}
		if _, err := s.CreateAgent(context.Background(), CreateAgentArgs{
			Handle:      "bad.agents.pds.test",
			AlsoKnownAs: []string{"at://x.pds.test"},
		}); err == nil {
			t.Fatal("CreateAgent accepted an at:// entry")
		}
	})
}
