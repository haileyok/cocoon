package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
	"github.com/labstack/echo/v4"
)

// TestCreateAgentEndpoint: a principal creates an agent in one call; the
// agent's genesis operation declares it an agent of the caller, the caller's
// repo endorses it, and only allowed principals with the right scopes can do
// it, agents included.
func TestCreateAgentEndpoint(t *testing.T) {
	setup := func(t *testing.T) (*Server, *plcTestServer, *models.RepoActor) {
		t.Helper()
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)
		s.evtman = s.newTestEvtman(t)
		s.repoman = NewRepoMan(s)
		s.config.Did = "did:web:" + testHostname
		s.config.Hostname = testHostname
		acct := s.createTestAccount(t, "principal."+testHostname)
		s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
		s.config.AgentPrincipals = []string{acct.Did}
		return s, p, mustRepoActor(t, s, acct.Did)
	}
	call := func(t *testing.T, s *Server, caller *models.RepoActor, kind credentialKind, scopes []string, body map[string]any) (int, createAgentOutput, string) {
		t.Helper()
		raw, _ := json.Marshal(body)
		c, rec := newRequestContext(http.MethodPost, "/xrpc/"+createAgentNSID, string(raw), nil)
		c.Set("repo", caller)
		c.Set("credentialKind", kind)
		if scopes != nil {
			c.Set("scopes", scopes)
		}
		if err := s.handleCreateAgentXrpc(c); err != nil {
			t.Fatalf("handler: %v", err)
		}
		var out createAgentOutput
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out, rec.Body.String()
	}
	oauthScopes := func(s *Server) []string {
		return []string{"atproto", "rpc:" + createAgentNSID + "?aud=" + s.config.Did, "repo:" + endorsementCollection}
	}

	t.Run("one call: account, declaration, endorsement", func(t *testing.T) {
		s, p, principal := setup(t)
		code, out, body := call(t, s, principal, credentialOAuth, oauthScopes(s), map[string]any{"recoveryKey": "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N"})
		if code != 200 {
			t.Fatalf("create: %d %s", code, body)
		}
		if out.Did == "" || out.Password == "" || !out.Endorsed || out.Endorsement == "" {
			t.Fatalf("output: %s", body)
		}
		aka := p.ops[0].AlsoKnownAs
		if len(aka) != 2 || aka[1] != plc.IdentLinkAgentOfPrefix+principal.Repo.Did {
			t.Fatalf("declaration: %v", aka)
		}
		if p.ops[0].RotationKeys[0] != "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N" {
			t.Fatalf("recovery key not first: %v", p.ops[0].RotationKeys)
		}
		var r models.Record
		if err := s.db.Client().Where("did = ? AND nsid = ? AND rkey = ?", principal.Repo.Did, endorsementCollection, out.Did).First(&r).Error; err != nil {
			t.Fatalf("no endorsement in the principal's repo: %v", err)
		}
		agent := mustRepoActor(t, s, out.Did)
		if !isAgentRepo(&agent.Repo) {
			t.Fatal("the new account isn't marked as an agent")
		}

		// The agent can't create agents, or change its identity.
		if code, _, _ := call(t, s, agent, credentialLegacyAccess, nil, map[string]any{}); code != 403 {
			t.Fatalf("an agent created an agent: %d", code)
		}
		c, _ := newRequestContext(http.MethodPost, "/xrpc/com.atproto.identity.signPlcOperation", "{}", nil)
		c.Set("repo", agent)
		c.Set("credentialKind", credentialLegacyAccess)
		ran := false
		_ = s.authorizeEndpoint(c, func(echo.Context) error { ran = true; return nil })
		if ran {
			t.Fatal("an agent reached an identity endpoint")
		}
	})

	t.Run("scopes, allowlist and rate limit", func(t *testing.T) {
		s, _, principal := setup(t)
		if code, _, body := call(t, s, principal, credentialOAuth, []string{"atproto", "repo:" + endorsementCollection}, map[string]any{}); code != 403 && code != 401 && code != 400 {
			t.Fatalf("without the rpc scope: %d %s", code, body)
		}
		if code, _, body := call(t, s, principal, credentialOAuth, []string{"atproto", "rpc:" + createAgentNSID + "?aud=" + s.config.Did}, map[string]any{}); code == 200 {
			t.Fatalf("without the endorsement scope: %d %s", code, body)
		}
		if code, _, _ := call(t, s, principal, credentialOAuth, oauthScopes(s), map[string]any{"handle": "evil.example.com"}); code != 400 {
			t.Fatalf("a handle outside the PDS's domain: %d", code)
		}
		s.config.AgentsPerHour = 1
		if code, _, body := call(t, s, principal, credentialLegacyAccess, nil, map[string]any{}); code != 200 {
			t.Fatalf("first: %d %s", code, body)
		}
		if code, _, _ := call(t, s, principal, credentialLegacyAccess, nil, map[string]any{}); code != 429 {
			t.Fatalf("over the limit: %d", code)
		}
		other := s.createTestAccount(t, "other."+testHostname)
		if code, _, _ := call(t, s, mustRepoActor(t, s, other.Did), credentialLegacyAccess, nil, map[string]any{}); code != 403 {
			t.Fatalf("an account not allowed created an agent: %d", code)
		}
		s.config.AgentPrincipals = nil
		if code, _, _ := call(t, s, principal, credentialLegacyAccess, nil, map[string]any{}); code != 403 {
			t.Fatalf("with no principals configured: %d", code)
		}
	})
}
