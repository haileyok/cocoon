package server

import (
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// Curated documented routes: every route docs/agent-setup.md instructs an
// agent to call must be mentioned in the doc AND registered on the server's
// router. Both directions are asserted so the test fails on route renames and
// on doc omissions alike.
var documentedAgentRoutes = []string{
	"/xrpc/_health",
	"/xrpc/com.atproto.server.createInviteCode",
	"/xrpc/com.atproto.server.createAccount",
	"/xrpc/com.atproto.server.createSession",
	"/xrpc/com.atproto.server.refreshSession",
	"/xrpc/com.atproto.repo.createRecord",
	"/xrpc/com.atproto.repo.getRecord",
	"/.well-known/atproto-did",
	"/.well-known/oauth-protected-resource",
	"/.well-known/oauth-authorization-server",
	"/oauth/par",
	"/oauth/token",
	"/admin/oauth/authorize",
	"/admin/accounts",
	"/admin/account",
}

// The runbook's eight sections, asserted present so each clause of the docs
// acceptance criteria has a failing mode.
var documentedAgentSections = []string{
	"## 1. Deploy",
	"## 2. Invite code",
	"## 3. Provision an account",
	"## 4. Session tokens",
	"## 5. First write",
	"## 6. Full OAuth client flow",
	"## 7. Manage",
	"## 8. Troubleshooting",
}

func readDocFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// newDocsTestServer builds a server whose full route table is registered, the
// same way Serve() does, but without starting the HTTP listener.
func newDocsTestServer(t *testing.T) *Server {
	t.Helper()

	s := newTestServer(t)
	attachOauthProvider(t, s)

	s.echo = echo.New()
	s.echo.Validator = newTestValidator()
	s.addRoutes()
	return s
}

// TestAgentSetupDocRoutesRegistered asserts every route the agent runbook
// documents is registered on the router, and vice versa within the curated
// list (the doc mentions each path).
func TestAgentSetupDocRoutesRegistered(t *testing.T) {
	doc := readDocFile(t, "../docs/agent-setup.md")

	s := newDocsTestServer(t)
	registered := map[string]bool{}
	for _, r := range s.echo.Routes() {
		registered[r.Path] = true
	}

	for _, path := range documentedAgentRoutes {
		if !strings.Contains(doc, path) {
			t.Errorf("docs/agent-setup.md does not mention documented route %s", path)
		}
		if !registered[path] {
			t.Errorf("route %s is documented but not registered on the server", path)
		}
	}
}

// TestAgentSetupDocSections asserts all eight runbook sections are present.
func TestAgentSetupDocSections(t *testing.T) {
	doc := readDocFile(t, "../docs/agent-setup.md")
	for _, section := range documentedAgentSections {
		if !strings.Contains(doc, section) {
			t.Errorf("docs/agent-setup.md is missing section %q", section)
		}
	}
}

// TestReadmeLinksAgentSetup asserts the README points agents at the runbook.
func TestReadmeLinksAgentSetup(t *testing.T) {
	readme := readDocFile(t, "../README.md")
	if !strings.Contains(readme, "docs/agent-setup.md") {
		t.Fatal("README.md does not link to docs/agent-setup.md")
	}
}
