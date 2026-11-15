package server

import (
	"bytes"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

// The OAuth consent and account-management pages render data that originates
// off-server (client metadata fetched from the client's own host) alongside
// local user data. These tests execute the production TemplateRenderer so
// they pin the escaping behavior the server actually uses, not a test-local
// copy of the templates.

// renderWithProductionRenderer loads the embedded templates exactly as
// production's loadTemplates does (non-dev path) and renders name with data.
func renderWithProductionRenderer(t *testing.T, name string, data map[string]any) string {
	t.Helper()

	s := newTestServer(t)
	e := echo.New()
	s.echo = e
	s.loadTemplates()

	c, rec := newRequestContext(http.MethodGet, "/", "", nil)
	if err := e.Renderer.Render(&bytes.Buffer{}, name, data, c); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	// Render into a fresh recorder for assertions.
	buf := &bytes.Buffer{}
	if err := e.Renderer.Render(buf, name, data, c); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	_ = rec
	return buf.String()
}

func authorizeAccountLink(t *testing.T, body, path string) string {
	t.Helper()
	for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		href := html.UnescapeString(m[1])
		u, err := url.Parse(href)
		if err == nil && u.Path == path && u.Scheme == "" && u.Host == "" {
			return href
		}
	}
	t.Fatalf("missing local link to %s", path)
	return ""
}

func TestAuthorizeAccountLinksPreserveQuery(t *testing.T) {
	for _, state := range []string{"ordinary-state", `"><script>alert(1)</script>&request_uri=evil#fragment + % ' javascript:alert(2)`} {
		t.Run(state, func(t *testing.T) {
			query := url.Values{
				"client_id":   {"http://localhost"},
				"request_uri": {"urn:ietf:params:oauth:request_uri:abc123"},
				"state":       {state},
				"extra":       {"first&value", "second=value"},
				"empty":       {""},
			}.Encode()
			out := renderWithProductionRenderer(t, "authorize.html", map[string]any{
				"AppName": "Local app", "Handle": "alice.pds.test",
				"QueryParams": query,
				"SigninURL":   "/account/signin?" + query,
				"SignoutURL":  "/account/signout?" + query,
				"Accounts": []models.RepoActor{
					{Repo: models.Repo{Did: "did:plc:alice"}, Actor: models.Actor{Handle: "alice.pds.test"}},
					{Repo: models.Repo{Did: "did:plc:bob"}, Actor: models.Actor{Handle: "bob.pds.test"}},
				},
				"ActiveDid": "did:plc:alice", "HasLoginHint": false,
			})
			for _, path := range []string{"/account/signin", "/account/signout"} {
				if got, want := authorizeAccountLink(t, out, path), path+"?"+query; got != want {
					t.Errorf("account link = %q, want %q", got, want)
				}
			}
			m := queryParamsField.FindStringSubmatch(out)
			if m == nil || html.UnescapeString(m[1]) != query {
				t.Errorf("switch form lost query: %v", m)
			}
			if strings.Contains(out, "<script>") || strings.Contains(out, "ZgotmplZ") {
				t.Fatal("query injected markup or produced a rejected link")
			}
		})
	}
}

func TestAuthorizePageEscapesClientName(t *testing.T) {
	xss := `"/><script>alert(1)</script><img src=x onerror=alert(2)>`
	out := renderWithProductionRenderer(t, "authorize.html", map[string]any{
		"Scopes":       []string{"atproto"},
		"AppName":      xss,
		"Handle":       "alice.pds.test",
		"RequestUri":   "urn:ietf:params:oauth:request_uri:abc123",
		"QueryParams":  "request_uri=abc123&client_id=abc",
		"Accounts":     []any{},
		"ActiveDid":    "",
		"HasLoginHint": false,
	})

	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") {
		t.Fatalf("authorize page contains unescaped client_name markup:\n%s", out)
	}
	// The attacker's text must still be visible (escaped), not silently dropped.
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("client_name was not rendered in escaped form:\n%s", out)
	}
}

func TestAuthorizePageEscapesUserHandle(t *testing.T) {
	xss := `alice.pds.test<script>alert(1)</script>`
	out := renderWithProductionRenderer(t, "authorize.html", map[string]any{
		"Scopes":       []string{"atproto"},
		"AppName":      "Innocent App",
		"Handle":       xss,
		"RequestUri":   "urn:ietf:params:oauth:request_uri:abc123",
		"QueryParams":  "request_uri=abc123",
		"Accounts":     []any{},
		"ActiveDid":    "",
		"HasLoginHint": false,
	})

	if strings.Contains(out, "<script>") {
		t.Fatalf("authorize page contains unescaped handle markup:\n%s", out)
	}
}

// The account management page renders the client_name of every authorized
// OAuth client (persisted XSS surface), plus token and IP data.
func TestAccountPageEscapesClientName(t *testing.T) {
	repo := &models.RepoActor{Repo: models.Repo{Did: "did:plc:abc"}, Actor: models.Actor{Did: "did:plc:abc", Handle: "alice.pds.test"}}
	xss := `<script>alert(document.domain)</script>`
	out := renderWithProductionRenderer(t, "account.html", map[string]any{
		"Repo": repo,
		"Apps": []accountApp{{
			ClientID: `https://evil.example/"><script>x</script>`,
			Name:     xss,
			Host:     "evil.example",
			Initial:  "<",
			URI:      safeClientURI("javascript:alert(1)"),
			Sessions: []accountSession{{ID: 1, IP: xss, LastActiveAgo: "1 minute", SignedInAgo: "1 minute", ExpiresIn: "1 hour"}},
		}},
		"SessionCount":     1,
		"TwoFactorMethods": int64(0),
		"EmailTwoFactor":   false,
		"flashes":          map[string]any{"errors": []any{}, "successes": []any{}},
		"Accounts":         []models.RepoActor{*repo},
		"ActiveDid":        "did:plc:abc",
	})

	if strings.Contains(out, "<script>") {
		t.Fatalf("account page contains unescaped client_name markup:\n%s", out)
	}
	if strings.Contains(out, "javascript:") {
		t.Fatalf("account page links to a javascript: URL:\n%s", out)
	}
}

// The signin page renders query params and flash messages into a form; a
// reflected value must not be able to break out of the hidden input.
func TestSigninPageEscapesQueryParamsAndFlashes(t *testing.T) {
	out := renderWithProductionRenderer(t, "signin.html", map[string]any{
		"flashes":     map[string]any{"errors": []string{`Bad <script>alert(1)</script>`}, "successes": []string{}, "tokenrequired": []string{}},
		"QueryParams": `request_uri=abc"><script>alert(1)</script>`,
		"Accounts":    []any{},
		"ActiveDid":   "",
	})

	if strings.Contains(out, "<script>") {
		t.Fatalf("signin page contains unescaped query params or flash markup:\n%s", out)
	}
}
