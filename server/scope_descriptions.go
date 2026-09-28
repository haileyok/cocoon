package server

import (
	"net/http"
	"strings"

	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
)

// scopePermission is one line on the consent page: a plain-language summary
// of what a group of requested scopes allows, with the raw scopes kept for
// anyone who wants to check.
type scopePermission struct {
	Title     string
	Detail    string
	Sensitive bool
	Raw       []string
}

func describeScopes(scope string) []scopePermission {
	var (
		out     []scopePermission
		repo    []string
		repoAll bool
		rpc     []string
		blob    []string
		account []string
		ident   []string
		include []string
		other   []string
	)
	add := func(p scopePermission) { out = append(out, p) }

	for _, raw := range strings.Fields(scope) {
		sc, err := scopes.Parse(raw)
		if err != nil {
			other = append(other, raw)
			continue
		}
		switch sc.Resource {
		case scopes.ResourceAtproto:
			add(scopePermission{Title: "Know who you are", Detail: "See your handle and DID.", Raw: []string{raw}})
		case scopes.ResourceTransition:
			switch sc.Transition {
			case "generic":
				add(scopePermission{Title: "Full access to your account", Detail: "Read and write posts, likes, follows, and other data, and act on your behalf with other services. Does not include direct messages.", Sensitive: true, Raw: []string{raw}})
			case "chat.bsky":
				add(scopePermission{Title: "Your direct messages", Detail: "Read and send Bluesky direct messages.", Sensitive: true, Raw: []string{raw}})
			case "email":
				add(scopePermission{Title: "Your email address", Detail: "See the email address on your account.", Raw: []string{raw}})
			default:
				other = append(other, raw)
			}
		case scopes.ResourceRepo:
			repo = append(repo, raw)
			for _, c := range sc.Collections {
				if c == "*" {
					repoAll = true
				}
			}
		case scopes.ResourceRPC:
			rpc = append(rpc, raw)
		case scopes.ResourceBlob:
			blob = append(blob, raw)
		case scopes.ResourceAccount:
			account = append(account, raw)
		case scopes.ResourceIdentity:
			ident = append(ident, raw)
		case scopes.ResourceInclude:
			include = append(include, raw)
		default:
			other = append(other, raw)
		}
	}

	if len(include) > 0 {
		add(scopePermission{Title: "A bundle of permissions", Detail: "Permissions defined by the app's publisher.", Raw: include})
	}
	if len(repo) > 0 {
		detail := "Create, change, or delete specific kinds of records in your repository."
		if repoAll {
			detail = "Create, change, or delete any record in your repository."
		}
		add(scopePermission{Title: "Change your data", Detail: detail, Sensitive: repoAll, Raw: repo})
	}
	if len(blob) > 0 {
		add(scopePermission{Title: "Upload media", Detail: "Upload images, video, or other files to your account.", Raw: blob})
	}
	if len(rpc) > 0 {
		add(scopePermission{Title: "Talk to other services as you", Detail: "Make requests on your behalf to other atproto services.", Raw: rpc})
	}
	if len(account) > 0 {
		add(scopePermission{Title: "Manage account settings", Detail: "Access account-level settings such as email or status.", Sensitive: true, Raw: account})
	}
	if len(ident) > 0 {
		add(scopePermission{Title: "Change your identity", Detail: "Change your handle or DID document.", Sensitive: true, Raw: ident})
	}
	if len(other) > 0 {
		add(scopePermission{Title: "Other permissions", Raw: other})
	}
	return out
}

// renderMessage shows a simple page for errors a person can act on, such as
// an expired sign-in request.
func (s *Server) renderMessage(e echo.Context, status int, title, message string) error {
	if status == 0 {
		status = http.StatusOK
	}
	return e.Render(status, "message.html", map[string]any{
		"Title":    title,
		"Message":  message,
		"Hostname": s.config.Hostname,
	})
}
