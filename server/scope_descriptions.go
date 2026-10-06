package server

import (
	"context"
	"net/http"
	"slices"
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

// consentScopes returns the scopes to show on the consent page and their
// descriptions. include: sets are expanded the same way the token endpoint
// expands them, so the page shows what the user is actually granting.
func (s *Server) consentScopes(ctx context.Context, scope, userDid string) ([]string, []scopePermission) {
	expanded := s.expandScopes(ctx, scope, userDid)
	return strings.Fields(expanded), describeScopes(expanded)
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
		// space: grants
		spaces      []string
		spaceTypes  []string
		spaceManage []string
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
		case scopes.ResourceSpace:
			spaces = append(spaces, raw)
			if !slices.Contains(spaceTypes, sc.Space.Type) {
				spaceTypes = append(spaceTypes, sc.Space.Type)
			}
			if sc.Space.Manage != nil {
				spaceManage = append(spaceManage, raw)
			}
		default:
			other = append(other, raw)
		}
	}

	if len(include) > 0 {
		names := make([]string, 0, len(include))
		for _, raw := range include {
			names = append(names, strings.TrimPrefix(raw, "include:"))
		}
		add(scopePermission{
			Title:  "Permissions defined by the app's publisher",
			Detail: "The app asked for these sets of permissions: " + strings.Join(names, ", ") + ". What Cocoon could look up from them is listed below.",
			Raw:    include,
		})
	}
	if len(repo) > 0 {
		detail := "Create, change, or delete specific kinds of records in your repository."
		if repoAll {
			detail = "Create, change, or delete any record in your repository."
		}
		add(scopePermission{Title: "Change your data", Detail: detail, Sensitive: repoAll, Raw: repo})
	}
	if len(spaces) > 0 {
		kinds := strings.Join(spaceTypes, ", ")
		if slices.Contains(spaceTypes, "*") {
			kinds = "any kind"
		}
		add(scopePermission{Title: "Your private spaces", Detail: "Read and write your data in private spaces (" + kinds + "), which only their members can see.", Raw: spaces})
	}
	if len(spaceManage) > 0 {
		add(scopePermission{Title: "Manage your private spaces", Detail: "Create, change, or delete spaces you own and decide who belongs to them.", Sensitive: true, Raw: spaceManage})
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
