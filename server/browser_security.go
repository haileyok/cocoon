package server

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
)

// The browser UI has no scripts. Styles include existing style attributes, and
// TOTP setup embeds a data: PNG. Do not add form-action 'self': Chromium applies
// it to the OAuth form's cross-origin 303 callback too, breaking consent.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action
const browserContentSecurityPolicy = "default-src 'none'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"

// browserSecurityHeaders is intentionally scoped to browser routes, including
// their errors and redirects. Protocol endpoints keep their existing CORS and
// response policies. Register with Echo.Use, not Pre, alongside session setup.
func browserSecurityHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		path := e.Request().URL.Path
		if path == "/account" || strings.HasPrefix(path, "/account/") || path == "/oauth/authorize" {
			h := e.Response().Header()
			h.Set("Content-Security-Policy", browserContentSecurityPolicy)
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Cache-Control", "no-store")
		}
		return next(e)
	}
}

// isSameOriginRequest implements the Origin/Referer CSRF check for browser
// forms. Compare the full origin, not the site: SameSite=Lax still sends cookies
// from sibling subdomains. An explicit null, malformed, or foreign Origin must
// not fall back to Referer. Missing both headers fails closed.
//
// The source may match the origin the request reached, using e.Scheme (Echo
// honors X-Forwarded-Proto only from loopback and private peers), or the PDS's
// public https origin. The second keeps consent working behind proxies that
// rewrite Host or don't forward the scheme; a page on another origin can't
// send it.
func (s *Server) isSameOriginRequest(e echo.Context) bool {
	r := e.Request()
	values, hasOrigin := r.Header["Origin"]
	if !hasOrigin {
		values = r.Header.Values("Referer")
	}
	if len(values) != 1 {
		return false
	}
	source, err := url.Parse(strings.TrimSpace(values[0]))
	if err != nil || source.User != nil || source.Opaque != "" || source.Fragment != "" {
		return false
	}
	if hasOrigin && (source.Path != "" || source.RawQuery != "" || source.ForceQuery) {
		return false
	}
	for _, origin := range []string{e.Scheme() + "://" + r.Host, "https://" + s.config.Hostname} {
		if target, err := url.Parse(origin); err == nil && sameOrigin(source, target) {
			return true
		}
	}
	return false
}

func sameOrigin(source, target *url.URL) bool {
	sourcePort, sourceOK := originPort(source)
	targetPort, targetOK := originPort(target)
	return sourceOK && targetOK && strings.EqualFold(source.Scheme, target.Scheme) &&
		strings.EqualFold(source.Hostname(), target.Hostname()) && sourcePort == targetPort
}

func originPort(u *url.URL) (int, bool) {
	if u.Hostname() == "" {
		return 0, false
	}
	var defaultPort int
	switch strings.ToLower(u.Scheme) {
	case "https":
		defaultPort = 443
	case "http":
		defaultPort = 80
	default:
		return 0, false
	}
	if u.Port() == "" {
		return defaultPort, !strings.HasSuffix(u.Host, ":")
	}
	port, err := strconv.Atoi(u.Port())
	return port, err == nil && port > 0 && port <= 65535
}
