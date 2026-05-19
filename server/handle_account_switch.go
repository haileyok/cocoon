package server

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

type AccountSwitchRequest struct {
	Did         string `form:"did"`
	QueryParams string `form:"query_params"`
	Next        string `form:"next"`
}

func sanitizeLocalRedirectPath(next string) string {
	redirect := strings.TrimSpace(next)
	if redirect == "" {
		return "/account"
	}
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		return "/account"
	}

	parsed, err := url.Parse(redirect)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "/account"
	}

	return redirect
}

func mergeRedirectQuery(redirect string, queryParams string) (string, error) {
	parsedRedirect, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}

	merged := parsedRedirect.Query()

	rawQueryParams := strings.TrimSpace(queryParams)
	if rawQueryParams != "" {
		rawQueryParams = strings.TrimPrefix(rawQueryParams, "?")
		additional, err := url.ParseQuery(rawQueryParams)
		if err != nil {
			return "", err
		}
		for key, values := range additional {
			for _, value := range values {
				merged.Add(key, value)
			}
		}
	}

	parsedRedirect.RawQuery = merged.Encode()
	return parsedRedirect.String(), nil
}

func isSameOriginRequest(e echo.Context) bool {
	host := e.Request().Host

	origin := strings.TrimSpace(e.Request().Header.Get("Origin"))
	if origin != "" {
		parsedOrigin, err := url.Parse(origin)
		return err == nil && parsedOrigin.Host == host
	}

	referer := strings.TrimSpace(e.Request().Header.Get("Referer"))
	if referer != "" {
		parsedReferer, err := url.Parse(referer)
		return err == nil && parsedReferer.Host == host
	}

	return false
}

func (s *Server) handleAccountSwitchPost(e echo.Context) error {
	if !isSameOriginRequest(e) {
		return e.JSON(http.StatusForbidden, map[string]string{"error": "Forbidden"})
	}

	var req AccountSwitchRequest
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, to.StringPtr("invalid switch account request"))
	}

	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return err
	}

	dids := getSessionDids(sess)
	if !slices.Contains(dids, req.Did) {
		return helpers.InputError(e, to.StringPtr("requested account is not logged in"))
	}

	setActiveSessionDid(sess, req.Did)
	applyAccountSessionOptions(sess, int(AccountSessionMaxAge.Seconds()))

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	redirect := sanitizeLocalRedirectPath(req.Next)
	redirect, err = mergeRedirectQuery(redirect, req.QueryParams)
	if err != nil {
		return helpers.InputError(e, to.StringPtr("invalid query params"))
	}

	return e.Redirect(303, redirect)
}
