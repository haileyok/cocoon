package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/internal/space"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
)

// xrpcError is an XRPC error response.
type xrpcError struct {
	Status  int
	Name    string
	Message string
	// Header is set on the response, e.g. WWW-Authenticate.
	Header map[string]string
}

func (e *xrpcError) Error() string { return e.Name + ": " + e.Message }

func errInvalid(name, format string, args ...any) *xrpcError {
	if name == "" {
		name = "InvalidRequest"
	}
	return &xrpcError{Status: 400, Name: name, Message: fmt.Sprintf(format, args...)}
}

func errForbidden(format string, args ...any) *xrpcError {
	return &xrpcError{Status: 403, Name: "Forbidden", Message: fmt.Sprintf(format, args...)}
}

func errAuthRequired(name, format string, args ...any) *xrpcError {
	if name == "" {
		name = "AuthenticationRequired"
	}
	return &xrpcError{Status: 401, Name: name, Message: fmt.Sprintf(format, args...)}
}

var (
	errSpaceNotFound = func() *xrpcError { return errInvalid("SpaceNotFound", "Space not found") }
)

// writeSpaceResult writes a handler's result: an *xrpcError, another error
// (500), a nil body (an empty 200), or a JSON body.
func writeSpaceResult(e echo.Context, body any, err error) error {
	if err != nil {
		var xe *xrpcError
		if errors.As(err, &xe) {
			for k, v := range xe.Header {
				e.Response().Header().Set(k, v)
			}
			return e.JSON(xe.Status, map[string]string{"error": xe.Name, "message": xe.Message})
		}
		slog.Error("space request failed", "path", e.Request().URL.Path, "err", err)
		return helpers.ServerError(e, nil)
	}
	if body == nil {
		return e.JSON(http.StatusOK, map[string]any{})
	}
	return e.JSON(http.StatusOK, body)
}

// bindSpaceJSON decodes a JSON request body.
func bindSpaceJSON(e echo.Context, dst any) error {
	b, err := io.ReadAll(io.LimitReader(e.Request().Body, 2<<20))
	if err != nil {
		return errInvalid("", "could not read the request body")
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return errInvalid("", "Invalid request body: %v", err)
	}
	return nil
}

// parseSpaceParam validates a space-ref param.
func parseSpaceParam(name, v string) (space.Ref, error) {
	if v == "" {
		return space.Ref{}, errInvalid("", "Params must have the property %q", name)
	}
	ref, err := space.ParseRef(v)
	if err != nil {
		return space.Ref{}, errInvalid("", "%s must be a valid space reference", name)
	}
	return ref, nil
}

func parseDIDParam(name, v string) (string, error) {
	if v == "" {
		return "", errInvalid("", "Params must have the property %q", name)
	}
	if _, err := syntax.ParseDID(v); err != nil {
		return "", errInvalid("", "%s must be a valid did", name)
	}
	return v, nil
}

func parseNSIDParam(name, v string, required bool) (string, error) {
	if v == "" {
		if required {
			return "", errInvalid("", "Params must have the property %q", name)
		}
		return "", nil
	}
	if _, err := syntax.ParseNSID(v); err != nil {
		return "", errInvalid("", "%s must be a valid nsid", name)
	}
	return v, nil
}

func parseRkeyParam(name, v string, required bool) (string, error) {
	if v == "" {
		if required {
			return "", errInvalid("", "Params must have the property %q", name)
		}
		return "", nil
	}
	if _, err := syntax.ParseRecordKey(v); err != nil {
		return "", errInvalid("", "%s must be a valid record key", name)
	}
	return v, nil
}

func parseTIDParam(name, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if _, err := syntax.ParseTID(v); err != nil {
		return "", errInvalid("", "%s must be a valid tid", name)
	}
	return v, nil
}

func parseLimitParam(v string, def, min, max int) (int, error) {
	if v == "" {
		return def, nil
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || fmt.Sprint(n) != v {
		return 0, errInvalid("", "limit must be an integer")
	}
	if n < min || n > max {
		return 0, errInvalid("", "limit must be between %d and %d", min, max)
	}
	return n, nil
}

func parseBoolParam(v string) (bool, error) {
	switch v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, errInvalid("", "expected a boolean")
}

var tidClock struct {
	sync.Mutex
	last string
}

// nextTID returns a TID after both now and prev, and after every TID this
// process has handed out.
func nextTID(prev string) string {
	tidClock.Lock()
	defer tidClock.Unlock()
	t := syntax.NewTIDNow(0)
	for _, floor := range []string{prev, tidClock.last} {
		if floor == "" {
			continue
		}
		if f, err := syntax.ParseTID(floor); err == nil && t.String() <= floor {
			t = syntax.NewTIDFromInteger(f.Integer() + 1)
		}
	}
	tidClock.last = t.String()
	return tidClock.last
}

func nowISO() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }

// spaceAuth is an authenticated caller of a space method.
type spaceAuth struct {
	did  string
	repo *models.RepoActor
	// oauth is set for an OAuth session, whose grants are checked; a legacy
	// session has no grants to check.
	oauth  bool
	scopes []string
	// credential is set for a space credential (no account).
	credential *spaceCredentialAuth
}

// spaceCredentialAuth is a verified space credential presented with a request
// signature.
type spaceCredentialAuth struct {
	Space    string
	Audience string
	Issuer   string
	Jti      string
	Exp      int64
	KeyID    string
}

// accountAuth returns the account behind a request authenticated by the
// session middlewares. Only access sessions (legacy or OAuth) act as an
// account here; refresh and service tokens do not.
func accountAuth(e echo.Context) (*spaceAuth, error) {
	kind, _ := e.Get("credentialKind").(credentialKind)
	repo, _ := e.Get("repo").(*models.RepoActor)
	if repo == nil {
		return nil, errAuthRequired("", "Authentication Required")
	}
	switch kind {
	case credentialLegacyAccess:
		return &spaceAuth{did: repo.Repo.Did, repo: repo}, nil
	case credentialOAuth:
		sc, _ := e.Get("scopes").([]string)
		return &spaceAuth{did: repo.Repo.Did, repo: repo, oauth: true, scopes: sc}, nil
	}
	return nil, errAuthRequired("InvalidToken", "Bad token scope")
}

// spacePermissions resolves an OAuth session's space grants: "self"
// authorities resolve to the user.
func (a *spaceAuth) spacePermissions() []*scopes.SpacePermission {
	var out []*scopes.SpacePermission
	for _, raw := range a.scopes {
		if p := scopes.ParseSpacePermission(raw); p != nil {
			out = append(out, p.WithResolvedAuthority(a.did))
		}
	}
	return out
}

// assertSpace checks an OAuth session's grants cover an operation. Legacy
// sessions carry no grants and pass.
func (a *spaceAuth) assertSpace(m scopes.SpaceMatch) error {
	if !a.oauth {
		return nil
	}
	for _, p := range a.spacePermissions() {
		if p.Matches(m) {
			return nil
		}
	}
	needed := scopes.SpaceScopeNeededFor(m)
	return &xrpcError{
		Status:  403,
		Name:    "InsufficientScope",
		Message: "Missing required scope " + needed,
		Header:  map[string]string{"WWW-Authenticate": fmt.Sprintf(`DPoP error="insufficient_scope", error_description="Missing required scope %s"`, needed)},
	}
}

// assertSpaceRef checks a grant for an operation on a space.
func (a *spaceAuth) assertSpaceRef(ref space.Ref, m scopes.SpaceMatch) error {
	m.Type, m.Authority, m.Skey = ref.Type, ref.Authority, ref.Skey
	return a.assertSpace(m)
}

// assertSpaceRead lets an account read only its own repo in a space; reaching
// another member's repo takes a space credential. A missing repo and a repo
// the caller may not read get the same error.
func assertSpaceRead(a *spaceAuth, ref space.Ref, repo string) error {
	if a.credential != nil {
		return assertCredentialSpace(a.credential, ref, repo)
	}
	if a.did != repo {
		return errInvalid("RepoNotFound", "Could not find repo for DID: %s", repo)
	}
	return a.assertSpaceRef(ref, scopes.SpaceMatch{Action: "read_self"})
}

func assertCredentialSpace(c *spaceCredentialAuth, ref space.Ref, audience string) error {
	if audience == "" {
		audience = ref.Authority
	}
	if c.Audience != audience {
		return errAuthRequired("BadSpaceAudience", "space audience does not match the request")
	}
	if c.Space != ref.String() {
		return errInvalid("InvalidCredential", "Credential is not scoped to this space")
	}
	return nil
}

func isSpaceSelfRead(a *spaceAuth, repo string) bool {
	return a.credential == nil && a.did == repo
}

// assertSpaceOwner checks the caller governs the space (a simplespace is
// anchored on its authority's own DID) and holds the manage grant.
func assertSpaceOwner(a *spaceAuth, ref space.Ref, m scopes.SpaceMatch) error {
	if err := a.assertSpaceRef(ref, m); err != nil {
		return err
	}
	if ref.Authority != a.did {
		return errInvalid("NotSpaceOwner", "Not the space owner")
	}
	return nil
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func trimDIDFragment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i]
	}
	return s
}

// spaceClient is the client for space requests to endpoints DID documents
// name. Unless overridden it refuses private and loopback addresses.
func (s *Server) spaceClient() *http.Client {
	s.spaceHTTPOnce.Do(func() {
		if s.spaceHTTP == nil {
			s.spaceHTTP = helpers.NewSafeFetchClient()
		}
	})
	return s.spaceHTTP
}
