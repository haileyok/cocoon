package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type OauthSigninInput struct {
	Username        string `form:"username"`
	Password        string `form:"password"`
	AuthFactorToken string `form:"token"`
	QueryParams     string `form:"query_params"`
}

type signinVerifyInput struct {
	Token string `form:"token"`
}

// Signing in with a second factor happens in two steps. Once the password
// checks out, the account and where to go afterwards are kept in the browser
// session, so the code page only asks for the code and the OAuth request
// can't be lost between the two steps.
const (
	pendingSigninDidKey     = "signin_pending_did"
	pendingSigninVersionKey = "signin_pending_version"
	pendingSigninAtKey      = "signin_pending_at"
	pendingSigninReturnKey  = "signin_pending_return"

	// pendingSigninLifetime matches how long an emailed code is valid.
	pendingSigninLifetime = 10 * time.Minute
)

type pendingSignin struct {
	Did            string
	SessionVersion int64
	Return         string // OAuth authorize query, empty for the account page
}

func setPendingSignin(sess *sessions.Session, p pendingSignin, now time.Time) {
	sess.Values[pendingSigninDidKey] = p.Did
	sess.Values[pendingSigninVersionKey] = p.SessionVersion
	sess.Values[pendingSigninAtKey] = now.Unix()
	sess.Values[pendingSigninReturnKey] = p.Return
}

func clearPendingSignin(sess *sessions.Session) {
	delete(sess.Values, pendingSigninDidKey)
	delete(sess.Values, pendingSigninVersionKey)
	delete(sess.Values, pendingSigninAtKey)
	delete(sess.Values, pendingSigninReturnKey)
}

// getPendingSignin returns the password-verified sign-in waiting for a code.
// ok is false when there is none or it is too old; the OAuth return is still
// reported so the caller can send the user back to the start of that flow.
func getPendingSignin(sess *sessions.Session, now time.Time) (p pendingSignin, ok bool) {
	if sess == nil {
		return p, false
	}
	p.Did, _ = sess.Values[pendingSigninDidKey].(string)
	p.SessionVersion, _ = sess.Values[pendingSigninVersionKey].(int64)
	p.Return, _ = sess.Values[pendingSigninReturnKey].(string)
	at, _ := sess.Values[pendingSigninAtKey].(int64)
	if p.Did == "" || at == 0 {
		return p, false
	}
	started := time.Unix(at, 0)
	if now.Before(started.Add(-time.Minute)) || now.After(started.Add(pendingSigninLifetime)) {
		return p, false
	}
	return p, true
}

// oauthReturnQuery keeps a sign-in query only when it carries an OAuth
// request. Other query strings (like "?add=1" for adding an account) must not
// send the user to /oauth/authorize afterwards.
func oauthReturnQuery(query string) string {
	query = strings.TrimPrefix(strings.TrimSpace(query), "?")
	q, err := url.ParseQuery(query)
	if err != nil || (q.Get("client_id") == "" && q.Get("request_uri") == "") {
		return ""
	}
	return q.Encode()
}

// signinReturnPath is where a finished sign-in goes: back into the OAuth
// flow when it started there, otherwise the account page.
func signinReturnPath(query string) string {
	query = strings.TrimPrefix(strings.TrimSpace(query), "?")
	if query == "" {
		return "/account"
	}
	return "/oauth/authorize?" + query
}

func signinPath(query string) string {
	query = strings.TrimPrefix(strings.TrimSpace(query), "?")
	if query == "" {
		return "/account/signin"
	}
	return "/account/signin?" + query
}

var ErrSessionUnauthenticated = errors.New("session is unauthenticated")

func (s *Server) getSessionRepoAndAccountsOrErr(e echo.Context) (*models.RepoActor, *sessions.Session, []models.RepoActor, error) {
	ctx := e.Request().Context()
	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return nil, nil, nil, err
	}

	return s.getSessionRepoAndAccountsFromSessionOrErr(e, ctx, sess)
}

func (s *Server) getSessionRepoAndAccountsFromSessionOrErr(e echo.Context, ctx context.Context, sess *sessions.Session) (*models.RepoActor, *sessions.Session, []models.RepoActor, error) {
	if sess == nil {
		return nil, nil, nil, errors.New("session is nil")
	}

	accounts, changed, err := s.getSessionAccountActors(ctx, sess)
	if err != nil {
		return nil, sess, nil, err
	}
	if changed {
		s.applyAccountSessionOptions(sess, int(AccountSessionMaxAge.Seconds()))
		if err := sess.Save(e.Request(), e.Response()); err != nil {
			return nil, sess, nil, err
		}
	}

	did := getActiveSessionDid(sess)
	if did == "" {
		return nil, sess, accounts, fmt.Errorf("%w: did was not set in session", ErrSessionUnauthenticated)
	}

	for i := range accounts {
		if accounts[i].Repo.Did == did {
			return &accounts[i], sess, accounts, nil
		}
	}

	return nil, sess, accounts, fmt.Errorf("%w: did was not found in session accounts", ErrSessionUnauthenticated)
}

func (s *Server) getSessionRepoOrErr(e echo.Context) (*models.RepoActor, *sessions.Session, error) {
	repo, sess, _, err := s.getSessionRepoAndAccountsOrErr(e)
	return repo, sess, err
}

func getFlashesFromSession(e echo.Context, sess *sessions.Session) map[string]any {
	defer sess.Save(e.Request(), e.Response())
	return map[string]any{
		"errors":        sess.Flashes("error"),
		"successes":     sess.Flashes("success"),
		"tokenrequired": sess.Flashes("tokenrequired"),
	}
}

// oauthRequestAppName names the app behind an in-progress OAuth request, so
// the sign-in pages can say where the user is headed. It returns "" when the
// query isn't an OAuth request or the app can't be identified quickly.
func (s *Server) oauthRequestAppName(ctx context.Context, query string) (string, *provider.OauthAuthorizationRequest) {
	q, err := url.ParseQuery(strings.TrimPrefix(query, "?"))
	if err != nil {
		return "", nil
	}
	var clientID string
	var authReq *provider.OauthAuthorizationRequest
	if reqURI := q.Get("request_uri"); reqURI != "" {
		if id, err := oauth.DecodeRequestUri(reqURI); err == nil {
			var r provider.OauthAuthorizationRequest
			if err := s.db.Raw(ctx, "SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, id).Scan(&r).Error; err == nil && r.RequestId != "" {
				authReq = &r
				clientID = r.ClientId
			}
		}
	}
	if clientID == "" {
		clientID = q.Get("client_id")
	}
	if clientID == "" {
		return "", authReq
	}
	d := s.describeClients(ctx, []string{clientID})[clientID]
	if d.Name != "" {
		return d.Name, authReq
	}
	return clientHost(clientID), authReq
}

func (s *Server) handleAccountSigninGet(e echo.Context) error {
	ctx := e.Request().Context()
	repo, sess, accounts, err := s.getSessionRepoAndAccountsOrErr(e)
	if err != nil && !errors.Is(err, ErrSessionUnauthenticated) {
		return helpers.ServerError(e, nil)
	}
	if err == nil && e.QueryString() == "" {
		return e.Redirect(303, "/account")
	}

	if sess == nil {
		return helpers.ServerError(e, nil)
	}

	activeDid := ""
	if repo != nil {
		activeDid = repo.Repo.Did
	}

	queryParams := oauthReturnQuery(e.QueryParams().Encode())
	appName, authReq := s.oauthRequestAppName(ctx, queryParams)
	username := e.QueryParam("login_hint")
	if username == "" && authReq != nil && authReq.Parameters.LoginHint != nil {
		username = *authReq.Parameters.LoginHint
	}

	return e.Render(200, "signin.html", map[string]any{
		"flashes":     getFlashesFromSession(e, sess),
		"QueryParams": queryParams,
		"Accounts":    accounts,
		"ActiveDid":   activeDid,
		"AppName":     appName,
		"Username":    username,
		"Hostname":    s.config.Hostname,
	})
}

func (s *Server) lookupSigninRepo(ctx context.Context, username string) (*models.RepoActor, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var query string
	if _, err := syntax.ParseDID(username); err == nil {
		query = "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?"
	} else if _, err := syntax.ParseHandle(username); err == nil {
		query = "SELECT r.*, a.* FROM actors a LEFT JOIN repos r ON a.did = r.did WHERE a.handle = ?"
	} else {
		query = "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email = ?"
	}
	var repo models.RepoActor
	if err := s.db.Raw(ctx, query, nil, username).Scan(&repo).Error; err != nil {
		return nil, err
	}
	if repo.Repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}

// finishSignin adds the account to the browser session and sends the user on.
func (s *Server) finishSignin(e echo.Context, sess *sessions.Session, repo *models.RepoActor, returnQuery string) error {
	clearPendingSignin(sess)
	s.applyAccountSessionOptions(sess, int(AccountSessionMaxAge.Seconds()))
	setActiveSessionDid(sess, repo.Repo.Did)
	sess.Values["version:"+repo.Repo.Did] = repo.SessionVersion
	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}
	return e.Redirect(303, signinReturnPath(returnQuery))
}

func (s *Server) handleAccountSigninPost(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAccountSigninPost")

	var req OauthSigninInput
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding sign in req", "error", err)
		return helpers.ServerError(e, nil)
	}
	req.QueryParams = oauthReturnQuery(req.QueryParams)

	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return helpers.ServerError(e, nil)
	}
	// A new password attempt replaces any sign-in that was waiting on a code.
	clearPendingSignin(sess)

	back := func(msg string) error {
		sess.AddFlash(msg, "error")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, signinPath(req.QueryParams))
	}

	repo, err := s.lookupSigninRepo(ctx, req.Username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return back("Handle or password is incorrect.")
		}
		logger.Error("looking up account for sign in", "error", err)
		return back("Something went wrong. Please try again.")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return back("Handle or password is incorrect.")
		}
		return back("Something went wrong. Please try again.")
	}

	res, err := s.checkSecondFactor(ctx, repo, req.AuthFactorToken)
	pending := pendingSignin{Did: repo.Repo.Did, SessionVersion: repo.SessionVersion, Return: req.QueryParams}
	toVerify := func(msg string) error {
		setPendingSignin(sess, pending, time.Now())
		if msg != "" {
			sess.AddFlash(msg, "error")
		}
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/signin/verify")
	}
	if errors.Is(err, errYubiCloudUnavailable) {
		return toVerify("Couldn't check your YubiKey with Yubico right now. Try again shortly, or use another sign-in method.")
	}
	if err != nil {
		logger.Error("checking second factor", "error", err)
		return back("Something went wrong. Please try again.")
	}

	switch res {
	case secondFactorOK:
		return s.finishSignin(e, sess, repo, req.QueryParams)
	case secondFactorRequired:
		return toVerify("")
	case secondFactorInvalid:
		return toVerify("That code is incorrect.")
	case secondFactorLocked:
		return back("Too many incorrect codes. Try again in a few minutes.")
	default: // secondFactorExpired: only emailed codes expire
		if err := s.createAndSendTwoFactorCode(ctx, *repo); err != nil {
			logger.Error("sending two factor code", "error", err)
			return back("Something went wrong. Please try again.")
		}
		return toVerify("That code has expired. We've emailed you a new one.")
	}
}

func (s *Server) hasStrongSecondFactor(ctx context.Context, did string) (bool, error) {
	var n int64
	if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM two_factor_credentials WHERE did = ?", nil, did).Scan(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Server) signinVerifyState(e echo.Context) (*sessions.Session, *models.RepoActor, pendingSignin, error) {
	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return nil, nil, pendingSignin{}, err
	}
	p, ok := getPendingSignin(sess, time.Now())
	if !ok {
		return sess, nil, p, nil
	}
	repo, err := s.getRepoActorByDid(e.Request().Context(), p.Did)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return sess, nil, p, nil
		}
		return sess, nil, p, err
	}
	// A password reset or "sign out everywhere" since the password step
	// cancels it.
	if repo.SessionVersion != p.SessionVersion {
		return sess, nil, p, nil
	}
	return sess, repo, p, nil
}

// restartSignin sends the user back to the password step, keeping the OAuth
// request they came with.
func (s *Server) restartSignin(e echo.Context, sess *sessions.Session, p pendingSignin, msg string) error {
	clearPendingSignin(sess)
	if msg != "" {
		sess.AddFlash(msg, "error")
	}
	sess.Save(e.Request(), e.Response())
	return e.Redirect(303, signinPath(p.Return))
}

func (s *Server) handleAccountSigninVerifyGet(e echo.Context) error {
	ctx := e.Request().Context()
	sess, repo, p, err := s.signinVerifyState(e)
	if err != nil {
		s.logger.Error("loading pending sign in", "error", err)
		return helpers.ServerError(e, nil)
	}
	if repo == nil {
		return s.restartSignin(e, sess, p, "Your sign-in timed out. Please enter your password again.")
	}

	creds, err := s.getTwoFactorCredentials(ctx, repo.Repo.Did)
	if err != nil {
		s.logger.Error("loading two factor methods", "error", err)
		return helpers.ServerError(e, nil)
	}
	hasTOTP, hasYubiKey := false, false
	for _, c := range creds {
		switch c.Type {
		case models.TwoFactorCredentialTOTP:
			hasTOTP = true
		case models.TwoFactorCredentialYubicoOTP:
			hasYubiKey = true
		}
	}

	appName, _ := s.oauthRequestAppName(ctx, p.Return)
	return e.Render(200, "signin_verify.html", map[string]any{
		"flashes":    getFlashesFromSession(e, sess),
		"Handle":     repo.Handle,
		"EmailCode":  len(creds) == 0,
		"HasTOTP":    hasTOTP,
		"HasYubiKey": hasYubiKey,
		"AppName":    appName,
		"RestartURL": signinPath(p.Return),
		"Hostname":   s.config.Hostname,
	})
}

func (s *Server) handleAccountSigninVerifyPost(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAccountSigninVerifyPost")

	var req signinVerifyInput
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, nil)
	}

	sess, repo, p, err := s.signinVerifyState(e)
	if err != nil {
		logger.Error("loading pending sign in", "error", err)
		return helpers.ServerError(e, nil)
	}
	if repo == nil {
		return s.restartSignin(e, sess, p, "Your sign-in timed out. Please enter your password again.")
	}

	again := func(msg, kind string) error {
		sess.AddFlash(msg, kind)
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/signin/verify")
	}

	res, err := s.checkSecondFactor(ctx, repo, req.Token)
	if errors.Is(err, errYubiCloudUnavailable) {
		return again("Couldn't check your YubiKey with Yubico right now. Try again shortly, or use another sign-in method.", "error")
	}
	if err != nil {
		logger.Error("checking second factor", "error", err)
		return again("Something went wrong. Please try again.", "error")
	}

	switch res {
	case secondFactorOK:
		return s.finishSignin(e, sess, repo, p.Return)
	case secondFactorRequired:
		// With emailed codes, checkSecondFactor has just sent a fresh one
		// (the page's "Send a new code" button submits an empty code).
		if has, err := s.hasStrongSecondFactor(ctx, repo.Repo.Did); err == nil && has {
			return again("Enter a code to continue.", "error")
		}
		return again("We've emailed you a new code.", "success")
	case secondFactorInvalid:
		return again("That code is incorrect.", "error")
	case secondFactorLocked:
		return s.restartSignin(e, sess, p, "Too many incorrect codes. Try again in a few minutes.")
	default: // secondFactorExpired: only emailed codes expire
		if err := s.createAndSendTwoFactorCode(ctx, *repo); err != nil {
			logger.Error("sending two factor code", "error", err)
			return again("Something went wrong. Please try again.", "error")
		}
		return again("That code has expired. We've emailed you a new one.", "error")
	}
}
