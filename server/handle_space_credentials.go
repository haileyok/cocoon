package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/haileyok/cocoon/internal/space"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// The space credential chain: a member's PDS mints a delegation token, and the
// authority exchanges it for a space credential bound to the key that signed
// the exchange (the reference's getDelegationToken.ts, getSpaceCredential.ts
// and simplespace/manager.ts at bluesky-social/atproto 5b95b2f2).

func (s *Server) handleSpaceGetDelegationToken(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", e.QueryParam("space"))
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Action: "read"}); err != nil {
			return nil, err
		}
		key, err := s.accountSigner(a.repo.Repo)
		if err != nil {
			return nil, err
		}
		tok, err := space.CreateSpaceToken(space.TokenDelegation, space.CreateTokenOpts{Iss: a.did, Sub: ref.String(), Aud: ref.HostAud()}, key)
		if err != nil {
			return nil, err
		}
		return map[string]any{"token": tok}, nil
	}()
	return writeSpaceResult(e, body, err)
}

// assertSpaceHost checks this host is the space's authority.
func (s *Server) assertSpaceHost(ctx context.Context, ref space.Ref) (*models.RepoActor, error) {
	repo, err := s.getRepoActorByDid(ctx, ref.Authority)
	if err != nil {
		if notFound(err) {
			return nil, errSpaceNotFound()
		}
		return nil, err
	}
	return repo, nil
}

func (s *Server) handleSpaceGetSpaceCredential(e echo.Context) error {
	body, err := func() (any, error) {
		ctx := e.Request().Context()
		d, err := s.verifyDelegationRequest(e)
		if err != nil {
			return nil, err
		}
		var in struct {
			Space             string `json:"space"`
			ClientAttestation string `json:"clientAttestation"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if d.space != ref.String() {
			return nil, errInvalid("InvalidDelegationToken", "Delegation token subject does not match requested space")
		}
		authority, err := s.assertSpaceHost(ctx, ref)
		if err != nil {
			return nil, err
		}
		clientID := ""
		if in.ClientAttestation != "" {
			if clientID, err = s.verifyClientAttestation(ctx, in.ClientAttestation, ref.HostAud()); err != nil {
				return nil, err
			}
		}
		st := s.spaceStore(nil, ref.Authority)
		sp, err := st.getSpace(ref.String())
		if err != nil {
			return nil, err
		}
		if sp != nil && sp.DeletedAt != nil {
			return nil, errInvalid("SpaceDeleted", "Space has been deleted")
		}
		cfg, err := st.getActiveSpaceConfig(ref.String())
		if err != nil {
			return nil, err
		}
		if err := s.authorizeCredential(ctx, cfg, d.userDid, clientID); err != nil {
			return nil, err
		}
		key, err := s.accountSigner(authority.Repo)
		if err != nil {
			return nil, err
		}
		cred, err := space.CreateSpaceToken(space.TokenCredential, space.CreateTokenOpts{Iss: ref.Authority, Sub: ref.String(), KeyID: d.keyID}, key)
		if err != nil {
			return nil, err
		}
		return map[string]any{"credential": cred}, nil
	}()
	return writeSpaceResult(e, body, err)
}

// authorizeCredential checks both perimeters a credential clears: the app
// first, since it decides from the config alone, so a refused app is never
// disclosed to a third-party managing app; then the user.
func (s *Server) authorizeCredential(ctx context.Context, cfg *models.SimplespaceConfig, userDid, clientID string) error {
	if cfg.AppAccessType == appAccessAllow {
		var allowed []string
		_ = json.Unmarshal([]byte(cfg.AppAllowed), &allowed)
		ok := false
		for _, a := range allowed {
			ok = ok || (clientID != "" && a == clientID)
		}
		if !ok {
			return errInvalid("AppNotAuthorized", "Application not authorized for this space")
		}
	}
	authorized, err := s.authorizeSpaceUser(ctx, cfg, userDid, "read", clientID)
	if err != nil {
		return err
	}
	if !authorized {
		return errInvalid("UserNotAuthorized", "User not authorized for this space")
	}
	return nil
}

// authorizeSpaceUser applies a space's read or write policy to a user. The
// authority is always admitted, so it can't lock itself out.
func (s *Server) authorizeSpaceUser(ctx context.Context, cfg *models.SimplespaceConfig, userDid, access, clientID string) (bool, error) {
	ref, err := space.ParseRef(cfg.Uri)
	if err != nil {
		return false, err
	}
	if userDid == ref.Authority {
		return true, nil
	}
	policy, app := cfg.ReadPolicy, cfg.ReadManagingApp
	if access == "write" {
		policy, app = cfg.WritePolicy, cfg.WriteManagingApp
	}
	switch policy {
	case policyPublic:
		return true, nil
	case policyMemberList:
		m, err := s.spaceStore(nil, ref.Authority).getMember(cfg.Uri, userDid)
		if err != nil || m == nil {
			return false, err
		}
		if access == "read" {
			return m.Read, nil
		}
		return m.Write, nil
	case policyManagingApp:
		if app == nil {
			return false, nil
		}
		return s.checkManagingApp(ctx, ref, *app, userDid, access, clientID), nil
	}
	return false, nil
}

// checkManagingApp asks a space's managing app whether to admit a user. An
// unreachable or failing app denies.
func (s *Server) checkManagingApp(ctx context.Context, ref space.Ref, app, userDid, access, clientID string) bool {
	const lxm = "com.atproto.simplespace.checkUserAccess"
	target, err := s.resolveNotifyTarget(ctx, ref.Authority, app, lxm)
	if err != nil || target == nil {
		s.logger.Warn("could not resolve managing app", "space", ref.String(), "managingApp", app, "err", err)
		return false
	}
	q := url.Values{"space": {ref.String()}, "user": {userDid}, "access": {access}}
	if clientID != "" {
		q.Set("clientId", clientID)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.endpoint+"/xrpc/"+lxm+"?"+q.Encode(), nil)
	if err != nil {
		return false
	}
	for k, v := range target.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.spaceClient().Do(req)
	if err != nil {
		s.logger.Warn("managing app check failed", "space", ref.String(), "managingApp", app, "err", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var out struct {
		Authorized bool `json:"authorized"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	return out.Authorized
}

func (s *Server) handleSpaceNotifyCredentialRevoked(e echo.Context) error {
	body, err := func() (any, error) {
		claims, err := s.verifyServiceAuth(e, "com.atproto.space.notifyCredentialRevoked")
		if err != nil {
			return nil, err
		}
		var in struct {
			Space       string   `json:"space"`
			Credentials []string `json:"credentials"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if len(in.Credentials) < 1 || len(in.Credentials) > 100 {
			return nil, errInvalid("", "credentials must hold 1 to 100 items")
		}
		for _, c := range in.Credentials {
			if c == "" {
				return nil, errInvalid("", "credentials must not be empty")
			}
		}
		if claims.Iss != ref.Authority {
			return nil, errForbidden("Revocation issuer is not the space authority")
		}
		if _, err := s.getRepoActorByDid(e.Request().Context(), claims.Aud); err != nil {
			if notFound(err) {
				return nil, errForbidden("Revocation audience does not match a repo hosted here")
			}
			return nil, err
		}
		return nil, s.addRevokedSpaceCredentials(e.Request().Context(), ref.String(), in.Credentials)
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSimplespaceGetSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := s.spaceAuthFromRequest(e)
		if err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", e.QueryParam("space"))
		if err != nil {
			return nil, err
		}
		if a.credential != nil {
			if err := assertCredentialSpace(a.credential, ref, ""); err != nil {
				return nil, err
			}
		} else if err := assertSpaceOwner(a, ref, scopes.SpaceMatch{Action: "read_self"}); err != nil {
			return nil, err
		}
		cfg, err := s.spaceStore(nil, ref.Authority).getActiveSpaceConfig(ref.String())
		if err != nil {
			return nil, err
		}
		return configToLex(cfg), nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSimplespaceUpdateSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in struct {
			Space       string          `json:"space"`
			ReadPolicy  json.RawMessage `json:"readPolicy"`
			WritePolicy json.RawMessage `json:"writePolicy"`
			AppAccess   json.RawMessage `json:"appAccess"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if err := assertSpaceOwner(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		set := map[string]any{}
		if len(in.ReadPolicy) > 0 && string(in.ReadPolicy) != "null" {
			p, app, err := policyToDB(in.ReadPolicy)
			if err != nil {
				return nil, err
			}
			set["read_policy"], set["read_managing_app"] = p, app
		}
		if len(in.WritePolicy) > 0 && string(in.WritePolicy) != "null" {
			p, app, err := policyToDB(in.WritePolicy)
			if err != nil {
				return nil, err
			}
			set["write_policy"], set["write_managing_app"] = p, app
		}
		if len(in.AppAccess) > 0 && string(in.AppAccess) != "null" {
			typ, allowed, err := appAccessToDB(in.AppAccess)
			if err != nil {
				return nil, err
			}
			set["app_access_type"], set["app_allowed"] = typ, allowed
		}
		return nil, s.db.Client().WithContext(e.Request().Context()).Transaction(func(tx *gorm.DB) error {
			st := s.spaceStore(tx, a.did)
			if _, err := st.getActiveSpaceConfig(ref.String()); err != nil {
				return err
			}
			return st.updateSpaceConfig(ref.String(), set)
		})
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSimplespaceListMembers(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		q := e.QueryParams()
		ref, err := parseSpaceParam("space", q.Get("space"))
		if err != nil {
			return nil, err
		}
		limit, err := parseLimitParam(q.Get("limit"), 100, 1, 1000)
		if err != nil {
			return nil, err
		}
		if err := assertSpaceOwner(a, ref, scopes.SpaceMatch{Action: "read_self"}); err != nil {
			return nil, err
		}
		st := s.spaceStore(nil, a.did)
		if _, err := st.getActiveSpaceConfig(ref.String()); err != nil {
			return nil, err
		}
		rows, err := st.listMembers(ref.String(), limit, q.Get("cursor"))
		if err != nil {
			return nil, err
		}
		members := make([]map[string]any, 0, len(rows))
		for _, m := range rows {
			members = append(members, map[string]any{"did": m.MemberDid, "read": m.Read, "write": m.Write})
		}
		res := map[string]any{"members": members}
		if len(rows) > 0 {
			res["cursor"] = rows[len(rows)-1].MemberDid
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSimplespaceDeleteSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in struct {
			Space string `json:"space"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if err := assertSpaceOwner(a, ref, scopes.SpaceMatch{Manage: "delete"}); err != nil {
			return nil, err
		}
		st := s.spaceStore(nil, a.did)
		sp, err := st.getSpace(ref.String())
		if err != nil {
			return nil, err
		}
		if sp == nil {
			return nil, errSpaceNotFound()
		}
		if sp.DeletedAt != nil {
			return nil, nil
		}
		return nil, s.deleteSpace(e.Request().Context(), ref)
	}()
	return writeSpaceResult(e, body, err)
}

// deleteSpace deletes a governed space with the authority's own repo in it,
// keeping the space row as a tombstone so getSpaceCredential answers
// SpaceDeleted, then tells registered services, best effort.
func (s *Server) deleteSpace(ctx context.Context, ref space.Ref) error {
	uri := ref.String()
	var recipients []models.SpaceCredentialRecipient
	err := s.db.Client().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		st := s.spaceStore(tx, ref.Authority)
		var err error
		if recipients, err = st.activeRecipients(uri); err != nil {
			return err
		}
		return st.deleteSpace(uri)
	})
	if err != nil {
		return err
	}
	const lxm = "com.atproto.space.notifySpaceDeleted"
	s.goSpace(func(ctx context.Context) {
		for _, r := range recipients {
			if err := s.sendNotify(ctx, ref.Authority, r.ServiceDid, lxm, map[string]any{"space": uri}); err != nil {
				s.logger.Warn("notify failed", "space", uri, "service", r.ServiceDid, "lxm", lxm, "err", err)
			}
		}
	})
	return nil
}

// goSpace runs background space work, tracked so tests can wait for it.
func (s *Server) goSpace(fn func(ctx context.Context)) {
	s.spaceJobs.Add(1)
	go func() {
		defer s.spaceJobs.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		fn(ctx)
	}()
}

// sendNotify posts a notification from a local account to a service.
func (s *Server) sendNotify(ctx context.Context, iss, service, lxm string, body any) error {
	target, err := s.resolveNotifyTarget(ctx, iss, service, lxm)
	if err != nil {
		return err
	}
	if target == nil {
		return errNoTarget
	}
	_, err = s.postXRPC(ctx, target, lxm, body)
	return err
}

// postXRPC posts JSON to a target, returning the status. A non-2xx status is
// an *xrpcCallError.
func (s *Server) postXRPC(ctx context.Context, target *notifyTarget, lxm string, body any) (int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.endpoint+"/xrpc/"+lxm, bytesReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range target.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.spaceClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var xe struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&xe)
		return resp.StatusCode, &xrpcCallError{Status: resp.StatusCode, Name: xe.Error}
	}
	return resp.StatusCode, nil
}

type xrpcCallError struct {
	Status int
	Name   string
}

func (e *xrpcCallError) Error() string {
	return fmt.Sprintf("xrpc call failed: %d %s", e.Status, e.Name)
}
