package server

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// The space credential chain: a member's PDS mints a delegation token, and the
// authority authorizes syncing with a space credential bound to the key the
// request names, given the delegation token and client attestation the space
// requires, optionally registering an endpoint for notifications (the
// reference's getDelegationToken.ts and authorizeSpaceSync.ts at
// bluesky-social/atproto d4def6e9).

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

// assertSpaceHost checks this host is the space's authority. Space-host
// methods reach straight into the authority's repo, which would otherwise fail
// as an error none of their lexicons declare.
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

// assertActiveSpaceHost is assertSpaceHost, but also refuses an authority that
// is taken down or deactivated, as sync does for a repo. Notification routes
// keep using assertSpaceHost so the authority's writer state stays current
// while the space is suspended.
func (s *Server) assertActiveSpaceHost(ctx context.Context, ref space.Ref) error {
	authority, err := s.assertSpaceHost(ctx, ref)
	if err != nil {
		return err
	}
	if authority.Repo.TakedownRef != nil {
		return errInvalid("RepoTakendown", "Repo has been takendown: %s", ref.Authority)
	}
	if authority.Repo.Deactivated {
		return errInvalid("RepoDeactivated", "Repo has been deactivated: %s", ref.Authority)
	}
	return nil
}

type notifyInput struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

func (s *Server) handleSpaceAuthorizeSpaceSync(e echo.Context) error {
	body, err := func() (any, error) {
		ctx := e.Request().Context()
		var in struct {
			Space             string       `json:"space"`
			CredentialKey     string       `json:"credentialKey"`
			DelegationToken   string       `json:"delegationToken"`
			ClientAttestation string       `json:"clientAttestation"`
			Notify            *notifyInput `json:"notify"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if in.CredentialKey == "" {
			return nil, errInvalid("", "Input must have the property \"credentialKey\"")
		}
		notify := in.Notify
		if notify != nil {
			if u, err := url.Parse(notify.Endpoint); err != nil || notify.Endpoint == "" || u.Scheme == "" || u.Host == "" {
				return nil, errInvalid("", "Input/notify/endpoint must be a valid URI")
			}
			if notify.Token == "" || len(notify.Token) > 512 {
				return nil, errInvalid("", "Input/notify/token must be 1 to 512 characters")
			}
		}
		if !space.IsP256DIDKey(in.CredentialKey) {
			return nil, errInvalid("", "credentialKey must be a P-256 did:key")
		}
		uri := ref.String()
		if err := s.assertActiveSpaceHost(ctx, ref); err != nil {
			return nil, err
		}
		st := s.spaceStore(nil, ref.Authority)
		// The durable signal that a space is gone: a syncer that missed its
		// deletion notice learns it here, the next time it reauthorizes.
		// Answered regardless of the request's authorization, since a public
		// space's syncer may not have a delegation token.
		sp, err := st.getSpace(uri)
		if err != nil {
			return nil, err
		}
		if sp != nil && sp.DeletedAt != nil {
			return nil, errInvalid("SpaceDeleted", "Space has been deleted")
		}

		// Empty when the request carries no delegation token, which only a
		// space that does not gate on the account accepts.
		repo := ""
		if in.DelegationToken != "" {
			d, err := s.verifyDelegationToken(ctx, in.DelegationToken)
			if err != nil {
				return nil, err
			}
			if d.space != uri {
				return nil, errInvalid("InvalidDelegationToken", "Delegation token subject does not match requested space")
			}
			repo = d.userDid
		}
		clientID := ""
		if in.ClientAttestation != "" {
			if clientID, err = s.verifyClientAttestation(ctx, in.ClientAttestation, ref.HostAud()); err != nil {
				return nil, err
			}
		}
		policy, err := st.getActiveSpacePolicy(uri)
		if err != nil {
			return nil, err
		}

		if err := s.authorizeCredential(ctx, ref, policy, repo, clientID); err != nil {
			// A refused request withdraws the registration it carries, so a
			// syncer that has lost access to the space stops being notified.
			// A failure to decide, such as an unreachable managing app, is not
			// a refusal, so it leaves the registration in place.
			if xe, ok := err.(*xrpcError); ok && notify != nil && xe.Status == http.StatusBadRequest {
				if rerr := st.removeNotifyRegistration(uri, notify.Endpoint, notify.Token); rerr != nil {
					return nil, rerr
				}
			}
			return nil, err
		}

		if notify != nil {
			registered, err := st.getNotifyRegistration(uri, notify.Endpoint, notify.Token)
			if err != nil {
				return nil, err
			}
			if registered == nil {
				if err := s.confirmRegistration(ctx, uri, *notify); err != nil {
					return nil, err
				}
			}
		}

		authority, err := s.assertSpaceHost(ctx, ref)
		if err != nil {
			return nil, err
		}
		key, err := s.accountSigner(authority.Repo)
		if err != nil {
			return nil, err
		}
		cred, err := space.CreateSpaceToken(space.TokenCredential, space.CreateTokenOpts{Iss: ref.Authority, Sub: uri, KeyID: in.CredentialKey}, key)
		if err != nil {
			return nil, err
		}

		if notify != nil {
			// Renewed by each authorization, so a syncer that keeps
			// reauthorizing stays registered.
			parsed, err := space.ParseSpaceToken(space.TokenCredential, cred)
			if err != nil {
				return nil, err
			}
			expiresAt := isoTime(time.Unix(parsed.Payload.Exp, 0))
			err = s.db.Client().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				return s.spaceStore(tx, ref.Authority).putNotifyRegistration(uri, notify.Endpoint, notify.Token, expiresAt)
			})
			if err != nil {
				return nil, err
			}
		}

		// Read after registering, so any update past this revision is
		// notified.
		res := map[string]any{"credential": cred}
		spaceRev, err := st.getSpaceRev(uri)
		if err != nil {
			return nil, err
		}
		if spaceRev != "" {
			res["spaceRev"] = spaceRev
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}

// confirmRegistration checks, before registering an endpoint, that it asked
// to be registered: the endpoint must recognize the token as one it issued for
// this space, and echo back a random challenge.
func (s *Server) confirmRegistration(ctx context.Context, spaceURI string, notify notifyInput) error {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	challenge := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	// The endpoint is chosen by the requester, so it is fetched as untrusted.
	out, err := s.postXRPCJSON(ctx, strings.TrimRight(notify.Endpoint, "/"), lxmConfirmRegistration,
		map[string]any{"space": spaceURI, "token": notify.Token, "challenge": challenge})
	if err == nil {
		var res struct {
			Challenge string `json:"challenge"`
		}
		if json.Unmarshal(out, &res) == nil && res.Challenge == challenge {
			return nil
		}
		err = fmt.Errorf("challenge mismatch")
	}
	s.logger.Warn("registration not confirmed", "space", spaceURI, "endpoint", notify.Endpoint, "err", err)
	return errInvalid("RegistrationNotConfirmed", "Notify endpoint did not confirm the registration")
}

func (s *Server) handleSpaceNotifyCredentialsRevoked(e echo.Context) error {
	body, err := func() (any, error) {
		claims, err := s.verifyServiceAuth(e, "com.atproto.space.notifyCredentialsRevoked")
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
	status, _, err := s.postXRPCBody(ctx, target, lxm, body)
	return status, err
}

// postXRPCJSON posts JSON to an endpoint without service auth, returning the
// response body.
func (s *Server) postXRPCJSON(ctx context.Context, endpoint, lxm string, body any) ([]byte, error) {
	_, out, err := s.postXRPCBody(ctx, &notifyTarget{endpoint: endpoint}, lxm, body)
	return out, err
}

func (s *Server) postXRPCBody(ctx context.Context, target *notifyTarget, lxm string, body any) (int, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.endpoint+"/xrpc/"+lxm, bytesReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range target.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.spaceClient().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var xe struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(out, &xe)
		return resp.StatusCode, nil, &xrpcCallError{Status: resp.StatusCode, Name: xe.Error}
	}
	return resp.StatusCode, out, nil
}

type xrpcCallError struct {
	Status int
	Name   string
}

func (e *xrpcCallError) Error() string {
	return fmt.Sprintf("xrpc call failed: %d %s", e.Status, e.Name)
}
