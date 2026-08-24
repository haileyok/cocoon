package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gorm.io/gorm"
)

func credentialExchangeError(e echo.Context, name string) error {
	return simpleSpaceError(e, http.StatusBadRequest, name)
}

func (s *Server) handleSimpleSpaceGetSpaceCredential(e echo.Context) error {
	var req ComAtprotoSpaceGetSpaceCredentialInput
	if err := e.Bind(&req); err != nil || req.Space == "" {
		return simpleSpaceInput(e)
	}
	ref, err := space.ParseSpaceURI(req.Space)
	if err != nil {
		return simpleSpaceInput(e)
	}
	principal, ok := PrincipalFromContext(e).(*DelegationPrincipal)
	if !ok || principal == nil {
		return simpleSpaceUnauthorized(e)
	}
	if err := validateDelegationForSimpleSpace(principal, ref); err != nil {
		return credentialExchangeError(e, "InvalidDelegationToken")
	}
	ctx := e.Request().Context()
	if status, statusErr := s.localRepoStatus(ctx, principal.Claims.Iss); statusErr != nil {
		return simpleSpaceInternal(e)
	} else if status != "" {
		return credentialExchangeError(e, repoStatusErrorName(status))
	}
	var row models.SimpleSpace
	if err := s.db.Client().WithContext(ctx).Where("uri = ?", ref.String()).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			var tombstone models.SpaceTombstone
			if tombErr := s.db.First(ctx, &tombstone, "space = ?", ref.String()).Error; tombErr == nil {
				return credentialExchangeError(e, "SpaceDeleted")
			}
			return credentialExchangeError(e, "SpaceNotFound")
		}
		return simpleSpaceInternal(e)
	}
	if row.Deleted || row.DeletedAt != nil {
		return credentialExchangeError(e, "SpaceDeleted")
	}
	if err := s.checkSpaceAvailable(ctx, ref.String(), string(ref.AuthorityDID)); err != nil {
		return credentialExchangeError(e, "SpaceNotFound")
	}

	clientResult, err := s.simpleSpaceCredentialClient(ctx, ref, req.ClientAttestation, row.AppAccess)
	if err != nil {
		return credentialExchangeError(e, "InvalidClientAttestation")
	}
	clientID := clientResult.ClientID
	// Match the reference perimeter order: an app allow-list is checked before
	// user policy, and the authority is always admitted by the user policy.
	if !simpleSpaceCredentialAppAllowed(&row, clientID) {
		return credentialExchangeError(e, "AppNotAuthorized")
	}
	if !s.simpleSpaceCredentialUserAllowed(ctx, &row, principal.Claims.Iss, clientID, ref.String()) {
		return credentialExchangeError(e, "UserNotAuthorized")
	}

	signer, err := s.simpleSpaceAuthoritySigner(ctx, ref)
	if err != nil {
		return simpleSpaceInternal(e)
	}
	credential, err := space.CreateSpaceCredential(space.CreateSpaceTokenOptions{
		Iss:     string(ref.AuthorityDID),
		Sub:     ref.String(),
		DPoPJKT: principal.DPoPJKT,
		Kid:     space.FallbackSigningKeyID,
	}, signer)
	if err != nil {
		return simpleSpaceInternal(e)
	}
	if err := s.consumeSimpleSpaceExchange(ctx, principal, clientResult.Attestation); err != nil {
		if errors.Is(err, space.ErrReplay) {
			return credentialExchangeError(e, "ReplayDetected")
		}
		return simpleSpaceInternal(e)
	}
	return e.JSON(http.StatusOK, ComAtprotoSpaceGetSpaceCredentialOutput{Credential: credential})
}

func (s *Server) consumeSimpleSpaceExchange(ctx context.Context, principal *DelegationPrincipal, attestation *space.SpaceToken) error {
	if principal == nil || principal.Claims.JTI == "" || principal.DPoPJTI == "" || principal.DPoPIssuedAt.IsZero() {
		return space.ErrBatchReplayUnavailable
	}
	replay := s.spaceReplayStore()
	batchStore, ok := replay.(space.BatchReplayStore)
	if !ok {
		return space.ErrBatchReplayUnavailable
	}
	artifacts := []space.ReplayArtifact{
		{JTI: principal.Claims.JTI, TokenType: string(space.TokenDelegation), ExpiresAt: time.Unix(principal.Claims.Exp, 0).Add(space.ClockSkew)},
		{JTI: principal.DPoPJTI, TokenType: "dpop", ExpiresAt: principal.DPoPIssuedAt.Add(space.MaxDpopProofAge).Add(space.ClockSkew)},
	}
	if attestation != nil {
		if attestation.Claims.JTI == "" {
			return space.ErrBatchReplayUnavailable
		}
		artifacts = append(artifacts, space.ReplayArtifact{
			JTI: attestation.Claims.JTI, TokenType: string(space.TokenClientAttestation),
			ExpiresAt: time.Unix(attestation.Claims.Exp, 0).Add(space.ClockSkew),
		})
	}
	return batchStore.ConsumeBatch(ctx, artifacts)
}

func validateDelegationForSimpleSpace(p *DelegationPrincipal, ref space.SpaceURI) error {
	if p == nil || p.Claims.Iss == "" || p.DPoPJKT == "" {
		return errors.New("delegation principal is incomplete")
	}
	if issuer, err := syntax.ParseDID(p.Claims.Iss); err != nil || string(issuer) != p.Claims.Iss {
		return errors.New("delegation issuer is not canonical")
	}
	requested := ref.String()
	if p.SpaceURI != requested || p.Claims.Sub != requested {
		return errors.New("delegation subject does not match requested space")
	}
	if p.AuthorityDID != string(ref.AuthorityDID) {
		return errors.New("delegation authority does not match requested space")
	}
	if p.Claims.Aud == nil || *p.Claims.Aud != string(ref.AuthorityDID)+space.SpaceHostAudienceSuffix {
		return errors.New("delegation audience does not match authority")
	}
	return nil
}

type simpleSpaceCredentialClientResult struct {
	ClientID    string
	Attestation *space.SpaceToken
}

func (s *Server) simpleSpaceCredentialClientID(ctx context.Context, ref space.SpaceURI, raw, appAccess string) (string, error) {
	result, err := s.simpleSpaceCredentialClient(ctx, ref, raw, appAccess)
	return result.ClientID, err
}

func (s *Server) simpleSpaceCredentialClient(ctx context.Context, ref space.SpaceURI, raw, appAccess string) (simpleSpaceCredentialClientResult, error) {
	if raw == "" {
		if appAccess == simpleSpaceAppAccessAllowList {
			return simpleSpaceCredentialClientResult{}, errors.New("allow-list requires client attestation")
		}
		return simpleSpaceCredentialClientResult{}, nil
	}
	if s.oauthProvider == nil || s.oauthProvider.ClientManager == nil {
		return simpleSpaceCredentialClientResult{}, errors.New("OAuth client metadata resolver is unavailable")
	}
	resolver := SpaceAuthorityKeyResolverFunc(func(resolveCtx context.Context, request space.KeyResolutionRequest) (space.Verifier, error) {
		if request.Algorithm != "ES256" {
			return nil, fmt.Errorf("client attestation algorithm must be ES256")
		}
		keys, err := s.oauthProvider.ClientManager.GetClientJWKSWithRefresh(resolveCtx, request.Issuer, request.ForceRefresh)
		if err != nil {
			return nil, err
		}
		var key jwk.Key
		if request.Kid != "" {
			published, ok := keys.LookupKeyID(request.Kid)
			if !ok {
				return nil, fmt.Errorf("client JWKS has no key %q", request.Kid)
			}
			key = published
		} else {
			if keys.Len() != 1 {
				return nil, errors.New("client attestation without kid requires exactly one published key")
			}
			published, ok := keys.Key(0)
			if !ok {
				return nil, errors.New("client JWKS key is unavailable")
			}
			key = published
		}
		var publicKey ecdsa.PublicKey
		if err := key.Raw(&publicKey); err != nil {
			return nil, fmt.Errorf("extract client attestation key: %w", err)
		}
		return space.NewECDSAVerifier(&publicKey, "ES256")
	})
	verified, err := space.VerifyClientAttestation(ctx, raw, space.VerifySpaceTokenOptions{
		SigningKeyResolver: resolver,
		Audience:           string(ref.AuthorityDID) + space.SpaceHostAudienceSuffix,
		Context:            ctx,
	})
	if err != nil || verified.Claims.Sub == "" || verified.Claims.Iss != verified.Claims.Sub {
		return simpleSpaceCredentialClientResult{}, errors.New("invalid client attestation")
	}
	return simpleSpaceCredentialClientResult{ClientID: verified.Claims.Sub, Attestation: &verified}, nil
}

func (s *Server) simpleSpaceCredentialUserAllowed(ctx context.Context, row *models.SimpleSpace, userDID, clientID, uri string) bool {
	return s.simpleSpacePolicyUserAllowed(ctx, row, userDID, uri, clientID)
}

func simpleSpaceCredentialAppAllowed(row *models.SimpleSpace, clientID string) bool {
	if row == nil {
		return false
	}
	switch row.AppAccess {
	case simpleSpaceAppAccessOpen:
		return true
	case simpleSpaceAppAccessAllowList:
		var allowed []string
		if jsonErr := unmarshalSimpleSpaceAllowed(row.AllowedClientIDs, &allowed); jsonErr != nil {
			return false
		}
		return clientID != "" && containsString(allowed, clientID)
	default:
		return false
	}
}

func unmarshalSimpleSpaceAllowed(raw []byte, dst *[]string) error {
	if len(raw) == 0 {
		return errors.New("missing allow-list")
	}
	return json.Unmarshal(raw, dst)
}

// simpleSpaceAuthoritySigner follows the pinned local-authority behavior: a
// local account's repository signing key is the authority's #atproto key. The
// server ES256 key fallback keeps white-box/minimal hosts usable when their
// authority repo has not been provisioned yet.
func (s *Server) simpleSpaceAuthoritySigner(ctx context.Context, ref space.SpaceURI) (space.Signer, error) {
	var repo models.Repo
	err := s.db.First(ctx, &repo, "did = ?", string(ref.AuthorityDID)).Error
	if err == nil {
		key, parseErr := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
		if parseErr != nil {
			return nil, parseErr
		}
		return space.NewAtprotoSigner(key)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if s.privateKey == nil {
		return nil, errors.New("local authority signing key is unavailable")
	}
	return space.NewECDSASigner(s.privateKey, "ES256", nil)
}

// Compatibility aliases for route integration.
func (s *Server) handleSpaceGetSpaceCredential(e echo.Context) error {
	return s.handleSimpleSpaceGetSpaceCredential(e)
}
func (s *Server) handleGetSpaceCredential(e echo.Context) error {
	return s.handleSimpleSpaceGetSpaceCredential(e)
}
func (s *Server) getSpaceCredential(e echo.Context) error {
	return s.handleSimpleSpaceGetSpaceCredential(e)
}
