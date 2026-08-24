package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ComAtprotoSpaceRegisterNotifyInput is the pinned registerNotify body.
type ComAtprotoSpaceRegisterNotifyInput struct {
	Space   string `json:"space"`
	Service string `json:"service"`
}

type ComAtprotoSpaceRegisterNotifyOutput struct {
	ExpiresAt time.Time `json:"expiresAt"`
}

// ComAtprotoSpaceUnregisterNotifyInput is the pinned unregisterNotify body.
type ComAtprotoSpaceUnregisterNotifyInput struct {
	Space   string `json:"space"`
	Service string `json:"service"`
}

// ComAtprotoSpaceNotifyWriteInput is deliberately metadata-only. Hash is the
// JSON bytes string from the pinned Lexicon; no record or blob fields are
// accepted or persisted.
type ComAtprotoSpaceNotifyWriteInput struct {
	Space string `json:"space"`
	Repo  string `json:"repo"`
	Rev   string `json:"rev"`
	Hash  string `json:"hash"`
}

type ComAtprotoSpaceNotifySpaceDeletedInput struct {
	Space string `json:"space"`
}

func requireSpaceCredentialNotification(e echo.Context, rawSpace string) (space.SpaceURI, error) {
	parsed, err := space.ParseSpaceURI(rawSpace)
	if err != nil {
		return space.SpaceURI{}, spaceInvalidRequest(e)
	}
	principal, ok := PrincipalFromContext(e).(*SpaceCredentialPrincipal)
	if !ok || principal == nil {
		return space.SpaceURI{}, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	credentialSpace, err := spaceCredentialSpace(principal)
	if err != nil {
		return space.SpaceURI{}, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	if credentialSpace.String() != parsed.String() {
		return space.SpaceURI{}, spaceJSONError(e, http.StatusForbidden, "Forbidden")
	}
	return parsed, nil
}

func (s *Server) requireSpaceServiceNotification(e echo.Context, lxm string) (*ServiceAuthPrincipal, error) {
	principal, ok := PrincipalFromContext(e).(*ServiceAuthPrincipal)
	if !ok || principal == nil {
		return nil, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	if principal.LXM != lxm {
		return nil, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	if s == nil || s.config == nil || principal.Audience != s.config.Did {
		return nil, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	if _, err := syntax.ParseDID(principal.Issuer); err != nil {
		return nil, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	return principal, nil
}

func (s *Server) handleSpaceRegisterNotify(e echo.Context) error {
	var req ComAtprotoSpaceRegisterNotifyInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.Service == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := requireSpaceCredentialNotification(e, req.Space)
	if err != nil {
		return err
	}
	service, err := parseSpaceNotificationService(req.Service)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	if s.config == nil || s.config.Did != string(spaceRef.AuthorityDID) {
		return spaceJSONError(e, http.StatusBadRequest, "SpaceNotFound")
	}
	if err := s.checkSpaceAvailable(e.Request().Context(), spaceRef.String(), string(spaceRef.AuthorityDID)); err != nil {
		return spaceJSONError(e, http.StatusBadRequest, "SpaceNotFound")
	}
	// A resolver is optional. If installed, registration can report the pinned
	// ServiceNotResolvable error without coupling normal DB writes to network
	// access. With no resolver, the service identifier is retained and the
	// worker resolves it later.
	if resolver := spaceNotificationResolver(s); resolver != nil {
		if target, resolveErr := resolver.Resolve(e.Request().Context(), service); resolveErr != nil || strings.TrimSpace(target) == "" {
			return spaceJSONError(e, http.StatusBadRequest, "ServiceNotResolvable")
		}
	}
	now := spaceNotificationClock(s)().UTC()
	expiresAt := now.Add(SpaceNotifyRegistrationTTL)
	row := &models.SpaceNotifyRegistration{Space: spaceRef.String(), Service: service, ExpiresAt: expiresAt}
	if err := s.db.Client().WithContext(e.Request().Context()).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "space"}, {Name: "service"}},
		DoUpdates: clause.Assignments(map[string]any{"expires_at": expiresAt, "updated_at": now}),
	}).Create(row).Error; err != nil {
		return spaceInternalError(e)
	}
	return e.JSON(http.StatusOK, ComAtprotoSpaceRegisterNotifyOutput{ExpiresAt: expiresAt})
}

func (s *Server) handleSpaceUnregisterNotify(e echo.Context) error {
	var req ComAtprotoSpaceUnregisterNotifyInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.Service == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := requireSpaceCredentialNotification(e, req.Space)
	if err != nil {
		return err
	}
	service, err := parseSpaceNotificationService(req.Service)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	if s.config == nil || s.config.Did != string(spaceRef.AuthorityDID) {
		return spaceJSONError(e, http.StatusBadRequest, "SpaceNotFound")
	}
	if err := s.checkSpaceAvailable(e.Request().Context(), spaceRef.String(), string(spaceRef.AuthorityDID)); err != nil {
		return spaceJSONError(e, http.StatusBadRequest, "SpaceNotFound")
	}
	// The pinned procedure is idempotent: deleting zero rows is success.
	if err := s.db.Client().WithContext(e.Request().Context()).Where("space = ? AND service = ?", spaceRef.String(), service).Delete(&models.SpaceNotifyRegistration{}).Error; err != nil {
		return spaceInternalError(e)
	}
	return e.JSON(http.StatusOK, struct{}{})
}

func (s *Server) handleSpaceNotifyWrite(e echo.Context) error {
	principal, err := s.requireSpaceServiceNotification(e, SpaceNotifyWriteLXM)
	if err != nil {
		return err
	}
	var req ComAtprotoSpaceNotifyWriteInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.Repo == "" || req.Rev == "" || req.Hash == "" {
		return spaceInvalidRequest(e)
	}
	parsed, err := space.ParseSpaceURI(req.Space)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	if req.Repo != principal.Issuer {
		return spaceJSONError(e, http.StatusForbidden, "Forbidden")
	}
	if _, err := syntax.ParseDID(req.Repo); err != nil {
		return spaceInvalidRequest(e)
	}
	if _, err := syntax.ParseTID(req.Rev); err != nil {
		return spaceInvalidRequest(e)
	}
	if principal.Audience != string(parsed.AuthorityDID) {
		return spaceJSONError(e, http.StatusForbidden, "Forbidden")
	}
	row, _, loadErr := s.simpleSpaceLoad(e.Request().Context(), parsed.String(), false)
	if errors.Is(loadErr, gorm.ErrRecordNotFound) {
		// Notifications are best-effort. The reference treats an ungoverned
		// or already-deleted local Space as a successful no-op so remote PDSes
		// do not retry a notification nobody here can maintain.
		return e.JSON(http.StatusOK, struct{}{})
	}
	if loadErr != nil {
		return spaceInternalError(e)
	}
	// notifyWrite comes from a PDS, so it has no OAuth client attestation.
	// Apply the same user policy as credential minting while intentionally
	// ignoring appAccess allow-lists.
	if !s.simpleSpacePolicyUserAllowed(e.Request().Context(), &row, req.Repo, parsed.String(), "") {
		return spaceJSONError(e, http.StatusForbidden, "Forbidden")
	}
	hash, err := ParseSpaceNotificationHash(req.Hash)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	if err := s.RecordSpaceNotifyWrite(e.Request().Context(), parsed.String(), req.Repo, req.Rev, hash, principal.Issuer); err != nil {
		return spaceInternalError(e)
	}
	return e.JSON(http.StatusOK, struct{}{})
}

func (s *Server) handleSpaceNotifySpaceDeleted(e echo.Context) error {
	principal, err := s.requireSpaceServiceNotification(e, SpaceNotifySpaceDeletedLXM)
	if err != nil {
		return err
	}
	var req ComAtprotoSpaceNotifySpaceDeletedInput
	if err := e.Bind(&req); err != nil || req.Space == "" {
		return spaceInvalidRequest(e)
	}
	parsed, err := space.ParseSpaceURI(req.Space)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	if principal.Issuer != string(parsed.AuthorityDID) {
		return spaceJSONError(e, http.StatusForbidden, "Forbidden")
	}
	if err := s.RecordSpaceNotifySpaceDeleted(e.Request().Context(), parsed.String(), principal.Issuer, false); err != nil {
		return spaceInternalError(e)
	}
	return e.JSON(http.StatusOK, struct{}{})
}

// Common short handler spellings retained for lifecycle owners and focused
// tests. Native notification routes are registered exclusively by addSpaceRoutes
// so every endpoint remains covered by the central authentication policy table.
func (s *Server) handleSpaceRegisterNotification(e echo.Context) error {
	return s.handleSpaceRegisterNotify(e)
}
func (s *Server) handleSpaceUnregisterNotification(e echo.Context) error {
	return s.handleSpaceUnregisterNotify(e)
}
func (s *Server) handleSpaceNotifySpaceDeletedNotification(e echo.Context) error {
	return s.handleSpaceNotifySpaceDeleted(e)
}
