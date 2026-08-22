package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// Pinned SimpleSpace policy discriminants. The wire form is the fully-qualified
// lexicon ref in $type; storage keeps the short, stable discriminant.
const (
	simpleSpacePolicyPublic       = "public"
	simpleSpacePolicyMemberList   = "member-list"
	simpleSpacePolicyManagingApp  = "managing-app"
	simpleSpaceAppAccessOpen      = "open"
	simpleSpaceAppAccessAllowList = "allow-list"

	simpleSpacePublicRef      = "com.atproto.simplespace.defs#publicPolicy"
	simpleSpaceMemberListRef  = "com.atproto.simplespace.defs#memberListPolicy"
	simpleSpaceManagingAppRef = "com.atproto.simplespace.defs#managingAppPolicy"
	simpleSpaceOpenRef        = "com.atproto.simplespace.defs#open"
	simpleSpaceAllowListRef   = "com.atproto.simplespace.defs#allowList"
)

// SimpleSpaceManagingAppAuthorizer is the narrow host integration used for the
// pinned managing-app policy. The implementation must perform the outbound
// checkUserAccess request as the authority; this package deliberately has no
// inbound checkUserAccess route.
type SimpleSpaceManagingAppAuthorizer interface {
	CheckUserAccess(context.Context, string, string, string, string) (bool, error)
}

// SimpleSpaceManagingAppAuthorizerFunc adapts a function to the interface.
type SimpleSpaceManagingAppAuthorizerFunc func(context.Context, string, string, string, string) (bool, error)

func (f SimpleSpaceManagingAppAuthorizerFunc) CheckUserAccess(ctx context.Context, app, spaceURI, userDID, clientID string) (bool, error) {
	if f == nil {
		return false, errors.New("nil managing-app authorizer")
	}
	return f(ctx, app, spaceURI, userDID, clientID)
}

// The Server type is parent-owned and cannot grow a field in this slice. Keep
// the injectable collaborator keyed by server identity; the map is process
// local and does not affect persistence or request authorization semantics.
var simpleSpaceAuthorizers sync.Map // map[*Server]SimpleSpaceManagingAppAuthorizer

// SetSimpleSpaceManagingAppAuthorizer installs the managing-app checker. A nil
// checker intentionally leaves the policy fail-closed.
func (s *Server) SetSimpleSpaceManagingAppAuthorizer(a SimpleSpaceManagingAppAuthorizer) {
	if s == nil {
		return
	}
	if a == nil {
		simpleSpaceAuthorizers.Delete(s)
		return
	}
	simpleSpaceAuthorizers.Store(s, a)
}

// SetManagingAppAuthorizer is a concise compatibility spelling for integration.
func (s *Server) SetManagingAppAuthorizer(a SimpleSpaceManagingAppAuthorizer) {
	s.SetSimpleSpaceManagingAppAuthorizer(a)
}

const simpleSpaceManagingAppTimeout = 5 * time.Second

type ComAtprotoSimpleSpaceCreateSpaceInput struct {
	Type      string          `json:"type"`
	SKey      *string         `json:"skey,omitempty"`
	Policy    json.RawMessage `json:"policy"`
	AppAccess json.RawMessage `json:"appAccess"`
}

type ComAtprotoSimpleSpaceUpdateSpaceInput struct {
	Space     string          `json:"space"`
	Policy    json.RawMessage `json:"policy,omitempty"`
	AppAccess json.RawMessage `json:"appAccess,omitempty"`
}

type ComAtprotoSimpleSpaceDeleteSpaceInput struct {
	Space string `json:"space"`
}

type ComAtprotoSimpleSpaceMemberInput struct {
	Space string `json:"space"`
	DID   string `json:"did"`
}

type ComAtprotoSimpleSpaceGetSpaceOutput struct {
	URI       string          `json:"uri"`
	Policy    json.RawMessage `json:"policy"`
	AppAccess json.RawMessage `json:"appAccess"`
}

type ComAtprotoSimpleSpaceCreateSpaceOutput struct {
	URI string `json:"uri"`
}

type ComAtprotoSimpleSpaceMember struct {
	DID string `json:"did"`
}

type ComAtprotoSimpleSpaceListMembersOutput struct {
	Cursor  *string                       `json:"cursor,omitempty"`
	Members []ComAtprotoSimpleSpaceMember `json:"members"`
}

type ComAtprotoSpaceGetSpaceCredentialInput struct {
	Space             string `json:"space"`
	ClientAttestation string `json:"clientAttestation,omitempty"`
}

type ComAtprotoSpaceGetSpaceCredentialOutput struct {
	Credential string `json:"credential"`
}

type simpleSpacePolicy struct {
	Kind        string
	ManagingApp string
	Wire        json.RawMessage
}

type simpleSpaceAppAccess struct {
	Kind    string
	Allowed []string
	Wire    json.RawMessage
}

func simpleSpaceError(e echo.Context, status int, name string) error {
	return e.JSON(status, map[string]string{"error": name})
}
func simpleSpaceUnauthorized(e echo.Context) error {
	return simpleSpaceError(e, http.StatusUnauthorized, "Unauthorized")
}
func simpleSpaceNotFound(e echo.Context) error {
	return simpleSpaceError(e, http.StatusBadRequest, "SpaceNotFound")
}
func simpleSpaceInternal(e echo.Context) error {
	return simpleSpaceError(e, http.StatusInternalServerError, "InternalServerError")
}
func simpleSpaceInput(e echo.Context) error {
	return simpleSpaceError(e, http.StatusBadRequest, "InvalidRequest")
}
func simpleSpaceOwnerError(e echo.Context) error {
	return simpleSpaceError(e, http.StatusBadRequest, "NotSpaceOwner")
}
func simpleSpaceUnsupportedPolicy(e echo.Context) error {
	return simpleSpaceError(e, http.StatusBadRequest, "UnsupportedPolicy")
}
func simpleSpaceUnsupportedApp(e echo.Context) error {
	return simpleSpaceError(e, http.StatusBadRequest, "UnsupportedAppAccess")
}

func simpleSpaceParseRef(raw string) (space.SpaceURI, error) { return space.ParseSpaceURI(raw) }

func simpleSpaceOAuth(e echo.Context) (*OAuthPrincipal, error) {
	p, ok := PrincipalFromContext(e).(*OAuthPrincipal)
	if !ok || p == nil || p.Subject == "" {
		return nil, errors.New("OAuth principal is required")
	}
	if did, err := syntax.ParseDID(p.Subject); err != nil || string(did) != p.Subject {
		return nil, errors.New("OAuth subject is not canonical")
	}
	return p, nil
}

func simpleSpaceManageAllowed(p *OAuthPrincipal, ref space.SpaceURI, action string) bool {
	if p == nil {
		return false
	}
	for _, raw := range p.Scopes {
		grant, err := scopes.Parse(raw)
		if err == nil && grant.AllowsSpaceManage(ref, action, p.Subject) {
			return true
		}
	}
	return false
}

func simpleSpaceReadAllowed(p *OAuthPrincipal, ref space.SpaceURI) bool {
	if p == nil {
		return false
	}
	for _, raw := range p.Scopes {
		grant, err := scopes.Parse(raw)
		if err == nil && grant.AllowsSpaceRead(ref, "", p.Subject) {
			return true
		}
	}
	return false
}

func simpleSpaceRequireManagement(e echo.Context, ref space.SpaceURI, action string) (*OAuthPrincipal, error) {
	p, err := simpleSpaceOAuth(e)
	if err != nil {
		return nil, simpleSpaceUnauthorized(e)
	}
	if !simpleSpaceManageAllowed(p, ref, action) {
		return nil, helpers.InsufficientScopeError(e, "space:"+string(ref.SpaceType)+"?authority=self&manage="+action)
	}
	return p, nil
}

func simpleSpaceRequireOwner(e echo.Context, p *OAuthPrincipal, row *models.SimpleSpace) error {
	if p == nil || row == nil || p.Subject != row.OwnerDID {
		return simpleSpaceOwnerError(e)
	}
	return nil
}

func parseSimpleSpacePolicy(raw json.RawMessage) (simpleSpacePolicy, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return simpleSpacePolicy{}, errors.New("policy is required")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return simpleSpacePolicy{}, errors.New("policy must be an object")
	}
	var typ string
	if err := json.Unmarshal(fields["$type"], &typ); err != nil {
		return simpleSpacePolicy{}, errors.New("policy $type is required")
	}
	out := simpleSpacePolicy{Wire: append(json.RawMessage(nil), raw...)}
	switch typ {
	case simpleSpacePublicRef:
		out.Kind = simpleSpacePolicyPublic
	case simpleSpaceMemberListRef:
		out.Kind = simpleSpacePolicyMemberList
	case simpleSpaceManagingAppRef:
		var app string
		if err := json.Unmarshal(fields["managingApp"], &app); err != nil || validateManagingApp(app) != nil {
			return simpleSpacePolicy{}, errors.New("managingApp is required and must be a DID service")
		}
		out.Kind, out.ManagingApp = simpleSpacePolicyManagingApp, app
	default:
		return simpleSpacePolicy{}, fmt.Errorf("unsupported policy union %q", typ)
	}
	return out, nil
}

func parseSimpleSpaceAppAccess(raw json.RawMessage) (simpleSpaceAppAccess, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return simpleSpaceAppAccess{}, errors.New("appAccess is required")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return simpleSpaceAppAccess{}, errors.New("appAccess must be an object")
	}
	var typ string
	if err := json.Unmarshal(fields["$type"], &typ); err != nil {
		return simpleSpaceAppAccess{}, errors.New("appAccess $type is required")
	}
	out := simpleSpaceAppAccess{Wire: append(json.RawMessage(nil), raw...)}
	switch typ {
	case simpleSpaceOpenRef:
		out.Kind = simpleSpaceAppAccessOpen
	case simpleSpaceAllowListRef:
		var allowed []string
		if err := json.Unmarshal(fields["allowed"], &allowed); err != nil {
			return simpleSpaceAppAccess{}, errors.New("allowed is required")
		}
		for _, clientID := range allowed {
			if clientID == "" || strings.ContainsAny(clientID, "\r\n") {
				return simpleSpaceAppAccess{}, errors.New("allowed contains an invalid client id")
			}
		}
		out.Kind, out.Allowed = simpleSpaceAppAccessAllowList, append([]string(nil), allowed...)
	default:
		return simpleSpaceAppAccess{}, fmt.Errorf("unsupported appAccess union %q", typ)
	}
	return out, nil
}

func validateManagingApp(raw string) error {
	if raw == "" || strings.Count(raw, "#") > 1 || strings.ContainsAny(raw, "\r\n") {
		return errors.New("invalid managing app")
	}
	base := raw
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		base = raw[:i]
		if i == len(raw)-1 || strings.ContainsAny(raw[i+1:], "/?#") {
			return errors.New("invalid managing app service fragment")
		}
	}
	_, err := syntax.ParseDID(base)
	return err
}

func simpleSpacePolicyWire(row models.SimpleSpace) json.RawMessage {
	if row.Policy == simpleSpacePolicyManagingApp && row.ManagingApp != nil {
		b, _ := json.Marshal(map[string]any{"$type": simpleSpaceManagingAppRef, "managingApp": *row.ManagingApp})
		return b
	}
	kind := simpleSpacePublicRef
	if row.Policy == simpleSpacePolicyMemberList {
		kind = simpleSpaceMemberListRef
	}
	b, _ := json.Marshal(map[string]string{"$type": kind})
	return b
}

func simpleSpaceAppWire(row models.SimpleSpace) json.RawMessage {
	if row.AppAccess == simpleSpaceAppAccessAllowList {
		var allowed []string
		_ = json.Unmarshal(row.AllowedClientIDs, &allowed)
		b, _ := json.Marshal(map[string]any{"$type": simpleSpaceAllowListRef, "allowed": allowed})
		return b
	}
	b, _ := json.Marshal(map[string]string{"$type": simpleSpaceOpenRef})
	return b
}

func (s *Server) simpleSpaceLoad(ctx context.Context, raw string, includeDeleted bool) (models.SimpleSpace, space.SpaceURI, error) {
	ref, err := simpleSpaceParseRef(raw)
	if err != nil {
		return models.SimpleSpace{}, space.SpaceURI{}, err
	}
	var row models.SimpleSpace
	q := s.db.Client().WithContext(ctx).Where("uri = ?", ref.String())
	if !includeDeleted {
		q = q.Where("deleted = ?", false).Where("deleted_at IS NULL")
	}
	if err := q.First(&row).Error; err != nil {
		return models.SimpleSpace{}, ref, err
	}
	return row, ref, nil
}

func (s *Server) handleSimpleSpaceCreateSpace(e echo.Context) error {
	p, err := simpleSpaceOAuth(e)
	if err != nil {
		return simpleSpaceUnauthorized(e)
	}
	var req ComAtprotoSimpleSpaceCreateSpaceInput
	if err := e.Bind(&req); err != nil || req.Type == "" || len(req.Policy) == 0 || len(req.AppAccess) == 0 {
		return simpleSpaceInput(e)
	}
	spaceType, err := syntax.ParseNSID(req.Type)
	if err != nil || string(spaceType) != req.Type {
		return simpleSpaceInput(e)
	}
	skey := ""
	if req.SKey != nil {
		skey = *req.SKey
	}
	if skey == "" {
		skey = simpleSpaceClock.Next().String()
	}
	key, err := syntax.ParseRecordKey(skey)
	if err != nil || string(key) != skey {
		return simpleSpaceInput(e)
	}
	policy, err := parseSimpleSpacePolicy(req.Policy)
	if err != nil {
		return simpleSpaceUnsupportedPolicy(e)
	}
	appAccess, err := parseSimpleSpaceAppAccess(req.AppAccess)
	if err != nil {
		return simpleSpaceUnsupportedApp(e)
	}
	ref, err := space.NewSpaceURI(p.Subject, req.Type, skey)
	if err != nil {
		return simpleSpaceInput(e)
	}
	if !simpleSpaceManageAllowed(p, ref, "create") {
		return helpers.InsufficientScopeError(e, "space:"+req.Type+"?authority=self&manage=create")
	}
	row := models.SimpleSpace{URI: ref.String(), OwnerDID: p.Subject, Type: req.Type, SKey: skey, Policy: policy.Kind, AppAccess: appAccess.Kind}
	if policy.ManagingApp != "" {
		row.ManagingApp = &policy.ManagingApp
	}
	row.AllowedClientIDs, _ = json.Marshal(appAccess.Allowed)
	ctx := e.Request().Context()
	if err := s.db.Transaction(ctx, func(tx *db.DB) error { return s.createSimpleSpaceRow(tx, ctx, &row) }); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return simpleSpaceError(e, http.StatusBadRequest, "SpaceAlreadyExists")
		}
		return simpleSpaceInternal(e)
	}
	return e.JSON(http.StatusOK, ComAtprotoSimpleSpaceCreateSpaceOutput{URI: row.URI})
}

func (s *Server) createSimpleSpaceRow(tx *db.DB, ctx context.Context, row *models.SimpleSpace) error {
	var old models.SimpleSpace
	err := tx.Client().WithContext(ctx).Where("uri = ?", row.URI).First(&old).Error
	if err == nil {
		// Space URIs are not reusable. A deleted row and its tombstone are durable
		// revocation state; resurrecting the URI could make old credentials or
		// retained remote data ambiguous.
		return gorm.ErrDuplicatedKey
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return tx.Create(ctx, row, nil).Error
}

func (s *Server) handleSimpleSpaceUpdateSpace(e echo.Context) error {
	var req ComAtprotoSimpleSpaceUpdateSpaceInput
	if err := e.Bind(&req); err != nil || req.Space == "" {
		return simpleSpaceInput(e)
	}
	ref, err := simpleSpaceParseRef(req.Space)
	if err != nil {
		return simpleSpaceInput(e)
	}
	p, err := simpleSpaceRequireManagement(e, ref, "update")
	if err != nil {
		return err
	}
	ctx := e.Request().Context()
	row, _, err := s.simpleSpaceLoad(ctx, ref.String(), false)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return simpleSpaceNotFound(e)
	}
	if err != nil {
		return simpleSpaceInternal(e)
	}
	if err := simpleSpaceRequireOwner(e, p, &row); err != nil {
		return err
	}
	if len(req.Policy) > 0 {
		policy, parseErr := parseSimpleSpacePolicy(req.Policy)
		if parseErr != nil {
			return simpleSpaceUnsupportedPolicy(e)
		}
		row.Policy, row.ManagingApp = policy.Kind, nil
		if policy.ManagingApp != "" {
			row.ManagingApp = &policy.ManagingApp
		}
	}
	if len(req.AppAccess) > 0 {
		appAccess, parseErr := parseSimpleSpaceAppAccess(req.AppAccess)
		if parseErr != nil {
			return simpleSpaceUnsupportedApp(e)
		}
		row.AppAccess = appAccess.Kind
		row.AllowedClientIDs, _ = json.Marshal(appAccess.Allowed)
	}
	if err := s.db.Save(ctx, &row, nil).Error; err != nil {
		return simpleSpaceInternal(e)
	}
	return nil
}

func (s *Server) handleSimpleSpaceDeleteSpace(e echo.Context) error {
	var req ComAtprotoSimpleSpaceDeleteSpaceInput
	if err := e.Bind(&req); err != nil || req.Space == "" {
		return simpleSpaceInput(e)
	}
	ref, err := simpleSpaceParseRef(req.Space)
	if err != nil {
		return simpleSpaceInput(e)
	}
	p, err := simpleSpaceRequireManagement(e, ref, "delete")
	if err != nil {
		return err
	}
	ctx := e.Request().Context()
	var row models.SimpleSpace
	err = s.db.Client().WithContext(ctx).Where("uri = ?", ref.String()).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var tomb models.SpaceTombstone
		if tombErr := s.db.First(ctx, &tomb, "space = ?", ref.String()).Error; tombErr == nil {
			if tomb.OwnerDID != "" && tomb.OwnerDID != p.Subject {
				return simpleSpaceOwnerError(e)
			}
			return e.NoContent(http.StatusOK)
		}
		return simpleSpaceNotFound(e)
	}
	if err != nil {
		return simpleSpaceInternal(e)
	}
	if err := simpleSpaceRequireOwner(e, p, &row); err != nil {
		return err
	}
	if row.Deleted || row.DeletedAt != nil {
		return e.NoContent(http.StatusOK)
	}
	deletedAt := time.Now().UTC()
	if err := s.db.Transaction(ctx, func(tx *db.DB) error {
		if err := tx.Client().WithContext(ctx).Model(&models.SimpleSpace{}).Where("uri = ?", ref.String()).Updates(map[string]any{"deleted": true, "deleted_at": deletedAt, "updated_at": deletedAt}).Error; err != nil {
			return err
		}
		tomb := models.SpaceTombstone{Space: ref.String(), OwnerDID: row.OwnerDID, SourceDID: p.Subject, DeletedAt: deletedAt}
		if err := tx.Create(ctx, &tomb, nil).Error; err != nil && !errors.Is(err, gorm.ErrDuplicatedKey) && !strings.Contains(strings.ToLower(err.Error()), "unique") {
			return err
		}
		return markSimpleSpaceDeleted(tx, ctx, ref.String(), string(ref.AuthorityDID), deletedAt)
	}); err != nil {
		return simpleSpaceInternal(e)
	}
	return e.NoContent(http.StatusOK)
}

func markSimpleSpaceDeleted(tx *db.DB, ctx context.Context, uri, authority string, deletedAt time.Time) error {
	for _, model := range []any{&models.SpaceRecord{}, &models.SpaceBlobRef{}, &models.SpaceRepoOp{}, &models.SpaceRepo{}, &models.SpaceWriter{}} {
		if err := tx.Client().WithContext(ctx).Where("space = ? AND author = ?", uri, authority).Delete(model).Error; err != nil {
			return err
		}
	}
	// Repositories hosted for other authors and the authority's writer-set view
	// are retained unchanged. The durable SpaceTombstone—not per-repo deletion
	// flags—revokes credential-backed access while preserving OAuth read_self
	// cleanup and migration recovery.
	if err := tx.Client().WithContext(ctx).Model(&models.SimpleSpaceMember{}).Where("space = ?", uri).Updates(map[string]any{"removed_at": deletedAt}).Error; err != nil {
		return err
	}
	var registrations []models.SpaceNotifyRegistration
	if err := tx.Client().WithContext(ctx).Where("space = ?", uri).Find(&registrations).Error; err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"space": uri})
	for _, registration := range registrations {
		key := notificationIdempotencyKey(SpaceNotifySpaceDeletedLXM, uri, registration.Service)
		var existing models.SpaceNotifyDelivery
		err := tx.Client().WithContext(ctx).Where("idempotency_key = ?", key).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			delivery := models.SpaceNotifyDelivery{IdempotencyKey: key, Kind: SpaceNotifySpaceDeletedLXM, Space: uri, Service: registration.Service, Deleted: true, Payload: payload, Status: "pending", ExpiresAt: deletedAt.Add(SpaceNotifyDeliveryTTL)}
			if err := tx.Create(ctx, &delivery, nil).Error; err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleSimpleSpaceGetSpace(e echo.Context) error {
	raw := e.QueryParam("space")
	if raw == "" {
		return simpleSpaceInput(e)
	}
	ref, err := simpleSpaceParseRef(raw)
	if err != nil {
		return simpleSpaceInput(e)
	}
	ctx := e.Request().Context()
	row, _, err := s.simpleSpaceLoad(ctx, ref.String(), false)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return simpleSpaceNotFound(e)
	}
	if err != nil {
		return simpleSpaceInternal(e)
	}
	switch p := PrincipalFromContext(e).(type) {
	case *SpaceCredentialPrincipal:
		credentialSpace, parseErr := spaceCredentialSpace(p)
		if parseErr != nil {
			return simpleSpaceUnauthorized(e)
		}
		if credentialSpace.String() != ref.String() || (p.AuthorityDID != "" && p.AuthorityDID != string(ref.AuthorityDID)) {
			return simpleSpaceError(e, http.StatusForbidden, "Forbidden")
		}
	case *OAuthPrincipal:
		if p == nil || p.Subject == "" || !s.simpleSpaceUserAllowed(ctx, &row, p.Subject, p.ClientID, ref.String()) {
			return simpleSpaceError(e, http.StatusForbidden, "NotAuthorized")
		}
	default:
		return simpleSpaceUnauthorized(e)
	}
	return e.JSON(http.StatusOK, ComAtprotoSimpleSpaceGetSpaceOutput{URI: row.URI, Policy: simpleSpacePolicyWire(row), AppAccess: simpleSpaceAppWire(row)})
}

func (s *Server) simpleSpaceUserAllowed(ctx context.Context, row *models.SimpleSpace, userDID, clientID, uri string) bool {
	if row == nil || userDID == "" {
		return false
	}
	switch row.Policy {
	case simpleSpacePolicyPublic:
	case simpleSpacePolicyMemberList:
		var member models.SimpleSpaceMember
		if err := s.db.Client().WithContext(ctx).Where("space = ? AND did = ? AND removed_at IS NULL", uri, userDID).First(&member).Error; err != nil {
			return false
		}
	case simpleSpacePolicyManagingApp:
		if row.ManagingApp == nil || !s.checkManagingApp(ctx, *row.ManagingApp, uri, userDID, clientID) {
			return false
		}
	default:
		return false
	}
	if row.AppAccess == simpleSpaceAppAccessAllowList {
		var allowed []string
		if json.Unmarshal(row.AllowedClientIDs, &allowed) != nil || !containsString(allowed, clientID) {
			return false
		}
	} else if row.AppAccess != simpleSpaceAppAccessOpen {
		return false
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (s *Server) checkManagingApp(ctx context.Context, app, uri, user, clientID string) bool {
	value, ok := simpleSpaceAuthorizers.Load(s)
	if !ok {
		return false
	}
	authorizer, ok := value.(SimpleSpaceManagingAppAuthorizer)
	if !ok || authorizer == nil {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, simpleSpaceManagingAppTimeout)
	defer cancel()
	authorized, err := authorizer.CheckUserAccess(checkCtx, app, uri, user, clientID)
	return err == nil && authorized && checkCtx.Err() == nil
}

func (s *Server) handleSimpleSpaceAddMember(e echo.Context) error {
	return s.handleSimpleSpaceMemberMutation(e, true)
}
func (s *Server) handleSimpleSpaceRemoveMember(e echo.Context) error {
	return s.handleSimpleSpaceMemberMutation(e, false)
}
func (s *Server) handleSimpleSpaceMemberMutation(e echo.Context, add bool) error {
	var req ComAtprotoSimpleSpaceMemberInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.DID == "" {
		return simpleSpaceInput(e)
	}
	ref, err := simpleSpaceParseRef(req.Space)
	if err != nil {
		return simpleSpaceInput(e)
	}
	did, err := syntax.ParseDID(req.DID)
	if err != nil || string(did) != req.DID {
		return simpleSpaceInput(e)
	}
	p, err := simpleSpaceRequireManagement(e, ref, "update")
	if err != nil {
		return err
	}
	ctx := e.Request().Context()
	row, _, err := s.simpleSpaceLoad(ctx, ref.String(), false)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return simpleSpaceNotFound(e)
	}
	if err != nil {
		return simpleSpaceInternal(e)
	}
	if err := simpleSpaceRequireOwner(e, p, &row); err != nil {
		return err
	}
	var member models.SimpleSpaceMember
	err = s.db.Client().WithContext(ctx).Where("space = ? AND did = ?", ref.String(), req.DID).First(&member).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		member = models.SimpleSpaceMember{Space: ref.String(), DID: req.DID}
		err = nil
	}
	if err != nil {
		return simpleSpaceInternal(e)
	}
	now := time.Now().UTC()
	if add {
		member.RemovedAt = nil
		isNew := member.CreatedAt.IsZero()
		if isNew {
			member.CreatedAt = now
		}
		member.UpdatedAt = now
		var writeErr error
		if isNew {
			writeErr = s.db.Create(ctx, &member, nil).Error
		} else {
			writeErr = s.db.Save(ctx, &member, nil).Error
		}
		if writeErr != nil {
			return simpleSpaceInternal(e)
		}
	} else if !member.CreatedAt.IsZero() {
		member.RemovedAt = &now
		member.UpdatedAt = now
		if err := s.db.Save(ctx, &member, nil).Error; err != nil {
			return simpleSpaceInternal(e)
		}
	}
	return e.NoContent(http.StatusOK)
}

func (s *Server) handleSimpleSpaceListMembers(e echo.Context) error {
	raw := e.QueryParam("space")
	if raw == "" {
		return simpleSpaceInput(e)
	}
	ref, err := simpleSpaceParseRef(raw)
	if err != nil {
		return simpleSpaceInput(e)
	}
	p, err := simpleSpaceOAuth(e)
	if err != nil {
		return simpleSpaceUnauthorized(e)
	}
	if !simpleSpaceReadAllowed(p, ref) {
		return helpers.InsufficientScopeError(e, "space:"+string(ref.SpaceType)+"?authority="+string(ref.AuthorityDID)+"&skey="+string(ref.SKey)+"&action=read")
	}
	if _, _, err := s.simpleSpaceLoad(e.Request().Context(), ref.String(), false); errors.Is(err, gorm.ErrRecordNotFound) {
		return simpleSpaceNotFound(e)
	} else if err != nil {
		return simpleSpaceInternal(e)
	}
	limit, err := parseSpaceLimit(e, 100, 1000)
	if err != nil {
		return simpleSpaceInput(e)
	}
	cursor := e.QueryParam("cursor")
	if cursor != "" {
		did, parseErr := syntax.ParseDID(cursor)
		if parseErr != nil || string(did) != cursor {
			return simpleSpaceInput(e)
		}
	}
	var members []models.SimpleSpaceMember
	q := s.db.Client().WithContext(e.Request().Context()).Where("space = ? AND removed_at IS NULL", ref.String()).Order("did ASC")
	if cursor != "" {
		q = q.Where("did > ?", cursor)
	}
	if err := q.Limit(limit + 1).Find(&members).Error; err != nil {
		return simpleSpaceInternal(e)
	}
	out := ComAtprotoSimpleSpaceListMembersOutput{Members: make([]ComAtprotoSimpleSpaceMember, 0, min(len(members), limit))}
	if len(members) > limit {
		members = members[:limit]
		next := members[len(members)-1].DID
		out.Cursor = &next
	}
	for _, member := range members {
		out.Members = append(out.Members, ComAtprotoSimpleSpaceMember{DID: member.DID})
	}
	return e.JSON(http.StatusOK, out)
}

// Compatibility aliases for route integration. Parent-owned server.go can
// choose any of these without requiring edits to this slice.
func (s *Server) handleCreateSpace(e echo.Context) error  { return s.handleSimpleSpaceCreateSpace(e) }
func (s *Server) handleUpdateSpace(e echo.Context) error  { return s.handleSimpleSpaceUpdateSpace(e) }
func (s *Server) handleDeleteSpace(e echo.Context) error  { return s.handleSimpleSpaceDeleteSpace(e) }
func (s *Server) handleGetSpace(e echo.Context) error     { return s.handleSimpleSpaceGetSpace(e) }
func (s *Server) handleAddMember(e echo.Context) error    { return s.handleSimpleSpaceAddMember(e) }
func (s *Server) handleRemoveMember(e echo.Context) error { return s.handleSimpleSpaceRemoveMember(e) }
func (s *Server) handleListMembers(e echo.Context) error  { return s.handleSimpleSpaceListMembers(e) }
func (s *Server) createSpace(e echo.Context) error        { return s.handleSimpleSpaceCreateSpace(e) }
func (s *Server) updateSpace(e echo.Context) error        { return s.handleSimpleSpaceUpdateSpace(e) }
func (s *Server) deleteSpace(e echo.Context) error        { return s.handleSimpleSpaceDeleteSpace(e) }
func (s *Server) getSpace(e echo.Context) error           { return s.handleSimpleSpaceGetSpace(e) }
func (s *Server) addMember(e echo.Context) error          { return s.handleSimpleSpaceAddMember(e) }
func (s *Server) removeMember(e echo.Context) error       { return s.handleSimpleSpaceRemoveMember(e) }
func (s *Server) listMembers(e echo.Context) error        { return s.handleSimpleSpaceListMembers(e) }

var simpleSpaceClock = syntax.NewTIDClock(0)
