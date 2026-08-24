package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

const (
	spaceCreateType = "com.atproto.space.applyWrites#create"
	spaceUpdateType = "com.atproto.space.applyWrites#update"
	spaceDeleteType = "com.atproto.space.applyWrites#delete"

	spaceCreateResultType = "com.atproto.space.applyWrites#createResult"
	spaceUpdateResultType = "com.atproto.space.applyWrites#updateResult"
	spaceDeleteResultType = "com.atproto.space.applyWrites#deleteResult"
)

// ComAtprotoSpaceCreateRecordInput is the pinned input shape for
// com.atproto.space.createRecord.
type ComAtprotoSpaceCreateRecordInput struct {
	Space      string         `json:"space"`
	Repo       string         `json:"repo"`
	Collection string         `json:"collection"`
	Rkey       *string        `json:"rkey,omitempty"`
	Validate   *bool          `json:"validate,omitempty"`
	Record     MarshalableMap `json:"record"`
}

// ComAtprotoSpacePutRecordInput is the pinned input shape for
// com.atproto.space.putRecord.
type ComAtprotoSpacePutRecordInput struct {
	Space      string         `json:"space"`
	Repo       string         `json:"repo"`
	Collection string         `json:"collection"`
	Rkey       string         `json:"rkey"`
	Validate   *bool          `json:"validate,omitempty"`
	Record     MarshalableMap `json:"record"`
}

// ComAtprotoSpaceDeleteRecordInput is the pinned input shape for
// com.atproto.space.deleteRecord.
type ComAtprotoSpaceDeleteRecordInput struct {
	Space      string `json:"space"`
	Repo       string `json:"repo"`
	Collection string `json:"collection"`
	Rkey       string `json:"rkey"`
}

// ComAtprotoSpaceApplyWritesInput is the pinned input shape for
// com.atproto.space.applyWrites.
type ComAtprotoSpaceApplyWritesInput struct {
	Space    string                              `json:"space"`
	Repo     string                              `json:"repo"`
	Validate *bool                               `json:"validate,omitempty"`
	Writes   []ComAtprotoSpaceApplyWritesElement `json:"writes"`
}

// ComAtprotoSpaceApplyWritesElement is the closed union element. Type is one
// of com.atproto.space.applyWrites#{create,update,delete}.
type ComAtprotoSpaceApplyWritesElement struct {
	Type       string         `json:"$type"`
	Collection string         `json:"collection"`
	Rkey       *string        `json:"rkey,omitempty"`
	Value      MarshalableMap `json:"value,omitempty"`
}

// ComAtprotoSpaceRecordWriteOutput is shared by createRecord and putRecord.
type ComAtprotoSpaceRecordWriteOutput struct {
	URI              string  `json:"uri"`
	CID              string  `json:"cid"`
	ValidationStatus *string `json:"validationStatus,omitempty"`
}

// ComAtprotoSpaceApplyWritesResult is the closed result union. The $type tag
// is required on the wire even though it is implicit in the lexicon union.
type ComAtprotoSpaceApplyWritesResult struct {
	Type             string  `json:"$type"`
	URI              string  `json:"uri,omitempty"`
	CID              string  `json:"cid,omitempty"`
	ValidationStatus *string `json:"validationStatus,omitempty"`
}

// ComAtprotoSpaceApplyWritesOutput is the pinned applyWrites output shape.
type ComAtprotoSpaceApplyWritesOutput struct {
	Results []ComAtprotoSpaceApplyWritesResult `json:"results"`
}

// ComAtprotoSpaceGetDelegationTokenOutput is the pinned delegation output.
type ComAtprotoSpaceGetDelegationTokenOutput struct {
	Token string `json:"token"`
}

// SetSpaceTypeResolver injects the local, typed space declaration resolver used
// for omitted-collection OAuth grants. It never performs network resolution.
func (s *Server) SetSpaceTypeResolver(resolver scopes.SpaceTypeResolver) {
	if s != nil {
		s.spaceTypeResolver = resolver
	}
}

func spaceOAuthPrincipal(e echo.Context) (*OAuthPrincipal, error) {
	principal, ok := PrincipalFromContext(e).(*OAuthPrincipal)
	if !ok || principal == nil || principal.Subject == "" {
		return nil, errors.New("OAuth principal is required")
	}
	did, err := syntax.ParseDID(principal.Subject)
	if err != nil || string(did) != principal.Subject {
		return nil, errors.New("OAuth principal subject is not canonical")
	}
	return principal, nil
}

func spaceOAuthUnauthorized(e echo.Context, err error) error {
	message := "OAuth principal is required"
	if err != nil && err.Error() != "" {
		message = err.Error()
	}
	return e.JSON(http.StatusUnauthorized, map[string]string{
		"error":             "Unauthorized",
		"error_description": message,
	})
}

func spaceOAuthInputError(e echo.Context, name string) error {
	return spaceJSONError(e, http.StatusBadRequest, name)
}

func spaceOAuthServerError(e echo.Context, err error) error {
	if err == nil {
		return spaceInternalError(e)
	}
	return helpers.ServerError(e, nil)
}

func spaceOAuthParseRef(s *Server, e echo.Context, raw string) (space.SpaceURI, error) {
	ref, err := space.ParseSpaceURI(raw)
	if err != nil {
		return space.SpaceURI{}, err
	}
	if s != nil {
		if err := s.checkSpaceAvailable(e.Request().Context(), ref.String(), string(ref.AuthorityDID)); err != nil {
			return space.SpaceURI{}, fmt.Errorf("space unavailable: %w", err)
		}
	}
	return ref, nil
}

func spaceRecordValid(record MarshalableMap) bool {
	if record == nil {
		return false
	}
	typeValue, ok := record["$type"].(string)
	if !ok || typeValue == "" {
		return false
	}
	parsed, err := syntax.ParseNSID(typeValue)
	return err == nil && string(parsed) == typeValue
}

func spaceCollectionValid(collection string) bool {
	parsed, err := syntax.ParseNSID(collection)
	return err == nil && string(parsed) == collection
}

func spaceRkeyValid(rkey string) bool {
	parsed, err := syntax.ParseRecordKey(rkey)
	return err == nil && string(parsed) == rkey
}

func (s *Server) allowsSpaceOAuthWrite(principal *OAuthPrincipal, ref space.SpaceURI, collection, action string) bool {
	if principal == nil {
		return false
	}
	if principal.Legacy {
		return true
	}
	for _, raw := range principal.Scopes {
		grant, err := scopes.Parse(raw)
		if err != nil {
			continue
		}
		if grant.AllowsSpaceWrite(ref, collection, action, principal.Subject, s.spaceTypeResolver) {
			return true
		}
	}
	return false
}

func spaceOAuthScopeRequired(collection, action string) string {
	return fmt.Sprintf("space:*?collection=%s&action=%s", collection, action)
}

func mapSpaceOAuthWriteError(e echo.Context, err error) error {
	if err == nil {
		return nil
	}
	var insufficientScope *SpaceRepoInsufficientScopeError
	if errors.As(err, &insufficientScope) {
		return helpers.InsufficientScopeError(e, spaceOAuthScopeRequired(insufficientScope.Action.Collection, string(insufficientScope.Action.Type)))
	}
	if errors.Is(err, gorm.ErrRecordNotFound) || strings.Contains(err.Error(), "does not exist") {
		return spaceOAuthInputError(e, "RecordNotFound")
	}
	if strings.Contains(err.Error(), "already exists") {
		return spaceOAuthInputError(e, "RecordAlreadyExists")
	}
	if strings.Contains(err.Error(), "space unavailable") || strings.Contains(err.Error(), "tombstoned") {
		return spaceOAuthInputError(e, "SpaceNotFound")
	}
	if strings.Contains(err.Error(), "MIME type does not match") {
		return spaceOAuthInputError(e, "InvalidMimeType")
	}
	if strings.Contains(err.Error(), "size does not match") {
		return spaceOAuthInputError(e, "InvalidSize")
	}
	if strings.Contains(err.Error(), "space ref:") || strings.Contains(err.Error(), "author DID:") || strings.Contains(err.Error(), "collection:") || strings.Contains(err.Error(), "rkey:") || strings.Contains(err.Error(), "record must be") || strings.Contains(err.Error(), "unknown operation") {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	return spaceOAuthServerError(e, err)
}

func requireSpaceOAuthRepo(principal *OAuthPrincipal, repo string) error {
	if principal == nil || repo == "" || repo != principal.Subject {
		return errors.New("repo does not match OAuth subject")
	}
	return nil
}

func (s *Server) handleSpaceCreateRecord(e echo.Context) error {
	principal, err := spaceOAuthPrincipal(e)
	if err != nil {
		return spaceOAuthUnauthorized(e, err)
	}
	var req ComAtprotoSpaceCreateRecordInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.Repo == "" || req.Collection == "" || req.Record == nil {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	if err := requireSpaceOAuthRepo(principal, req.Repo); err != nil || !spaceCollectionValid(req.Collection) || !spaceRecordValid(req.Record) {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	ref, err := spaceOAuthParseRef(s, e, req.Space)
	if err != nil {
		if strings.Contains(err.Error(), "space unavailable") {
			return spaceOAuthInputError(e, "SpaceNotFound")
		}
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	if !s.allowsSpaceOAuthWrite(principal, ref, req.Collection, "create") {
		return helpers.InsufficientScopeError(e, spaceOAuthScopeRequired(req.Collection, "create"))
	}
	var rkey string
	if req.Rkey != nil {
		rkey = *req.Rkey
		if !spaceRkeyValid(rkey) {
			return spaceOAuthInputError(e, "InvalidRequest")
		}
	}
	batch, err := s.spaceRepoManager().Apply(e.Request().Context(), ref.String(), principal.Subject, []SpaceRepoOperation{{
		Type: SpaceRepoOpCreate, Collection: req.Collection, Rkey: rkey, Record: req.Record,
	}})
	if err != nil {
		return mapSpaceOAuthWriteError(e, err)
	}
	change := batch.Changes[0]
	return e.JSON(http.StatusOK, ComAtprotoSpaceRecordWriteOutput{URI: change.URI, CID: change.CID})
}

func (s *Server) handleSpacePutRecord(e echo.Context) error {
	principal, err := spaceOAuthPrincipal(e)
	if err != nil {
		return spaceOAuthUnauthorized(e, err)
	}
	var req ComAtprotoSpacePutRecordInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.Repo == "" || req.Collection == "" || req.Rkey == "" || req.Record == nil {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	if err := requireSpaceOAuthRepo(principal, req.Repo); err != nil || !spaceCollectionValid(req.Collection) || !spaceRkeyValid(req.Rkey) || !spaceRecordValid(req.Record) {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	ref, err := spaceOAuthParseRef(s, e, req.Space)
	if err != nil {
		if strings.Contains(err.Error(), "space unavailable") {
			return spaceOAuthInputError(e, "SpaceNotFound")
		}
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	// Scope resolution may require a remote Space declaration lookup. Resolve
	// both state-independent grant decisions before opening the repository
	// transaction, then select the concrete action under the repo lock.
	allowed := SpaceRepoAllowedActions{
		SpaceRepoOpCreate: s.allowsSpaceOAuthWrite(principal, ref, req.Collection, "create"),
		SpaceRepoOpUpdate: s.allowsSpaceOAuthWrite(principal, ref, req.Collection, "update"),
	}
	batch, err := s.spaceRepoManager().PutRecordWithAuthorization(e.Request().Context(), ref.String(), principal.Subject, req.Collection, req.Rkey, req.Record, allowed.Authorize)
	if err != nil {
		return mapSpaceOAuthWriteError(e, err)
	}
	change := batch.Changes[0]
	return e.JSON(http.StatusOK, ComAtprotoSpaceRecordWriteOutput{URI: change.URI, CID: change.CID})
}

func (s *Server) handleSpaceDeleteRecord(e echo.Context) error {
	principal, err := spaceOAuthPrincipal(e)
	if err != nil {
		return spaceOAuthUnauthorized(e, err)
	}
	var req ComAtprotoSpaceDeleteRecordInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.Repo == "" || req.Collection == "" || req.Rkey == "" {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	if err := requireSpaceOAuthRepo(principal, req.Repo); err != nil || !spaceCollectionValid(req.Collection) || !spaceRkeyValid(req.Rkey) {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	ref, err := spaceOAuthParseRef(s, e, req.Space)
	if err != nil {
		if strings.Contains(err.Error(), "space unavailable") {
			return spaceOAuthInputError(e, "SpaceNotFound")
		}
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	if !s.allowsSpaceOAuthWrite(principal, ref, req.Collection, "delete") {
		return helpers.InsufficientScopeError(e, spaceOAuthScopeRequired(req.Collection, "delete"))
	}
	manager := s.spaceRepoManager()
	_, getErr := manager.GetRecord(e.Request().Context(), ref.String(), principal.Subject, req.Collection, req.Rkey)
	if errors.Is(getErr, gorm.ErrRecordNotFound) {
		return e.JSON(http.StatusOK, struct{}{})
	}
	if getErr != nil {
		return mapSpaceOAuthWriteError(e, getErr)
	}
	if _, err := manager.DeleteRecord(e.Request().Context(), ref.String(), principal.Subject, req.Collection, req.Rkey); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || strings.Contains(err.Error(), "does not exist") {
			return e.JSON(http.StatusOK, struct{}{})
		}
		return mapSpaceOAuthWriteError(e, err)
	}
	return e.JSON(http.StatusOK, struct{}{})
}

func validSpaceApplyType(value string) bool {
	return value == spaceCreateType || value == spaceUpdateType || value == spaceDeleteType
}

func (s *Server) handleSpaceApplyWrites(e echo.Context) error {
	principal, err := spaceOAuthPrincipal(e)
	if err != nil {
		return spaceOAuthUnauthorized(e, err)
	}
	var req ComAtprotoSpaceApplyWritesInput
	if err := e.Bind(&req); err != nil || req.Space == "" || req.Repo == "" || req.Writes == nil {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	if err := requireSpaceOAuthRepo(principal, req.Repo); err != nil {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	ref, err := spaceOAuthParseRef(s, e, req.Space)
	if err != nil {
		if strings.Contains(err.Error(), "space unavailable") {
			return spaceOAuthInputError(e, "SpaceNotFound")
		}
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	operations := make([]SpaceRepoOperation, 0, len(req.Writes))
	for _, item := range req.Writes {
		if !validSpaceApplyType(item.Type) || item.Collection == "" || !spaceCollectionValid(item.Collection) {
			return spaceOAuthInputError(e, "InvalidRequest")
		}
		action := ""
		switch item.Type {
		case spaceCreateType:
			action = "create"
			if (item.Rkey != nil && (*item.Rkey == "" || !spaceRkeyValid(*item.Rkey))) || !spaceRecordValid(item.Value) {
				return spaceOAuthInputError(e, "InvalidRequest")
			}
		case spaceUpdateType:
			action = "update"
			if item.Rkey == nil || *item.Rkey == "" || !spaceRkeyValid(*item.Rkey) || !spaceRecordValid(item.Value) {
				return spaceOAuthInputError(e, "InvalidRequest")
			}
		case spaceDeleteType:
			action = "delete"
			if item.Rkey == nil || *item.Rkey == "" || !spaceRkeyValid(*item.Rkey) || item.Value != nil {
				return spaceOAuthInputError(e, "InvalidRequest")
			}
		}
		if !s.allowsSpaceOAuthWrite(principal, ref, item.Collection, action) {
			return helpers.InsufficientScopeError(e, spaceOAuthScopeRequired(item.Collection, action))
		}
		rkey := ""
		if item.Rkey != nil {
			rkey = *item.Rkey
		}
		operations = append(operations, SpaceRepoOperation{Type: SpaceRepoOpType(action), Collection: item.Collection, Rkey: rkey, Record: item.Value})
	}
	if len(operations) == 0 {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	batch, err := s.spaceRepoManager().Apply(e.Request().Context(), ref.String(), principal.Subject, operations)
	if err != nil {
		return mapSpaceOAuthWriteError(e, err)
	}
	results := make([]ComAtprotoSpaceApplyWritesResult, 0, len(batch.Changes))
	for _, change := range batch.Changes {
		result := ComAtprotoSpaceApplyWritesResult{}
		switch change.Type {
		case SpaceRepoOpCreate:
			result.Type = spaceCreateResultType
			result.URI, result.CID = change.URI, change.CID
		case SpaceRepoOpUpdate:
			result.Type = spaceUpdateResultType
			result.URI, result.CID = change.URI, change.CID
		case SpaceRepoOpDelete:
			result.Type = spaceDeleteResultType
		default:
			return spaceOAuthServerError(e, errors.New("space manager returned unknown result type"))
		}
		results = append(results, result)
	}
	return e.JSON(http.StatusOK, ComAtprotoSpaceApplyWritesOutput{Results: results})
}
