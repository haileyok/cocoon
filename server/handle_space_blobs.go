package server

import (
	"bytes"
	"errors"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type ComAtprotoSpaceListBlobsResponse struct {
	Cursor *string  `json:"cursor,omitempty"`
	CIDs   []string `json:"cids"`
}

func oauthAllowsBlobScope(p *OAuthPrincipal, detectedMIME string) bool {
	if p == nil {
		return false
	}
	if p.Legacy {
		return true
	}
	parsed, err := scopes.ParseList(strings.Join(p.Scopes, " "))
	if err != nil {
		return false
	}
	for _, grant := range parsed {
		if grant.Resource != scopes.ResourceBlob {
			continue
		}
		for _, pattern := range grant.Accept {
			if blobMIMEPatternMatches(pattern, detectedMIME) {
				return true
			}
		}
	}
	return false
}

func oauthHasBlobScope(p *OAuthPrincipal) bool {
	if p == nil {
		return false
	}
	if p.Legacy {
		return true
	}
	parsed, err := scopes.ParseList(strings.Join(p.Scopes, " "))
	if err != nil {
		return false
	}
	for _, grant := range parsed {
		if grant.Resource == scopes.ResourceBlob && len(grant.Accept) != 0 {
			return true
		}
	}
	return false
}

func blobMIMEPatternMatches(pattern, detected string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "*" || pattern == "*/*" {
		return true
	}
	patternType, _, err := mime.ParseMediaType(pattern)
	if err != nil {
		patternType = pattern
	}
	detectedType, _, err := mime.ParseMediaType(strings.ToLower(detected))
	if err != nil {
		detectedType = strings.ToLower(strings.SplitN(detected, ";", 2)[0])
	}
	if patternType == detectedType {
		return true
	}
	if strings.HasSuffix(patternType, "/*") {
		return strings.HasPrefix(detectedType, strings.TrimSuffix(patternType, "*"))
	}
	// Accept patterns in the OAuth grammar are media-type globs; support a
	// conservative glob match for callers using image/* or application/*+json.
	matched, _ := path.Match(patternType, detectedType)
	return matched
}

func (s *Server) findSpaceBlobRef(e echo.Context, spaceRef space.SpaceURI, author string, blobCID cid.Cid) (models.SpaceBlobRef, error) {
	var refs []models.SpaceBlobRef
	if err := s.db.Client().WithContext(e.Request().Context()).Where("space = ? AND author = ?", spaceRef.String(), author).Find(&refs).Error; err != nil {
		return models.SpaceBlobRef{}, err
	}
	for _, ref := range refs {
		if ref.CID == blobCID.String() {
			return ref, nil
		}
	}
	return models.SpaceBlobRef{}, gorm.ErrRecordNotFound
}

func (s *Server) loadSpaceBlob(e echo.Context, author string, blobCID cid.Cid) ([]byte, string, error) {
	ctx := e.Request().Context()
	ready, err := s.selectReadyBlob(ctx, author, blobCID.Bytes(), false)
	if err != nil {
		return nil, "", err
	}
	if ready == nil {
		return nil, "", gorm.ErrRecordNotFound
	}
	data, err := s.readReadyBlob(ctx, ready)
	if err != nil {
		return nil, "", err
	}
	mimeType := ready.Blob.MimeType
	if mimeType == "" {
		mimeType = http.DetectContentType(data)
	}
	return data, mimeType, nil
}

func (s *Server) handleSpaceGetBlob(e echo.Context) error {
	spaceRaw, author, rawCID := e.QueryParam("space"), spaceRepoQueryParam(e), e.QueryParam("cid")
	if spaceRaw == "" || author == "" || rawCID == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := s.authorizeSpaceRepoRead(e, spaceRaw, author)
	if err != nil {
		return err
	}
	blobCID, err := cid.Parse(rawCID)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	ref, err := s.findSpaceBlobRef(e, spaceRef, author, blobCID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceJSONError(e, http.StatusBadRequest, "BlobNotFound")
	}
	if err != nil {
		return spaceInternalError(e)
	}
	data, detectedMIME, err := s.loadSpaceBlob(e, ref.Author, blobCID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceJSONError(e, http.StatusBadRequest, "BlobNotFound")
	}
	if err != nil {
		return spaceInternalError(e)
	}
	if p, ok := PrincipalFromContext(e).(*OAuthPrincipal); ok && !oauthAllowsBlobScope(p, detectedMIME) {
		return forbiddenSpaceBlobScope(e)
	}
	// Never redirect to CDNUrl: blob authorization must remain in this request.
	e.Response().Header().Set(echo.HeaderContentDisposition, "attachment; filename="+blobCID.String())
	e.Response().Header().Set(echo.HeaderContentLength, strconv.Itoa(len(data)))
	return e.Stream(http.StatusOK, detectedMIME, bytes.NewReader(data))
}

func forbiddenSpaceBlobScope(e echo.Context) error {
	return e.JSON(http.StatusForbidden, map[string]string{"error": "insufficient_scope", "message": "Missing covering blob scope"})
}

func (s *Server) handleSpaceListBlobs(e echo.Context) error {
	ctx := e.Request().Context()
	spaceRaw, author := e.QueryParam("space"), e.QueryParam("repo")
	if spaceRaw == "" || author == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := s.authorizeSpaceRepoRead(e, spaceRaw, author)
	if err != nil {
		return err
	}
	if _, err := s.getSpaceRepo(ctx, spaceRef, author); errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceRepoNotFound(e)
	} else if err != nil {
		return spaceInternalError(e)
	}
	if p, ok := PrincipalFromContext(e).(*OAuthPrincipal); ok && !oauthHasBlobScope(p) {
		return forbiddenSpaceBlobScope(e)
	}
	limit, err := parseSpaceLimit(e, 500, 1000)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	cursor := e.QueryParam("cursor")
	query := s.db.Client().WithContext(ctx).
		Model(&models.SpaceBlobRef{}).
		Where("space = ? AND author = ?", spaceRef.String(), author).
		Distinct("cid").
		Order("cid ASC")
	if cursor != "" {
		query = query.Where("cid > ?", cursor)
	}
	var cids []string
	if err := query.Limit(limit+1).Pluck("cid", &cids).Error; err != nil {
		return spaceInternalError(e)
	}
	hasMore := len(cids) > limit
	if hasMore {
		cids = cids[:limit]
	}
	response := ComAtprotoSpaceListBlobsResponse{CIDs: cids}
	if hasMore && len(cids) != 0 {
		next := cids[len(cids)-1]
		response.Cursor = &next
	}
	return e.JSON(http.StatusOK, response)
}
