package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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
	var blob models.Blob
	if err := s.db.Client().WithContext(ctx).Where("did = ? AND cid = ?", author, blobCID.Bytes()).First(&blob).Error; err != nil {
		return nil, "", err
	}
	var data bytes.Buffer
	switch blob.Storage {
	case "", "sqlite":
		var parts []models.BlobPart
		if err := s.db.Client().WithContext(ctx).Where("blob_id = ?", blob.ID).Order("idx ASC").Find(&parts).Error; err != nil {
			return nil, "", err
		}
		for _, part := range parts {
			_, _ = data.Write(part.Data)
		}
	case "s3":
		if s.s3Config == nil || !s.s3Config.BlobstoreEnabled {
			return nil, "", fmt.Errorf("S3 blob storage is disabled")
		}
		config := &aws.Config{
			Region:      aws.String(s.s3Config.Region),
			Credentials: credentials.NewStaticCredentials(s.s3Config.AccessKey, s.s3Config.SecretKey, ""),
		}
		if s.s3Config.Endpoint != "" {
			config.Endpoint = aws.String(s.s3Config.Endpoint)
			config.S3ForcePathStyle = aws.Bool(true)
		}
		sess, err := session.NewSession(config)
		if err != nil {
			return nil, "", err
		}
		result, err := s3.New(sess).GetObject(&s3.GetObjectInput{
			Bucket: aws.String(s.s3Config.Bucket),
			Key:    aws.String(fmt.Sprintf("blobs/%s/%s", author, blobCID.String())),
		})
		if err != nil {
			return nil, "", err
		}
		defer result.Body.Close()
		if _, err := io.Copy(&data, result.Body); err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("unknown blob storage %q", blob.Storage)
	}
	return data.Bytes(), http.DetectContentType(data.Bytes()), nil
}

func (s *Server) handleSpaceGetBlob(e echo.Context) error {
	spaceRaw, author, rawCID := e.QueryParam("space"), e.QueryParam("did"), e.QueryParam("cid")
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
	return e.Stream(http.StatusOK, "application/octet-stream", bytes.NewReader(data))
}

func forbiddenSpaceBlobScope(e echo.Context) error {
	return e.JSON(http.StatusForbidden, map[string]string{"error": "insufficient_scope", "message": "Missing covering blob scope"})
}

func (s *Server) handleSpaceListBlobs(e echo.Context) error {
	ctx := e.Request().Context()
	spaceRaw, author := e.QueryParam("space"), e.QueryParam("did")
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
	limit, err := parseSpaceLimit(e, 50, 1000)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	var refs []models.SpaceBlobRef
	if err := s.db.Client().WithContext(ctx).Where("space = ? AND author = ?", spaceRef.String(), author).Find(&refs).Error; err != nil {
		return spaceInternalError(e)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].CID < refs[j].CID })
	// SpaceBlobRef's primary key prevents duplicates, but preserve a set here so
	// old databases with duplicate rows cannot leak duplicate CIDs in the API.
	cids := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if _, ok := seen[ref.CID]; ok {
			continue
		}
		if cursor := e.QueryParam("cursor"); cursor != "" && ref.CID <= cursor {
			continue
		}
		seen[ref.CID] = struct{}{}
		cids = append(cids, ref.CID)
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
