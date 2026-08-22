package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// These handlers are intentionally separate from the legacy com.atproto.sync
// and com.atproto.repo handlers. Route registration is left to Space integration.

type ComAtprotoSpaceGetRecordResponse struct {
	URI   string `json:"uri"`
	CID   string `json:"cid,omitempty"`
	Value any    `json:"value"`
}

type ComAtprotoSpaceListRecordsRecord struct {
	URI   string `json:"uri"`
	CID   string `json:"cid"`
	Value any    `json:"value,omitempty"`
}

type ComAtprotoSpaceListRecordsResponse struct {
	Cursor  *string                            `json:"cursor,omitempty"`
	Records []ComAtprotoSpaceListRecordsRecord `json:"records"`
}

type ComAtprotoSpaceGetLatestCommitResponse struct {
	Commit space.SignedCommit `json:"commit"`
}

type ComAtprotoSpaceRepoOp struct {
	Rev        string `json:"rev"`
	Collection string `json:"collection"`
	RKey       string `json:"rkey"`
	CID        string `json:"cid,omitempty"`
	Prev       string `json:"prev,omitempty"`
	Value      any    `json:"value,omitempty"`
}

type ComAtprotoSpaceListRepoOpsResponse struct {
	Cursor *string                 `json:"cursor,omitempty"`
	Ops    []ComAtprotoSpaceRepoOp `json:"ops"`
	Commit *space.SignedCommit     `json:"commit,omitempty"`
}

func spaceJSONError(e echo.Context, status int, name string) error {
	return e.JSON(status, map[string]string{"error": name})
}

func spaceInvalidRequest(e echo.Context) error {
	return spaceJSONError(e, http.StatusBadRequest, "InvalidRequest")
}

func spaceRepoNotFound(e echo.Context) error {
	return spaceJSONError(e, http.StatusBadRequest, "RepoNotFound")
}

func spaceInternalError(e echo.Context) error {
	return spaceJSONError(e, http.StatusInternalServerError, "InternalServerError")
}

func spaceCredentialSpace(p *SpaceCredentialPrincipal) (space.SpaceURI, error) {
	if p == nil {
		return space.SpaceURI{}, errors.New("nil Space credential principal")
	}
	raw := p.SpaceURI
	if raw == "" {
		raw = p.Claims.Sub
	}
	return space.ParseSpaceURI(raw)
}

// authorizeSpaceRepoRead applies the read policy inside each handler. OAuth is
// deliberately restricted to the token subject's own repo even if a read grant
// would otherwise cover every repo. A credential is exact-space and any-author.
func (s *Server) authorizeSpaceRepoRead(e echo.Context, rawSpace, author string) (space.SpaceURI, error) {
	spaceRef, err := space.ParseSpaceURI(rawSpace)
	if err != nil {
		return space.SpaceURI{}, spaceInvalidRequest(e)
	}
	if _, err := syntax.ParseDID(author); err != nil {
		return space.SpaceURI{}, spaceInvalidRequest(e)
	}

	switch p := PrincipalFromContext(e).(type) {
	case *SpaceCredentialPrincipal:
		credentialSpace, parseErr := spaceCredentialSpace(p)
		if parseErr != nil {
			return space.SpaceURI{}, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
		}
		if credentialSpace.String() != spaceRef.String() {
			return space.SpaceURI{}, spaceJSONError(e, http.StatusForbidden, "Forbidden")
		}
	case *OAuthPrincipal:
		if p == nil || p.Subject == "" || p.Subject != author || !oauthAllowsSpaceRead(p, spaceRef, author) {
			return space.SpaceURI{}, helpers.InsufficientScopeError(e, "space:"+spaceRef.String())
		}
	default:
		return space.SpaceURI{}, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	if err := s.assertSpaceRepoAvailable(e, author); err != nil {
		return space.SpaceURI{}, err
	}
	return spaceRef, nil
}

func (s *Server) assertSpaceRepoAvailable(e echo.Context, author string) error {
	var repo models.Repo
	result := s.db.Client().WithContext(e.Request().Context()).First(&repo, "did = ?", author)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return spaceRepoNotFound(e)
	}
	if result.Error != nil {
		return spaceInternalError(e)
	}
	if status := repo.Status(); status != nil {
		switch *status {
		case "deactivated":
			return spaceJSONError(e, http.StatusBadRequest, "RepoDeactivated")
		case "suspended":
			return spaceJSONError(e, http.StatusBadRequest, "RepoSuspended")
		case "takendown":
			return spaceJSONError(e, http.StatusBadRequest, "RepoTakendown")
		}
	}
	return nil
}

func oauthAllowsSpaceRead(p *OAuthPrincipal, value space.SpaceURI, author string) bool {
	if p == nil || p.Subject == "" || p.Subject != author {
		return false
	}
	parsed, err := scopes.ParseList(strings.Join(p.Scopes, " "))
	if err != nil {
		return false
	}
	for _, grant := range parsed {
		if grant.Resource == scopes.ResourceSpace && grant.AllowsSpaceRead(value, author, p.Subject) {
			return true
		}
	}
	return false
}

func parseSpaceBool(e echo.Context, name string) (bool, error) {
	raw := e.QueryParam(name)
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	return value, err
}

func parseSpaceLimit(e echo.Context, defaultLimit, max int) (int, error) {
	raw := e.QueryParam("limit")
	if raw == "" {
		return defaultLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > max {
		return 0, errors.New("limit out of range")
	}
	return limit, nil
}

func (s *Server) spaceRepoManager() *SpaceRepoMan {
	if s.spaceRepoMan != nil {
		return s.spaceRepoMan
	}
	return NewSpaceRepoMan(s)
}

func (s *Server) getSpaceRepo(ctx context.Context, spaceRef space.SpaceURI, author string) (models.SpaceRepo, error) {
	return s.spaceRepoManager().GetRepo(ctx, spaceRef.String(), author)
}

func spacePath(row models.SpaceRecord) string { return row.Collection + "/" + row.Rkey }

func sortSpaceRecords(rows []models.SpaceRecord, reverse bool) {
	sort.Slice(rows, func(i, j int) bool {
		cmp := bytes.Compare([]byte(spacePath(rows[i])), []byte(spacePath(rows[j])))
		if reverse {
			return cmp > 0
		}
		return cmp < 0
	})
}

func (s *Server) loadSpaceRecords(ctx context.Context, spaceRef space.SpaceURI, author, collection string) (models.SpaceRepo, []models.SpaceRecord, error) {
	repo, err := s.getSpaceRepo(ctx, spaceRef, author)
	if err != nil {
		return models.SpaceRepo{}, nil, err
	}
	query := s.db.Client().WithContext(ctx).Where("space = ? AND author = ?", spaceRef.String(), author)
	if collection != "" {
		query = query.Where("collection = ?", collection)
	}
	var rows []models.SpaceRecord
	if err := query.Find(&rows).Error; err != nil {
		return models.SpaceRepo{}, nil, err
	}
	return repo, rows, nil
}

func spaceRecordURI(spaceRef space.SpaceURI, author, collection, rkey string) (string, error) {
	recordRef, err := space.NewRecordURI(string(spaceRef.AuthorityDID), string(spaceRef.SpaceType), string(spaceRef.SKey), author, collection, rkey)
	if err != nil {
		return "", err
	}
	return recordRef.String(), nil
}

func decodeSpaceRecord(row models.SpaceRecord) (any, error) {
	return atdata.UnmarshalCBOR(row.CanonicalCBOR)
}

func (s *Server) handleSpaceGetRecord(e echo.Context) error {
	ctx := e.Request().Context()
	rawSpace, author := e.QueryParam("space"), e.QueryParam("did")
	collection, rkey := e.QueryParam("collection"), e.QueryParam("rkey")
	if rawSpace == "" || author == "" || collection == "" || rkey == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := s.authorizeSpaceRepoRead(e, rawSpace, author)
	if err != nil {
		return err
	}
	if _, err := syntax.ParseNSID(collection); err != nil {
		return spaceInvalidRequest(e)
	}
	if _, err := syntax.ParseRecordKey(rkey); err != nil {
		return spaceInvalidRequest(e)
	}
	if _, err := s.getSpaceRepo(ctx, spaceRef, author); errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceRepoNotFound(e)
	} else if err != nil {
		return spaceInternalError(e)
	}
	var row models.SpaceRecord
	if err := s.db.Client().WithContext(ctx).Where("space = ? AND author = ? AND collection = ? AND rkey = ?", spaceRef.String(), author, collection, rkey).First(&row).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceJSONError(e, http.StatusBadRequest, "RecordNotFound")
	} else if err != nil {
		return spaceInternalError(e)
	}
	if requestedCID := e.QueryParam("cid"); requestedCID != "" {
		parsed, parseErr := syntax.ParseCID(requestedCID)
		if parseErr != nil || parsed.String() != row.CID {
			return spaceJSONError(e, http.StatusBadRequest, "RecordNotFound")
		}
	}
	value, err := decodeSpaceRecord(row)
	if err != nil {
		return spaceInternalError(e)
	}
	uri, err := spaceRecordURI(spaceRef, author, collection, rkey)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	return e.JSON(http.StatusOK, ComAtprotoSpaceGetRecordResponse{URI: uri, CID: row.CID, Value: value})
}

func (s *Server) handleSpaceListRecords(e echo.Context) error {
	ctx := e.Request().Context()
	rawSpace, author := e.QueryParam("space"), e.QueryParam("did")
	if rawSpace == "" || author == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := s.authorizeSpaceRepoRead(e, rawSpace, author)
	if err != nil {
		return err
	}
	collection := e.QueryParam("collection")
	if collection != "" {
		if _, err := syntax.ParseNSID(collection); err != nil {
			return spaceInvalidRequest(e)
		}
	}
	limit, err := parseSpaceLimit(e, 50, 100)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	reverse, err := parseSpaceBool(e, "reverse")
	if err != nil {
		return spaceInvalidRequest(e)
	}
	excludeValues, err := parseSpaceBool(e, "excludeValues")
	if err != nil {
		return spaceInvalidRequest(e)
	}
	_, rows, err := s.loadSpaceRecords(ctx, spaceRef, author, collection)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceRepoNotFound(e)
	}
	if err != nil {
		return spaceInternalError(e)
	}
	sortSpaceRecords(rows, reverse)
	cursor := e.QueryParam("cursor")
	if cursor != "" {
		filtered := rows[:0]
		for _, row := range rows {
			path := spacePath(row)
			if (!reverse && path > cursor) || (reverse && path < cursor) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	items := make([]ComAtprotoSpaceListRecordsRecord, 0, len(rows))
	for _, row := range rows {
		uri, err := spaceRecordURI(spaceRef, author, row.Collection, row.Rkey)
		if err != nil {
			return spaceInternalError(e)
		}
		item := ComAtprotoSpaceListRecordsRecord{URI: uri, CID: row.CID}
		if !excludeValues {
			item.Value, err = decodeSpaceRecord(row)
			if err != nil {
				return spaceInternalError(e)
			}
		}
		items = append(items, item)
	}
	response := ComAtprotoSpaceListRecordsResponse{Records: items}
	if hasMore && len(rows) != 0 {
		next := spacePath(rows[len(rows)-1])
		response.Cursor = &next
	}
	return e.JSON(http.StatusOK, response)
}

func (s *Server) signSpaceCommit(ctx context.Context, spaceRef space.SpaceURI, author, rev string, hash []byte) (space.SignedCommit, error) {
	var account models.Repo
	if err := s.db.First(ctx, &account, "did = ?", author).Error; err != nil {
		return space.SignedCommit{}, err
	}
	key, err := atcrypto.ParsePrivateBytesK256(account.SigningKey)
	if err != nil {
		return space.SignedCommit{}, fmt.Errorf("parse account signing key: %w", err)
	}
	return space.SignCommit(hash, space.CommitContext{Space: spaceRef.String(), Author: author, Rev: rev}, key)
}

func (s *Server) currentSpaceCommit(ctx context.Context, spaceRef space.SpaceURI, author string) (space.SignedCommit, error) {
	repo, err := s.getSpaceRepo(ctx, spaceRef, author)
	if err != nil {
		return space.SignedCommit{}, err
	}
	ltHash, err := space.NewLtHash(repo.LtHash)
	if err != nil {
		return space.SignedCommit{}, err
	}
	return s.signSpaceCommit(ctx, spaceRef, author, repo.Rev, ltHash.Digest())
}

func (s *Server) handleSpaceGetLatestCommit(e echo.Context) error {
	ctx := e.Request().Context()
	rawSpace, author := e.QueryParam("space"), e.QueryParam("did")
	if rawSpace == "" || author == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := s.authorizeSpaceRepoRead(e, rawSpace, author)
	if err != nil {
		return err
	}
	commit, err := s.currentSpaceCommit(ctx, spaceRef, author)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceRepoNotFound(e)
	}
	if err != nil {
		return spaceInternalError(e)
	}
	return e.JSON(http.StatusOK, ComAtprotoSpaceGetLatestCommitResponse{Commit: commit})
}

func (s *Server) repoRecordsForCAR(ctx context.Context, spaceRef space.SpaceURI, author string) (models.SpaceRepo, []space.SerializedRecord, error) {
	repo, rows, err := s.loadSpaceRecords(ctx, spaceRef, author, "")
	if err != nil {
		return models.SpaceRepo{}, nil, err
	}
	records := make([]space.SerializedRecord, 0, len(rows))
	for _, row := range rows {
		parsedCID, err := cid.Parse(row.CID)
		if err != nil {
			return models.SpaceRepo{}, nil, err
		}
		record, err := space.SerializeRecordBytes(row.Collection, row.Rkey, parsedCID, row.CanonicalCBOR)
		if err != nil {
			return models.SpaceRepo{}, nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return bytes.Compare([]byte(records[i].Collection+"/"+records[i].RKey), []byte(records[j].Collection+"/"+records[j].RKey)) < 0
	})
	return repo, records, nil
}

func (s *Server) handleSpaceGetRepo(e echo.Context) error {
	ctx := e.Request().Context()
	rawSpace, author := e.QueryParam("space"), e.QueryParam("did")
	if rawSpace == "" || author == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := s.authorizeSpaceRepoRead(e, rawSpace, author)
	if err != nil {
		return err
	}
	excludeValues, err := parseSpaceBool(e, "excludeValues")
	if err != nil {
		return spaceInvalidRequest(e)
	}
	repo, records, err := s.repoRecordsForCAR(ctx, spaceRef, author)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceRepoNotFound(e)
	}
	if err != nil {
		return spaceInternalError(e)
	}
	repoCommit, err := space.RepoCommitFromRecords(records)
	if err != nil {
		return spaceInternalError(e)
	}
	commit, err := s.signSpaceCommit(ctx, spaceRef, author, repo.Rev, repoCommit.Hash())
	if err != nil {
		return spaceInternalError(e)
	}
	data, err := space.SerializeRepo(commit, records, space.SerializeRepoOptions{ExcludeValues: excludeValues})
	if err != nil {
		return spaceInternalError(e)
	}
	return e.Stream(http.StatusOK, "application/vnd.ipld.car", bytes.NewReader(data))
}

type spaceOpCursor struct {
	Rev string `json:"rev"`
	Idx int    `json:"idx"`
}

func encodeSpaceOpCursor(rev string, idx int) string {
	data, _ := json.Marshal(spaceOpCursor{Rev: rev, Idx: idx})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeSpaceOpCursor(raw string) (spaceOpCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return spaceOpCursor{}, err
	}
	var cursor spaceOpCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Rev == "" || cursor.Idx < 0 {
		return spaceOpCursor{}, errors.New("invalid opaque cursor")
	}
	return cursor, nil
}

func (s *Server) handleSpaceListRepoOps(e echo.Context) error {
	ctx := e.Request().Context()
	rawSpace, author := e.QueryParam("space"), e.QueryParam("did")
	if rawSpace == "" || author == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := s.authorizeSpaceRepoRead(e, rawSpace, author)
	if err != nil {
		return err
	}
	limit, err := parseSpaceLimit(e, 500, 1000)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	excludeValues, err := parseSpaceBool(e, "excludeValues")
	if err != nil {
		return spaceInvalidRequest(e)
	}
	repo, err := s.getSpaceRepo(ctx, spaceRef, author)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return spaceRepoNotFound(e)
	}
	if err != nil {
		return spaceInternalError(e)
	}
	var rows []models.SpaceRepoOp
	if err := s.db.Client().WithContext(ctx).Where("space = ? AND author = ?", spaceRef.String(), author).Order("rev ASC, idx ASC").Find(&rows).Error; err != nil {
		return spaceInternalError(e)
	}
	if since := e.QueryParam("since"); since != "" {
		filtered := rows[:0]
		for _, row := range rows {
			if row.Rev > since {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	if rawCursor := e.QueryParam("cursor"); rawCursor != "" {
		cursor, err := decodeSpaceOpCursor(rawCursor)
		if err != nil {
			return spaceInvalidRequest(e)
		}
		filtered := rows[:0]
		for _, row := range rows {
			if row.Rev > cursor.Rev || (row.Rev == cursor.Rev && row.Idx > cursor.Idx) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	// A batch is atomic: do not split a revision when the page reaches limit.
	selectedEnd := len(rows)
	if len(rows) > limit {
		selectedEnd = 0
		for selectedEnd < len(rows) {
			rev := rows[selectedEnd].Rev
			groupEnd := selectedEnd + 1
			for groupEnd < len(rows) && rows[groupEnd].Rev == rev {
				groupEnd++
			}
			selectedEnd = groupEnd
			if selectedEnd >= limit {
				break
			}
		}
	}
	selected := rows[:selectedEnd]
	hasMore := selectedEnd < len(rows)
	current := make(map[string]models.SpaceRecord)
	if !excludeValues && len(selected) > 0 {
		var records []models.SpaceRecord
		if err := s.db.Client().WithContext(ctx).Where("space = ? AND author = ?", spaceRef.String(), author).Find(&records).Error; err != nil {
			return spaceInternalError(e)
		}
		for _, record := range records {
			current[spacePath(record)] = record
		}
	}
	ops := make([]ComAtprotoSpaceRepoOp, 0, len(selected))
	for _, row := range selected {
		op := ComAtprotoSpaceRepoOp{Rev: row.Rev, Collection: row.Collection, RKey: row.Rkey}
		if row.CurrentCID != nil {
			op.CID = *row.CurrentCID
		}
		if row.PreviousCID != nil {
			op.Prev = *row.PreviousCID
		}
		if !excludeValues && row.CurrentCID != nil {
			key := row.Collection + "/" + row.Rkey
			if record, ok := current[key]; ok && record.CID == *row.CurrentCID {
				value, err := decodeSpaceRecord(record)
				if err != nil {
					return spaceInternalError(e)
				}
				op.Value = value
			}
		}
		ops = append(ops, op)
	}
	response := ComAtprotoSpaceListRepoOpsResponse{Ops: ops}
	if hasMore && len(selected) > 0 {
		last := selected[len(selected)-1]
		next := encodeSpaceOpCursor(last.Rev, last.Idx)
		response.Cursor = &next
	} else {
		commit, err := s.currentSpaceCommit(ctx, spaceRef, author)
		if err != nil {
			return spaceInternalError(e)
		}
		response.Commit = &commit
	}
	_ = repo // explicit RepoNotFound guard above
	return e.JSON(http.StatusOK, response)
}

// A writer may store either the serialized LtHash state or its sha256 digest.
func spaceHashHex(raw []byte) string {
	if len(raw) == space.LtHashStateBytes {
		if hash, err := space.NewLtHash(raw); err == nil {
			return hex.EncodeToString(hash.Digest())
		}
	}
	if len(raw) == sha256.Size {
		return hex.EncodeToString(raw)
	}
	return ""
}
