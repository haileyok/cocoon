package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type ComAtprotoSpaceListReposRepoRef struct {
	DID  string `json:"did"`
	Rev  string `json:"rev"`
	Hash string `json:"hash"`
}

type listReposRepoWire struct {
	DID  string            `json:"did"`
	Rev  string            `json:"rev"`
	Hash map[string]string `json:"hash"`
}

func (r ComAtprotoSpaceListReposRepoRef) MarshalJSON() ([]byte, error) {
	return json.Marshal(listReposRepoWire{
		DID: r.DID,
		Rev: r.Rev,
		Hash: map[string]string{
			"$bytes": r.Hash,
		},
	})
}

func (r *ComAtprotoSpaceListReposRepoRef) UnmarshalJSON(data []byte) error {
	var wire listReposRepoWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.DID, r.Rev = wire.DID, wire.Rev
	r.Hash = wire.Hash["$bytes"]
	return nil
}

type ComAtprotoSpaceListReposResponse struct {
	Cursor *string                           `json:"cursor,omitempty"`
	Repos  []ComAtprotoSpaceListReposRepoRef `json:"repos"`
}

type spaceWriterCursor struct {
	Author string `json:"author"`
}

func encodeSpaceWriterCursor(author string) string {
	data, _ := json.Marshal(spaceWriterCursor{Author: author})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeSpaceWriterCursor(raw string) (spaceWriterCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return spaceWriterCursor{}, err
	}
	var cursor spaceWriterCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Author == "" {
		return spaceWriterCursor{}, errors.New("invalid opaque writer cursor")
	}
	return cursor, nil
}

func authorizeSpaceCredentialRead(e echo.Context, rawSpace string) (space.SpaceURI, error) {
	spaceRef, err := space.ParseSpaceURI(rawSpace)
	if err != nil {
		return space.SpaceURI{}, spaceInvalidRequest(e)
	}
	principal, ok := PrincipalFromContext(e).(*SpaceCredentialPrincipal)
	if !ok || principal == nil {
		if _, oauth := PrincipalFromContext(e).(*OAuthPrincipal); oauth {
			return space.SpaceURI{}, spaceJSONError(e, http.StatusForbidden, "Forbidden")
		}
		return space.SpaceURI{}, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	credentialSpace, err := spaceCredentialSpace(principal)
	if err != nil {
		return space.SpaceURI{}, spaceJSONError(e, http.StatusUnauthorized, "Unauthorized")
	}
	if credentialSpace.String() != spaceRef.String() {
		return space.SpaceURI{}, spaceJSONError(e, http.StatusForbidden, "Forbidden")
	}
	return spaceRef, nil
}

func (s *Server) handleSpaceListRepos(e echo.Context) error {
	ctx := e.Request().Context()
	rawSpace := e.QueryParam("space")
	if rawSpace == "" {
		return spaceInvalidRequest(e)
	}
	spaceRef, err := authorizeSpaceCredentialRead(e, rawSpace)
	if err != nil {
		return err
	}
	if err := s.checkSpaceAvailable(ctx, spaceRef.String(), string(spaceRef.AuthorityDID)); err != nil {
		return spaceJSONError(e, http.StatusBadRequest, "SpaceNotFound")
	}
	limit, err := parseSpaceLimit(e, 500, 1000)
	if err != nil {
		return spaceInvalidRequest(e)
	}
	cursor := e.QueryParam("cursor")
	cursorAuthor := ""
	if cursor != "" {
		decoded, err := decodeSpaceWriterCursor(cursor)
		if err != nil {
			return spaceInvalidRequest(e)
		}
		cursorAuthor = decoded.Author
	}
	var writers []models.SpaceWriter
	query := s.db.Client().WithContext(ctx).Where("space = ?", spaceRef.String()).Order("author ASC")
	if cursorAuthor != "" {
		query = query.Where("author > ?", cursorAuthor)
	}
	if err := query.Limit(limit + 1).Find(&writers).Error; err != nil {
		return spaceInternalError(e)
	}
	if len(writers) == 0 && cursorAuthor == "" {
		var configured models.SimpleSpace
		if err := s.db.Client().WithContext(ctx).Where("uri = ?", spaceRef.String()).First(&configured).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return spaceJSONError(e, http.StatusBadRequest, "SpaceNotFound")
		} else if err != nil {
			return spaceInternalError(e)
		}
	}
	hasMore := len(writers) > limit
	if hasMore {
		writers = writers[:limit]
	}
	repos := make([]ComAtprotoSpaceListReposRepoRef, 0, len(writers))
	for _, writer := range writers {
		ref := ComAtprotoSpaceListReposRepoRef{DID: writer.Author, Rev: writer.Rev, Hash: spaceHashHex(writer.Hash)}
		// A locally tracked writer may have been registered before its notification
		// head was persisted. Fill missing metadata from the current local repo,
		// but never enumerate SimpleSpaceMember rows here: this is the writer set.
		if ref.Rev == "" || ref.Hash == "" {
			var repo models.SpaceRepo
			if err := s.db.Client().WithContext(ctx).Where("space = ? AND author = ?", spaceRef.String(), writer.Author).First(&repo).Error; err == nil {
				if ref.Rev == "" {
					ref.Rev = repo.Rev
				}
				if ref.Hash == "" {
					ref.Hash = spaceHashHex(repo.LtHash)
				}
			}
		}
		repos = append(repos, ref)
	}
	response := ComAtprotoSpaceListReposResponse{Repos: repos}
	if hasMore && len(repos) != 0 {
		next := encodeSpaceWriterCursor(repos[len(repos)-1].DID)
		response.Cursor = &next
	}
	return e.JSON(http.StatusOK, response)
}
