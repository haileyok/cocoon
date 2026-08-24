package server

import (
	"encoding/base64"
	"encoding/json"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSyncListBlobsResponse struct {
	Cursor *string  `json:"cursor,omitempty"`
	Cids   []string `json:"cids"`
}

type syncListBlobsCursor struct {
	CreatedAt string `json:"created_at"`
	ID        uint   `json:"id,omitempty"`
	CID       string `json:"cid,omitempty"`
	// RawCID is populated only while scanning a grouped query. Keeping the
	// database value here lets the cursor advance past malformed CID rows too;
	// it is never serialized into a public cursor.
	RawCID []byte `json:"-"`
}

type syncListBlobsCandidate struct {
	CID       []byte `gorm:"column:cid"`
	CreatedAt string `gorm:"column:created_at"`
	ID        uint   `gorm:"column:id"`
}

func encodeSyncListBlobsCursor(createdAt string, id uint) string {
	data, _ := json.Marshal(syncListBlobsCursor{CreatedAt: createdAt, ID: id})
	return base64.RawURLEncoding.EncodeToString(data)
}

func encodeSyncListBlobsLogicalCursor(candidate syncListBlobsCandidate) string {
	data, _ := json.Marshal(syncListBlobsCursor{
		CreatedAt: candidate.CreatedAt,
		ID:        candidate.ID,
		CID:       cidString(candidate.CID),
	})
	return base64.RawURLEncoding.EncodeToString(data)
}

func syncListBlobsCursorForCandidate(candidate syncListBlobsCandidate) syncListBlobsCursor {
	return syncListBlobsCursor{
		CreatedAt: candidate.CreatedAt,
		ID:        candidate.ID,
		CID:       cidString(candidate.CID),
		RawCID:    append([]byte(nil), candidate.CID...),
	}
}

// decodeSyncListBlobsCursor accepts the opaque cursors emitted by this handler
// and timestamp-only cursors emitted by older versions. Legacy cursors cannot
// disambiguate equal timestamps, but accepting them avoids breaking clients
// already holding a cursor while all newly emitted cursors are logical-CID
// cursors that do not split duplicate generations.
func decodeSyncListBlobsCursor(raw string) (syncListBlobsCursor, bool) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err == nil {
		var cursor syncListBlobsCursor
		if json.Unmarshal(data, &cursor) == nil && cursor.CreatedAt != "" {
			return cursor, false
		}
	}
	return syncListBlobsCursor{CreatedAt: raw}, true
}

func (s *Server) handleSyncListBlobs(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleSyncListBlobs")

	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	// TODO: add tid param
	limit, err := getLimitFromContext(e, 500)
	if err != nil || limit < 1 || limit > 1000 {
		return helpers.InputError(e, nil)
	}

	cursorRaw := e.QueryParam("cursor")
	var cursor syncListBlobsCursor
	legacyCursor := false
	if cursorRaw != "" {
		cursor, legacyCursor = decodeSyncListBlobsCursor(cursorRaw)
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find user for requested blobs", "error", err)
		return helpers.InputError(e, nil)
	}

	status := urepo.Status()
	if status != nil {
		if *status == "deactivated" {
			return helpers.InputError(e, to.StringPtr("RepoDeactivated"))
		}
	}

	// Blob.RefCount is the public-repository reference count. Permissioned Space
	// references live in space_blob_refs and intentionally do not make an upload
	// visible through this unauthenticated public sync endpoint.
	//
	// Grouping by CID before applying the limit is important: Blob rows are
	// generations, while this endpoint exposes logical CIDs. MAX(created_at) and
	// MAX(id) preserve the existing newest-first order without using a
	// database-specific DISTINCT ON/window-function query.
	const candidateBatchSize = 1001
	var after *syncListBlobsCursor
	if cursorRaw != "" {
		after = &cursor
	}
	cstrs := make([]string, 0, limit+1)
	var lastReturned syncListBlobsCandidate
	for {
		query := s.db.Client().WithContext(ctx).
			Model(&models.Blob{}).
			Select("cid, MAX(created_at) AS created_at, MAX(id) AS id").
			Where("did = ? AND ref_count > 0", did).
			Group("cid").
			Order("MAX(created_at) DESC, MAX(id) DESC, cid DESC")

		if after != nil {
			switch {
			case len(after.RawCID) > 0 || after.CID != "":
				rawCID := after.RawCID
				if len(rawCID) == 0 {
					parsed, parseErr := cid.Parse(after.CID)
					if parseErr != nil {
						return helpers.InputError(e, nil)
					}
					rawCID = parsed.Bytes()
				}
				query = query.Having("(MAX(created_at) < ? OR (MAX(created_at) = ? AND (MAX(id) < ? OR (MAX(id) = ? AND cid < ?))))", after.CreatedAt, after.CreatedAt, after.ID, after.ID, rawCID)
			case legacyCursor:
				query = query.Having("MAX(created_at) < ?", after.CreatedAt)
			default:
				// This is an opaque cursor emitted by the immediately previous
				// generation-based implementation. Keep accepting it for clients
				// that already hold one, while all new cursors use the logical CID
				// tie-breaker above.
				query = query.Having("(MAX(created_at) < ? OR (MAX(created_at) = ? AND MAX(id) < ?))", after.CreatedAt, after.CreatedAt, after.ID)
			}
		}

		var candidates []syncListBlobsCandidate
		if err := query.Limit(candidateBatchSize).Find(&candidates).Error; err != nil {
			logger.Error("error getting records", "error", err)
			return helpers.ServerError(e, nil)
		}
		if len(candidates) == 0 {
			break
		}

		var scanned syncListBlobsCandidate
		for _, candidate := range candidates {
			scanned = candidate
			ready, readyErr := s.selectReadyBlob(ctx, did, candidate.CID, true)
			if readyErr != nil {
				logger.Error("error looking up blob", "error", readyErr)
				return helpers.ServerError(e, nil)
			}
			if ready == nil {
				continue
			}
			parsed, parseErr := cid.Cast(candidate.CID)
			if parseErr != nil {
				// selectReadyBlob normally rejects malformed CIDs while checking
				// SQLite content/S3 identity, but keep the wire response guarded.
				logger.Error("error casting ready cid", "error", parseErr)
				continue
			}
			cstrs = append(cstrs, parsed.String())
			if len(cstrs) <= limit {
				lastReturned = candidate
			}
			if len(cstrs) > limit {
				break
			}
		}

		if len(cstrs) > limit {
			break
		}
		if len(candidates) < candidateBatchSize {
			break
		}
		// Continue from the last grouped candidate, including malformed rows,
		// so invalid CIDs cannot cause an empty intermediate page or a loop.
		next := syncListBlobsCursorForCandidate(scanned)
		after = &next
	}

	hasMore := len(cstrs) > limit
	if hasMore {
		cstrs = cstrs[:limit]
	}

	var newcursor *string
	if hasMore {
		next := encodeSyncListBlobsLogicalCursor(lastReturned)
		newcursor = &next
	}

	return e.JSON(200, ComAtprotoSyncListBlobsResponse{
		Cursor: newcursor,
		Cids:   cstrs,
	})
}
