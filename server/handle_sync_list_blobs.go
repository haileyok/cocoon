package server

import (
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSyncListBlobsResponse struct {
	Cursor *string  `json:"cursor,omitempty"`
	Cids   []string `json:"cids"`
}

func (s *Server) handleSyncListBlobs(e echo.Context) error {
	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	// TODO: add tid param
	cursor := e.QueryParam("cursor")
	limit, err := getLimitFromContext(e, 50)
	if err != nil {
		return helpers.InputError(e, nil)
	}

	cursorquery := ""

	params := []any{did}
	if cursor != "" {
		params = append(params, cursor)
		cursorquery = "AND created_at < ?"
	}
	params = append(params, limit)

	var blobs []models.Blob
	if err := s.db.Raw("SELECT * FROM blobs WHERE did = ? "+cursorquery+" ORDER BY created_at DESC LIMIT ?", nil, params...).Scan(&blobs).Error; err != nil {
		s.logger.Error("error getting records", "error", err)
		return helpers.ServerError(e, nil)
	}

	var cstrs []string
	for _, b := range blobs {
		c, err := cid.Cast(b.Cid)
		if err != nil {
			s.logger.Error("error casting cid", "error", err)
			return helpers.ServerError(e, nil)
		}
		cstrs = append(cstrs, c.String())
	}

	var newcursor *string
	if len(blobs) == 50 {
		newcursor = &blobs[len(blobs)-1].CreatedAt
	}

	return e.JSON(200, ComAtprotoSyncListBlobsResponse{
		Cursor: newcursor,
		Cids:   cstrs,
	})
}
