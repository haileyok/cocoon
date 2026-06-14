package server

import (
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoGetRecordResponse struct {
	Uri   string         `json:"uri"`
	Cid   string         `json:"cid"`
	Value map[string]any `json:"value"`
}

func (s *Server) handleRepoGetRecord(e echo.Context) error {
	ctx := e.Request().Context()

	repo := e.QueryParam("repo")
	collection := e.QueryParam("collection")
	rkey := e.QueryParam("rkey")
	cidstr := e.QueryParam("cid")

	params := []any{repo, collection, rkey}
	cidquery := ""

	if cidstr != "" {
		c, err := syntax.ParseCID(cidstr)
		if err != nil {
			return err
		}
		params = append(params, c.String())
		cidquery = " AND cid = ?"
	}

	var record models.Record
	if err := s.db.Raw(ctx, "SELECT * FROM records WHERE did = ? AND nsid = ? AND rkey = ?"+cidquery, nil, params...).Scan(&record).Error; err != nil {
		return helpers.ServerError(e, nil)
	}

	// A zero-row Scan leaves record zero-valued without an error, so an empty
	// Did means the record is not stored on this PDS.
	if record.Did == "" {
		uri := "at://" + repo + "/" + collection + "/" + rkey
		return e.JSON(400, map[string]string{
			"error":   "RecordNotFound",
			"message": "Could not locate record: " + uri,
		})
	}

	val, err := atdata.UnmarshalCBOR(record.Value)
	if err != nil {
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, ComAtprotoRepoGetRecordResponse{
		Uri:   "at://" + record.Did + "/" + record.Nsid + "/" + record.Rkey,
		Cid:   record.Cid,
		Value: val,
	})
}
