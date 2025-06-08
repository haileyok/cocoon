package server

import (
	"strconv"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/data"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoListRecordsResponse struct {
	Cursor  *string                               `json:"cursor,omitempty"`
	Records []ComAtprotoRepoListRecordsRecordItem `json:"records"`
}

type ComAtprotoRepoListRecordsRecordItem struct {
	Uri   string         `json:"uri"`
	Cid   string         `json:"cid"`
	Value map[string]any `json:"value"`
}

func getLimitFromContext(e echo.Context, def int) (int, error) {
	limit := def
	limitstr := e.QueryParam("limit")

	if limitstr != "" {
		l64, err := strconv.ParseInt(limitstr, 10, 32)
		if err != nil {
			return 0, err
		}
		limit = int(l64)
	}

	return limit, nil
}

func (s *Server) handleListRecords(e echo.Context) error {
	did := e.QueryParam("repo")
	collection := e.QueryParam("collection")
	cursor := e.QueryParam("cursor")
	reverse := e.QueryParam("reverse")
	limit, err := getLimitFromContext(e, 50)
	if err != nil {
		return helpers.InputError(e, nil)
	}

	sort := "DESC"
	dir := "<"
	cursorquery := ""

	if strings.ToLower(reverse) == "true" {
		sort = "ASC"
		dir = ">"
	}

	params := []any{did, collection}
	if cursor != "" {
		params = append(params, cursor)
		cursorquery = "AND created_at " + dir + " ?"
	}
	params = append(params, limit)

	var records []models.Record
	if err := s.db.Raw("SELECT * FROM records WHERE did = ? AND nsid = ? "+cursorquery+" ORDER BY created_at "+sort+" limit ?", nil, params...).Scan(&records).Error; err != nil {
		s.logger.Error("error getting records", "error", err)
		return helpers.ServerError(e, nil)
	}

	items := []ComAtprotoRepoListRecordsRecordItem{}
	for _, r := range records {
		val, err := data.UnmarshalCBOR(r.Value)
		if err != nil {
			return err
		}

		items = append(items, ComAtprotoRepoListRecordsRecordItem{
			Uri:   "at://" + r.Did + "/" + r.Nsid + "/" + r.Rkey,
			Cid:   r.Cid,
			Value: val,
		})
	}

	var newcursor *string
	if len(records) == limit {
		newcursor = to.StringPtr(records[len(records)-1].CreatedAt)
	}

	return e.JSON(200, ComAtprotoRepoListRecordsResponse{
		Cursor:  newcursor,
		Records: items,
	})
}
