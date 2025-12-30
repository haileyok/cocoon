package server

import (
	"strconv"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRepoListRecordsRequest struct {
	Repo       string `query:"repo" validate:"required"`
	Collection string `query:"collection" validate:"required,atproto-nsid"`
	Limit      int64  `query:"limit"`
	Cursor     string `query:"cursor"`
	Reverse    bool   `query:"reverse"`
}

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
	ctx := e.Request().Context()

	var req ComAtprotoRepoListRecordsRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("could not bind list records request", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	if req.Limit <= 0 {
		req.Limit = 50
	} else if req.Limit > 100 {
		req.Limit = 100
	}

	limit, err := getLimitFromContext(e, 50)
	if err != nil {
		return helpers.InputError(e, nil)
	}

	sort := "DESC"
	dir := "<"
	cursorquery := ""

	if req.Reverse {
		sort = "ASC"
		dir = ">"
	}

	did := req.Repo
	if _, err := syntax.ParseDID(did); err != nil {
		actor, err := s.getActorByHandle(ctx, req.Repo)
		if err != nil {
			return helpers.InputError(e, to.StringPtr("RepoNotFound"))
		}
		did = actor.Did
	}

	params := []any{did, req.Collection}
	if req.Cursor != "" {
		params = append(params, req.Cursor)
		cursorquery = "AND created_at " + dir + " ?"
	}
	params = append(params, limit)

	var records []models.Record
	if err := s.db.Raw(ctx, "SELECT * FROM records WHERE did = ? AND nsid = ? "+cursorquery+" ORDER BY created_at "+sort+" limit ?", nil, params...).Scan(&records).Error; err != nil {
		s.logger.Error("error getting records", "error", err)
		return helpers.ServerError(e, nil)
	}

	items := []ComAtprotoRepoListRecordsRecordItem{}
	for _, r := range records {
		val, err := atdata.UnmarshalCBOR(r.Value)
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
