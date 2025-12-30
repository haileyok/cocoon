package server

import (
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSyncListReposResponse struct {
	Cursor *string                           `json:"cursor,omitempty"`
	Repos  []ComAtprotoSyncListReposRepoItem `json:"repos"`
}

type ComAtprotoSyncListReposRepoItem struct {
	Did    string  `json:"did"`
	Head   string  `json:"head"`
	Rev    string  `json:"rev"`
	Active bool    `json:"active"`
	Status *string `json:"status,omitempty"`
}

// TODO: paginate this bitch
func (s *Server) handleListRepos(e echo.Context) error {
	ctx := e.Request().Context()

	var repos []models.Repo
	if err := s.db.Raw(ctx, "SELECT * FROM repos ORDER BY created_at DESC LIMIT 500", nil).Scan(&repos).Error; err != nil {
		return err
	}

	var items []ComAtprotoSyncListReposRepoItem
	for _, r := range repos {
		c, err := cid.Cast(r.Root)
		if err != nil {
			return err
		}

		items = append(items, ComAtprotoSyncListReposRepoItem{
			Did:    r.Did,
			Head:   c.String(),
			Rev:    r.Rev,
			Active: r.Active(),
			Status: r.Status(),
		})
	}

	return e.JSON(200, ComAtprotoSyncListReposResponse{
		Cursor: nil,
		Repos:  items,
	})
}
