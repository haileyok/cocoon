package server

import (
	"strconv"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

// Admin account visibility endpoints.
//
// Plain /admin/* routes gated by the same Basic-auth middleware as the admin
// invite-code XRPCs: management operations, not protocol ones, so they don't
// squat made-up NSIDs in com.atproto.*.

const (
	adminAccountsDefaultLimit = 100
	adminAccountsMaxLimit     = 500
)

type AdminAccountsListQuery struct {
	Limit  string `query:"limit"`
	Offset string `query:"offset"`
}

type AdminAccountSummary struct {
	Did       string `json:"did"`
	Handle    string `json:"handle"`
	Email     string `json:"email"`
	Active    bool   `json:"active"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
}

type AdminAccountDetail struct {
	Did            string `json:"did"`
	Handle         string `json:"handle"`
	Email          string `json:"email"`
	EmailConfirmed bool   `json:"emailConfirmed"`
	Active         bool   `json:"active"`
	Status         string `json:"status"`
	TwoFactorType  string `json:"twoFactorType"`
	CreatedAt      string `json:"createdAt"`
	Rev            string `json:"rev"`
}

// handleAdminAccounts lists accounts (repos joined to actors), most recent
// first, with derived active/status fields.
func (s *Server) handleAdminAccounts(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAdminAccounts")

	limit := adminAccountsDefaultLimit
	if q := e.QueryParam("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			return helpers.InputError(e, to.StringPtr("limit must be a positive integer"))
		}
		if n > adminAccountsMaxLimit {
			n = adminAccountsMaxLimit
		}
		limit = n
	}

	offset := 0
	if q := e.QueryParam("offset"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 0 {
			return helpers.InputError(e, to.StringPtr("offset must be a non-negative integer"))
		}
		offset = n
	}

	var repos []models.RepoActor
	if err := s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did ORDER BY r.created_at DESC LIMIT ? OFFSET ?", nil, limit, offset).Scan(&repos).Error; err != nil {
		logger.Error("error listing accounts", "error", err)
		return helpers.ServerError(e, nil)
	}

	out := make([]AdminAccountSummary, 0, len(repos))
	for _, ra := range repos {
		status := ""
		if st := ra.Repo.Status(); st != nil {
			status = *st
		}
		out = append(out, AdminAccountSummary{
			Did:       ra.Repo.Did,
			Handle:    ra.Actor.Handle,
			Email:     ra.Repo.Email,
			Active:    ra.Repo.Active(),
			Status:    status,
			CreatedAt: ra.Repo.CreatedAt.Format(time.RFC3339),
		})
	}

	return e.JSON(200, out)
}

// handleAdminAccount returns the detailed record for a single DID.
func (s *Server) handleAdminAccount(e echo.Context) error {
	ctx := e.Request().Context()

	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, to.StringPtr("did is required"))
	}

	ra, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		return helpers.InputError(e, to.StringPtr("unable to find actor"))
	}

	status := ""
	if st := ra.Repo.Status(); st != nil {
		status = *st
	}

	return e.JSON(200, AdminAccountDetail{
		Did:            ra.Repo.Did,
		Handle:         ra.Actor.Handle,
		Email:          ra.Repo.Email,
		EmailConfirmed: ra.Repo.EmailConfirmedAt != nil,
		Active:         ra.Repo.Active(),
		Status:         status,
		TwoFactorType:  string(ra.Repo.TwoFactorType),
		CreatedAt:      ra.Repo.CreatedAt.Format(time.RFC3339),
		Rev:            ra.Repo.Rev,
	})
}
