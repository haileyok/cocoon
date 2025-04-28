package server

import (
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type ComAtprotoRepoDescribeRepoResponse struct {
	Did             string          `json:"did"`
	Handle          string          `json:"handle"`
	DidDoc          identity.DidDoc `json:"didDoc"`
	Collections     []string        `json:"collections"`
	HandleIsCorrect bool            `json:"handleIsCorrect"`
}

func (s *Server) handleDescribeRepo(e echo.Context) error {
	did := e.QueryParam("repo")
	repo, err := s.getRepoActorByDid(did)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return helpers.InputError(e, to.StringPtr("RepoNotFound"))
		}

		s.logger.Error("error looking up repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	handleIsCorrect := true

	diddoc, err := s.passport.FetchDoc(e.Request().Context(), repo.Repo.Did)
	if err != nil {
		s.logger.Error("error fetching diddoc", "error", err)
		return helpers.ServerError(e, nil)
	}

	dochandle := ""
	for _, aka := range diddoc.AlsoKnownAs {
		if strings.HasPrefix(aka, "at://") {
			dochandle = strings.TrimPrefix(aka, "at://")
			break
		}
	}

	if repo.Handle != dochandle {
		handleIsCorrect = false
	}

	if handleIsCorrect {
		resolvedDid, err := s.passport.ResolveHandle(e.Request().Context(), repo.Handle)
		if err != nil {
			e.Logger().Error("error resolving handle", "error", err)
			return helpers.ServerError(e, nil)
		}

		if resolvedDid != repo.Repo.Did {
			handleIsCorrect = false
		}
	}

	var records []models.Record
	if err := s.db.Raw("SELECT DISTINCT(nsid) FROM records WHERE did = ?", repo.Repo.Did).Scan(&records).Error; err != nil {
		s.logger.Error("error getting collections", "error", err)
		return helpers.ServerError(e, nil)
	}

	var collections []string = make([]string, 0)
	for _, r := range records {
		collections = append(collections, r.Nsid)
	}

	return e.JSON(200, ComAtprotoRepoDescribeRepoResponse{
		Did:             repo.Repo.Did,
		Handle:          repo.Handle,
		DidDoc:          *diddoc,
		Collections:     collections,
		HandleIsCorrect: handleIsCorrect,
	})
}
