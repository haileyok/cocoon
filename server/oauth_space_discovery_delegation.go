package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// ComAtprotoSpaceListSpacesSpaceView is the pinned listSpaces spaceView.
type ComAtprotoSpaceListSpacesSpaceView struct {
	URI string `json:"uri"`
}

// ComAtprotoSpaceListSpacesOutput is the pinned listSpaces output shape.
type ComAtprotoSpaceListSpacesOutput struct {
	Cursor *string                              `json:"cursor,omitempty"`
	Spaces []ComAtprotoSpaceListSpacesSpaceView `json:"spaces"`
}

func oauthAllowsWholeSpaceRead(principal *OAuthPrincipal, ref space.SpaceURI) bool {
	if principal == nil {
		return false
	}
	if principal.Legacy {
		return principal.Subject != ""
	}
	for _, raw := range principal.Scopes {
		grant, err := scopes.Parse(raw)
		if err != nil || grant.Resource != scopes.ResourceSpace {
			continue
		}
		if grant.MatchesSpace(ref, principal.Subject) {
			for _, action := range grant.Actions {
				if action == "read" {
					return true
				}
			}
		}
	}
	return false
}

func parseSpaceListFilter(e echo.Context) (spaceType, authority, cursor string, limit int, err error) {
	spaceType = e.QueryParam("type")
	if spaceType != "" {
		parsed, parseErr := syntax.ParseNSID(spaceType)
		if parseErr != nil || string(parsed) != spaceType {
			return "", "", "", 0, errors.New("invalid space type")
		}
	}
	authority = e.QueryParam("did")
	if authority != "" {
		parsed, parseErr := syntax.ParseDID(authority)
		if parseErr != nil || string(parsed) != authority {
			return "", "", "", 0, errors.New("invalid authority DID")
		}
	}
	cursor = e.QueryParam("cursor")
	limit = 50
	if raw := e.QueryParam("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return "", "", "", 0, errors.New("limit must be between 1 and 100")
		}
	}
	return spaceType, authority, cursor, limit, nil
}

func (s *Server) handleSpaceListSpaces(e echo.Context) error {
	principal, err := spaceOAuthPrincipal(e)
	if err != nil {
		return spaceOAuthUnauthorized(e, err)
	}
	spaceType, authority, cursor, limit, err := parseSpaceListFilter(e)
	if err != nil {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	ctx := e.Request().Context()
	var rows []models.SpaceRepo
	if s.db == nil {
		return spaceOAuthServerError(e, errors.New("database is unavailable"))
	}
	if err := s.db.Client().WithContext(ctx).Where("author = ?", principal.Subject).Order("space ASC").Find(&rows).Error; err != nil {
		return spaceOAuthServerError(e, err)
	}

	// Legacy access tokens are the reference implementation's broad auth mode;
	// they may discover the caller's own Spaces. Granular OAuth tokens require
	// an explicit whole-space read grant.
	hasReadGrant := principal.Legacy
	for _, raw := range principal.Scopes {
		grant, parseErr := scopes.Parse(raw)
		if parseErr == nil && grant.Resource == scopes.ResourceSpace {
			for _, action := range grant.Actions {
				if action == "read" {
					hasReadGrant = true
					break
				}
			}
		}
		if hasReadGrant {
			break
		}
	}
	if !hasReadGrant {
		return helpers.InsufficientScopeError(e, "space:*?action=read")
	}

	matching := 0
	spaces := make([]ComAtprotoSpaceListSpacesSpaceView, 0, min(limit, len(rows)))
	for _, row := range rows {
		ref, parseErr := space.ParseSpaceURI(row.Space)
		if parseErr != nil || ref.String() != row.Space {
			continue
		}
		if spaceType != "" && string(ref.SpaceType) != spaceType {
			continue
		}
		if authority != "" && string(ref.AuthorityDID) != authority {
			continue
		}
		if cursor != "" && row.Space <= cursor {
			continue
		}
		matching++
		if !oauthAllowsWholeSpaceRead(principal, ref) {
			continue
		}
		if len(spaces) < limit {
			spaces = append(spaces, ComAtprotoSpaceListSpacesSpaceView{URI: ref.String()})
		}
	}
	if matching > 0 && len(spaces) == 0 {
		return helpers.InsufficientScopeError(e, "space:*?action=read")
	}
	var next *string
	if len(spaces) == limit {
		last := spaces[len(spaces)-1].URI
		for _, row := range rows {
			ref, parseErr := space.ParseSpaceURI(row.Space)
			if parseErr != nil || ref.String() != row.Space || row.Space <= last {
				continue
			}
			if spaceType != "" && string(ref.SpaceType) != spaceType {
				continue
			}
			if authority != "" && string(ref.AuthorityDID) != authority {
				continue
			}
			if !oauthAllowsWholeSpaceRead(principal, ref) {
				continue
			}
			next = &last
			break
		}
	}
	return e.JSON(http.StatusOK, ComAtprotoSpaceListSpacesOutput{Cursor: next, Spaces: spaces})
}

func (s *Server) handleSpaceGetDelegationToken(e echo.Context) error {
	principal, err := spaceOAuthPrincipal(e)
	if err != nil {
		return spaceOAuthUnauthorized(e, err)
	}
	rawSpace := e.QueryParam("space")
	if rawSpace == "" {
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	ref, err := spaceOAuthParseRef(s, e, rawSpace)
	if err != nil {
		if strings.Contains(err.Error(), "space unavailable") {
			return spaceOAuthInputError(e, "SpaceNotFound")
		}
		return spaceOAuthInputError(e, "InvalidRequest")
	}
	allowed := false
	for _, raw := range principal.Scopes {
		grant, parseErr := scopes.Parse(raw)
		if parseErr == nil && grant.AllowsSpaceDelegation(ref, principal.Subject) {
			allowed = true
			break
		}
	}
	if !allowed {
		return helpers.InsufficientScopeError(e, "space:*?action=read")
	}

	var account *models.RepoActor
	if principal.Repo != nil && principal.Repo.Repo.Did == principal.Subject {
		account = principal.Repo
	} else if s.db != nil {
		account, err = s.getRepoActorByDid(e.Request().Context(), principal.Subject)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return spaceOAuthInputError(e, "RepoNotFound")
			}
			return spaceOAuthServerError(e, err)
		}
	}
	if account == nil || account.Repo.Did != principal.Subject {
		return spaceOAuthInputError(e, "RepoNotFound")
	}
	key, err := atcrypto.ParsePrivateBytesK256(account.Repo.SigningKey)
	if err != nil {
		return spaceOAuthServerError(e, err)
	}
	signer, err := space.NewAtprotoSigner(key)
	if err != nil {
		return spaceOAuthServerError(e, err)
	}
	token, err := space.CreateDelegationToken(space.CreateSpaceTokenOptions{
		Iss:       principal.Subject,
		Sub:       ref.String(),
		Aud:       string(ref.AuthorityDID) + space.SpaceHostAudienceSuffix,
		ExpiresIn: space.DelegationLifetime,
	}, signer)
	if err != nil {
		return spaceOAuthServerError(e, err)
	}
	return e.JSON(http.StatusOK, ComAtprotoSpaceGetDelegationTokenOutput{Token: token})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
