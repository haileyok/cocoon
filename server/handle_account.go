package server

import (
	"errors"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/hako/durafmt"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleAccount(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAuth")

	repo, sess, accounts, err := s.getSessionRepoAndAccountsOrErr(e)
	if err != nil {
		if !errors.Is(err, ErrSessionUnauthenticated) {
			return helpers.ServerError(e, nil)
		}
		return e.Redirect(303, "/account/signin")
	}

	oldestPossibleSession := time.Now().Add(constants.ConfidentialClientSessionLifetime)

	var tokens []provider.OauthToken
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_tokens WHERE sub = ? AND created_at < ? ORDER BY created_at ASC", nil, repo.Repo.Did, oldestPossibleSession).Scan(&tokens).Error; err != nil {
		logger.Error("couldnt fetch oauth sessions for account", "did", repo.Repo.Did, "error", err)
		sess.AddFlash("Unable to fetch sessions. See server logs for more details.", "error")
		sess.Save(e.Request(), e.Response())
		return e.Render(200, "account.html", map[string]any{
			"Repo":      repo,
			"Tokens":    []map[string]string{},
			"flashes":   getFlashesFromSession(e, sess),
			"Accounts":  accounts,
			"ActiveDid": repo.Repo.Did,
		})
	}

	var filtered []provider.OauthToken
	for _, t := range tokens {
		ageRes := oauth.GetSessionAgeFromToken(t)
		if ageRes.SessionExpired {
			continue
		}
		filtered = append(filtered, t)
	}

	now := time.Now()

	tokenInfo := []map[string]string{}
	for _, t := range tokens {
		ageRes := oauth.GetSessionAgeFromToken(t)
		maxTime := constants.PublicClientSessionLifetime
		if t.ClientAuth.Method != "none" {
			maxTime = constants.ConfidentialClientSessionLifetime
		}

		var clientName string
		metadata, err := s.oauthProvider.ClientManager.GetClient(ctx, t.ClientId)
		if err != nil {
			clientName = t.ClientId
		} else {
			clientName = metadata.Metadata.ClientName
		}

		tokenInfo = append(tokenInfo, map[string]string{
			"ClientName":  clientName,
			"Age":         durafmt.Parse(ageRes.SessionAge).LimitFirstN(2).String(),
			"LastUpdated": durafmt.Parse(now.Sub(t.UpdatedAt)).LimitFirstN(2).String(),
			"ExpiresIn":   durafmt.Parse(now.Add(maxTime).Sub(now)).LimitFirstN(2).String(),
			"Token":       t.Token,
			"Ip":          t.Ip,
		})
	}

	return e.Render(200, "account.html", map[string]any{
		"Repo":      repo,
		"Tokens":    tokenInfo,
		"flashes":   getFlashesFromSession(e, sess),
		"Accounts":  accounts,
		"ActiveDid": repo.Repo.Did,
	})
}
