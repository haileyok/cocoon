package server

import (
	"time"

	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleAccount(e echo.Context) error {
	repo, sess, err := s.getSessionRepoOrErr(e)
	if err != nil {
		return e.Redirect(303, "/account/signin")
	}

	oldestPossibleSession := time.Now().Add(constants.ConfidentialClientSessionLifetime)

	var tokens []provider.OauthToken
	if err := s.db.Raw("SELECT * FROM oauth_tokens WHERE sub = ? AND created_at < ? ORDER BY created_at ASC", nil, repo.Repo.Did, oldestPossibleSession).Scan(&tokens).Error; err != nil {
		s.logger.Error("couldnt fetch oauth sessions for account", "did", repo.Repo.Did, "error", err)
		sess.AddFlash("Unable to fetch sessions. See server logs for more details.", "error")
		sess.Save(e.Request(), e.Response())
		return e.Render(200, "account.html", map[string]any{
			"flashes": getFlashesFromSession(e, sess),
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

	tokenInfo := []map[string]string{}
	for _, t := range tokens {
		tokenInfo = append(tokenInfo, map[string]string{
			"ClientId":  t.ClientId,
			"CreatedAt": t.CreatedAt.Format("02 Jan 06 15:04 MST"),
			"UpdatedAt": t.CreatedAt.Format("02 Jan 06 15:04 MST"),
			"ExpiresAt": t.CreatedAt.Format("02 Jan 06 15:04 MST"),
			"Token":     t.Token,
			"Ip":        t.Ip,
		})
	}

	return e.Render(200, "account.html", map[string]any{
		"Repo":    repo,
		"Tokens":  tokenInfo,
		"flashes": getFlashesFromSession(e, sess),
	})
}
