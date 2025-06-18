package server

import (
	"time"

	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleAccount(e echo.Context) error {
	repo, sess, err := s.getSessionRepoOrErr(e)
	if err != nil {
		return e.Redirect(303, "/account/signin")
	}

	now := time.Now()

	var tokens []provider.OauthToken
	if err := s.db.Raw("SELECT * FROM oauth_tokens WHERE sub = ? AND expires_at <= ? ORDER BY created_at ASC", nil, repo.Repo.Did, now).Scan(&tokens).Error; err != nil {
		s.logger.Error("couldnt fetch oauth sessions for account", "did", repo.Repo.Did, "error", err)
		sess.AddFlash("Unable to fetch sessions. See server logs for more details.", "error")
		sess.Save(e.Request(), e.Response())
		return e.Render(200, "account.html", map[string]any{
			"flashes": getFlashesFromSession(e, sess),
		})
	}

	return e.Render(200, "account.html", map[string]any{
		"Repo":    repo,
		"Tokens":  tokens,
		"flashes": getFlashesFromSession(e, sess),
	})
}
