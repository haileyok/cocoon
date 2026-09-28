package server

import (
	"errors"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleAccount(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAccount")

	repo, sess, accounts, err := s.getSessionRepoAndAccountsOrErr(e)
	if err != nil {
		if !errors.Is(err, ErrSessionUnauthenticated) {
			return helpers.ServerError(e, nil)
		}
		return e.Redirect(303, "/account/signin")
	}

	apps, err := s.loadAccountApps(ctx, repo, time.Now())
	if err != nil {
		logger.Error("couldnt fetch oauth sessions for account", "did", repo.Repo.Did, "error", err)
		sess.AddFlash("Unable to load your app sessions. See server logs for more details.", "error")
		apps = nil
	}

	sessionCount := 0
	for _, a := range apps {
		sessionCount += len(a.Sessions)
	}

	var twoFactorMethods int64
	if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM two_factor_credentials WHERE did = ?", nil, repo.Repo.Did).Scan(&twoFactorMethods).Error; err != nil {
		logger.Error("counting two factor methods", "did", repo.Repo.Did, "error", err)
	}

	return e.Render(200, "account.html", map[string]any{
		"Repo":             repo,
		"Apps":             apps,
		"SessionCount":     sessionCount,
		"TwoFactorMethods": twoFactorMethods,
		"EmailTwoFactor":   repo.TwoFactorType != models.TwoFactorTypeNone,
		"flashes":          getFlashesFromSession(e, sess),
		"Accounts":         accounts,
		"ActiveDid":        repo.Repo.Did,
		"Hostname":         s.config.Hostname,
	})
}
