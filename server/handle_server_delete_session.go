package server

import (
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleDeleteSession(e echo.Context) error {
	ctx := e.Request().Context()

	token := e.Get("token").(string)

	var acctok models.Token
	if err := s.db.Raw(ctx, "DELETE FROM tokens WHERE token = ? RETURNING *", nil, token).Scan(&acctok).Error; err != nil {
		s.logger.Error("error deleting access token from db", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE token = ?", nil, acctok.RefreshToken).Error; err != nil {
		s.logger.Error("error deleting refresh token from db", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
