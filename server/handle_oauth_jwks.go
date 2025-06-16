package server

import "github.com/labstack/echo/v4"

type OauthJwksResponse struct {
	Keys []any `json:"keys"`
}

// TODO: ?
func (s *Server) handleOauthJwks(e echo.Context) error {
	return e.JSON(200, OauthJwksResponse{Keys: []any{}})
}
