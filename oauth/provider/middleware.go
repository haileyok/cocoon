package provider

import (
	"github.com/labstack/echo/v4"
)

func (p *Provider) BaseMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		e.Response().Header().Set("cache-control", "no-store")
		e.Response().Header().Set("pragma", "no-cache")

		nonce := p.NextNonce()
		if nonce != "" {
			e.Response().Header().Set("DPoP-Nonce", nonce)
			e.Response().Header().Add("access-control-expose-headers", "DPoP-Nonce")
		}

		return next(e)
	}
}
