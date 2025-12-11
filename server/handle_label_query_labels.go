package server

import (
	"github.com/labstack/echo/v4"
)

type Label struct {
	Ver *int    `json:"ver,omitempty"`
	Src string  `json:"src"`
	Uri string  `json:"uri"`
	Cid *string `json:"cid,omitempty"`
	Val string  `json:"val"`
	Neg *bool   `json:"neg,omitempty"`
	Cts string  `json:"cts"`
	Exp *string `json:"exp,omitempty"`
	Sig []byte  `json:"sig,omitempty"`
}

type ComAtprotoLabelQueryLabelsResponse struct {
	Cursor *string `json:"cursor,omitempty"`
	Labels []Label `json:"labels"`
}

func (s *Server) handleLabelQueryLabels(e echo.Context) error {
	svc := e.Request().Header.Get("atproto-proxy")
	if svc != "" || s.config.FallbackProxy != "" {
		return s.handleProxy(e)
	}

	return e.JSON(200, ComAtprotoLabelQueryLabelsResponse{
		Cursor: nil,
		Labels: []Label{},
	})
}
