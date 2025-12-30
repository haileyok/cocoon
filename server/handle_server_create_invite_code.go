package server

import (
	"github.com/google/uuid"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerCreateInviteCodeRequest struct {
	UseCount   int     `json:"useCount" validate:"required"`
	ForAccount *string `json:"forAccount,omitempty"`
}

type ComAtprotoServerCreateInviteCodeResponse struct {
	Code string `json:"code"`
}

func (s *Server) handleCreateInviteCode(e echo.Context) error {
	ctx := e.Request().Context()

	var req ComAtprotoServerCreateInviteCodeRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		s.logger.Error("error validating", "error", err)
		return helpers.InputError(e, nil)
	}

	ic := uuid.NewString()

	var acc string
	if req.ForAccount == nil {
		acc = "admin"
	} else {
		acc = *req.ForAccount
	}

	if err := s.db.Create(ctx, &models.InviteCode{
		Code:              ic,
		Did:               acc,
		RemainingUseCount: req.UseCount,
	}, nil).Error; err != nil {
		s.logger.Error("error creating invite code", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, ComAtprotoServerCreateInviteCodeResponse{
		Code: ic,
	})
}
