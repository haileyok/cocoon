package server

import (
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerCreateInviteCodesRequest struct {
	CodeCount   *int      `json:"codeCount,omitempty"`
	UseCount    int       `json:"useCount" validate:"required"`
	ForAccounts *[]string `json:"forAccounts,omitempty"`
}

type ComAtprotoServerCreateInviteCodesResponse []ComAtprotoServerCreateInviteCodesItem

type ComAtprotoServerCreateInviteCodesItem struct {
	Account string   `json:"account"`
	Codes   []string `json:"codes"`
}

func (s *Server) handleCreateInviteCodes(e echo.Context) error {
	var req ComAtprotoServerCreateInviteCodesRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		s.logger.Error("error validating", "error", err)
		return helpers.InputError(e, nil)
	}

	if req.CodeCount == nil {
		req.CodeCount = to.IntPtr(1)
	}

	if req.ForAccounts == nil {
		req.ForAccounts = to.StringSlicePtr([]string{"admin"})
	}

	var codes []ComAtprotoServerCreateInviteCodesItem

	for _, did := range *req.ForAccounts {
		var ics []string

		for range *req.CodeCount {
			ic := uuid.NewString()
			ics = append(ics, ic)

			if err := s.db.Create(&models.InviteCode{
				Code:              ic,
				Did:               did,
				RemainingUseCount: req.UseCount,
			}, nil).Error; err != nil {
				s.logger.Error("error creating invite code", "error", err)
				return helpers.ServerError(e, nil)
			}
		}

		codes = append(codes, ComAtprotoServerCreateInviteCodesItem{
			Account: did,
			Codes:   ics,
		})
	}

	return e.JSON(200, codes)
}
