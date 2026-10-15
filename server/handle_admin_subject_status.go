package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// com.atproto.admin.defs#repoRef and the status fields of
// com.atproto.admin.updateSubjectStatus / getSubjectStatus. Only repo subjects
// are supported; record and blob subjects return an error.

type AdminRepoRef struct {
	Type string `json:"$type" validate:"required,atproto-nsid"`
	Did  string `json:"did" validate:"required,atproto-did"`
}

type AdminRecordRef struct {
	Type string `json:"$type" validate:"required,atproto-nsid"`
	Uri  string `json:"uri" validate:"required"`
}

type AdminBlobRef struct {
	Type string `json:"$type" validate:"required,atproto-nsid"`
	Did  string `json:"did" validate:"required,atproto-did"`
	Cid  string `json:"cid" validate:"required"`
}

type AdminStatusAttr struct {
	Applied *bool   `json:"applied" validate:"required"`
	Ref     *string `json:"ref,omitempty"`
}

type AdminUpdateSubjectStatusRequest struct {
	Subject     any              `json:"subject" validate:"required"`
	Takedown    *AdminStatusAttr `json:"takedown,omitempty"`
	Deactivated *AdminStatusAttr `json:"deactivated,omitempty"`
}

func (s *Server) handleAdminUpdateSubjectStatus(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAdminUpdateSubjectStatus")

	var req AdminUpdateSubjectStatusRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	did, err := adminRepoSubjectDid(req.Subject)
	if err != nil {
		return helpers.InputError(e, to.StringPtr("UnsupportedSubject"))
	}

	if req.Takedown != nil {
		if err := s.setRepoTakedown(ctx, did, *req.Takedown.Applied, req.Takedown.Ref); err != nil {
			logger.Error("error applying takedown", "did", did, "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	if req.Deactivated != nil {
		if err := s.setRepoDeactivated(ctx, did, *req.Deactivated.Applied); err != nil {
			logger.Error("error applying deactivation", "did", did, "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("error loading repo", "did", did, "error", err)
		return helpers.ServerError(e, nil)
	}

	takedown := adminTakedownStatus(urepo.Repo.TakedownRef)
	return e.JSON(200, map[string]any{
		"subject":     AdminRepoRef{Type: "com.atproto.admin.defs#repoRef", Did: did},
		"takedown":    takedown,
		"deactivated": &AdminStatusAttr{Applied: to.BoolPtr(urepo.Repo.Deactivated)},
	})
}

func (s *Server) handleAdminGetSubjectStatus(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAdminGetSubjectStatus")

	did := e.QueryParam("did")
	if did == "" {
		uri := e.QueryParam("uri")
		if uri != "" {
			return helpers.InputError(e, to.StringPtr("UnsupportedSubject"))
		}
		return helpers.InputError(e, to.StringPtr("InvalidRequest"))
	}
	if _, err := syntax.ParseDID(did); err != nil {
		return helpers.InputError(e, to.StringPtr("InvalidRequest"))
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return helpers.InputError(e, to.StringPtr("SubjectNotFound"))
	}
	if err != nil {
		logger.Error("error loading repo", "did", did, "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.JSON(200, map[string]any{
		"subject":     AdminRepoRef{Type: "com.atproto.admin.defs#repoRef", Did: did},
		"takedown":    adminTakedownStatus(urepo.Repo.TakedownRef),
		"deactivated": &AdminStatusAttr{Applied: to.BoolPtr(urepo.Repo.Deactivated)},
	})
}

// adminRepoSubjectDid returns the DID of a #repoRef subject. Record and blob
// subjects are not supported and return an error.
func adminRepoSubjectDid(subject any) (string, error) {
	switch sv := subject.(type) {
	case AdminRepoRef:
		if sv.Type != "" && sv.Type != "com.atproto.admin.defs#repoRef" {
			return "", fmt.Errorf("unsupported subject type %q", sv.Type)
		}
		if _, err := syntax.ParseDID(sv.Did); err != nil {
			return "", err
		}
		return sv.Did, nil
	case map[string]any:
		// echo binds unknown JSON objects as map[string]any
		typ, _ := sv["$type"].(string)
		did, _ := sv["did"].(string)
		if typ == "com.atproto.admin.defs#repoRef" {
			if _, err := syntax.ParseDID(did); err != nil {
				return "", err
			}
			return did, nil
		}
		return "", fmt.Errorf("unsupported subject type %q", typ)
	default:
		return "", fmt.Errorf("unsupported subject")
	}
}

func adminTakedownStatus(ref *string) *AdminStatusAttr {
	if ref == nil {
		return &AdminStatusAttr{Applied: to.BoolPtr(false)}
	}
	return &AdminStatusAttr{Applied: to.BoolPtr(true), Ref: ref}
}

// setRepoTakedown applies or clears a takedown: applied sets takedown_ref to
// ref (or a placeholder), clearing sets it to NULL.
func (s *Server) setRepoTakedown(ctx context.Context, did string, applied bool, ref *string) error {
	unlock := s.lockRepoWrite(did)
	defer unlock()

	if applied {
		r := "admin"
		if ref != nil && *ref != "" {
			r = *ref
		}
		if err := s.db.Exec(ctx, "UPDATE repos SET takedown_ref = ? WHERE did = ?", nil, r, did).Error; err != nil {
			return err
		}
	} else {
		if err := s.db.Exec(ctx, "UPDATE repos SET takedown_ref = NULL WHERE did = ?", nil, did).Error; err != nil {
			return err
		}
	}
	return nil
}

// setRepoDeactivated applies or clears account deactivation, matching what
// com.atproto.server.deactivateAccount (and activateAccount) do, and emits the
// matching #account firehose event.
func (s *Server) setRepoDeactivated(ctx context.Context, did string, applied bool) error {
	unlock := s.lockRepoWrite(did)
	defer unlock()

	if err := s.db.Exec(ctx, "UPDATE repos SET deactivated = ? WHERE did = ?", nil, applied, did).Error; err != nil {
		return err
	}

	var status *string
	if applied {
		status = to.StringPtr("deactivated")
	}
	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: !applied,
			Did:    did,
			Status: status,
			Seq:    time.Now().UnixMicro(), // TODO: bad puppy
			Time:   time.Now().Format(util.ISO8601),
		},
	})
	return nil
}
