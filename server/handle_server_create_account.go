package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/repo"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/blockstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ComAtprotoServerCreateAccountRequest struct {
	Email      string  `json:"email" validate:"required,email"`
	Handle     string  `json:"handle" validate:"required,atproto-handle"`
	Did        *string `json:"did" validate:"atproto-did"`
	Password   string  `json:"password" validate:"required"`
	InviteCode string  `json:"inviteCode" validate:"required"`
}

type ComAtprotoServerCreateAccountResponse struct {
	AccessJwt  string `json:"accessJwt"`
	RefreshJwt string `json:"refreshJwt"`
	Handle     string `json:"handle"`
	Did        string `json:"did"`
}

func (s *Server) handleCreateAccount(e echo.Context) error {
	var request ComAtprotoServerCreateAccountRequest

	if err := e.Bind(&request); err != nil {
		s.logger.Error("error receiving request", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}

	request.Handle = strings.ToLower(request.Handle)

	if err := e.Validate(request); err != nil {
		s.logger.Error("error validating request", "endpoint", "com.atproto.server.createAccount", "error", err)

		var verr ValidationError
		if errors.As(err, &verr) {
			if verr.Field == "Email" {
				// TODO: what is this supposed to be? `InvalidEmail` isn't listed in doc
				return helpers.InputError(e, to.StringPtr("InvalidEmail"))
			}

			if verr.Field == "Handle" {
				return helpers.InputError(e, to.StringPtr("InvalidHandle"))
			}

			if verr.Field == "Password" {
				return helpers.InputError(e, to.StringPtr("InvalidPassword"))
			}

			if verr.Field == "InviteCode" {
				return helpers.InputError(e, to.StringPtr("InvalidInviteCode"))
			}
		}
	}

	// see if the handle is already taken
	_, err := s.getActorByHandle(request.Handle)
	if err != nil && err != gorm.ErrRecordNotFound {
		s.logger.Error("error looking up handle in db", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}
	if err == nil {
		return helpers.InputError(e, to.StringPtr("HandleNotAvailable"))
	}

	if did, err := s.passport.ResolveHandle(e.Request().Context(), request.Handle); err == nil && did != "" {
		return helpers.InputError(e, to.StringPtr("HandleNotAvailable"))
	}

	var ic models.InviteCode
	if err := s.db.Raw("SELECT * FROM invite_codes WHERE code = ?", nil, request.InviteCode).Scan(&ic).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return helpers.InputError(e, to.StringPtr("InvalidInviteCode"))
		}
		s.logger.Error("error getting invite code from db", "error", err)
		return helpers.ServerError(e, nil)
	}

	if ic.RemainingUseCount < 1 {
		return helpers.InputError(e, to.StringPtr("InvalidInviteCode"))
	}

	// see if the email is already taken
	_, err = s.getRepoByEmail(request.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		s.logger.Error("error looking up email in db", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}
	if err == nil {
		return helpers.InputError(e, to.StringPtr("EmailNotAvailable"))
	}

	// TODO: unsupported domains

	// TODO: did stuff

	k, err := crypto.GeneratePrivateKeyK256()
	if err != nil {
		s.logger.Error("error creating signing key", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}

	did, op, err := s.plcClient.CreateDID(k, "", request.Handle)
	if err != nil {
		s.logger.Error("error creating operation", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.plcClient.SendOperation(e.Request().Context(), did, op); err != nil {
		s.logger.Error("error sending plc op", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		s.logger.Error("error hashing password", "error", err)
		return helpers.ServerError(e, nil)
	}

	urepo := models.Repo{
		Did:                   did,
		CreatedAt:             time.Now(),
		Email:                 request.Email,
		EmailVerificationCode: to.StringPtr(fmt.Sprintf("%s-%s", helpers.RandomVarchar(6), helpers.RandomVarchar(6))),
		Password:              string(hashed),
		SigningKey:            k.Bytes(),
	}

	actor := models.Actor{
		Did:    did,
		Handle: request.Handle,
	}

	if err := s.db.Create(&urepo, nil).Error; err != nil {
		s.logger.Error("error inserting new repo", "error", err)
		return helpers.ServerError(e, nil)
	}

	bs := blockstore.New(did, s.db)
	r := repo.NewRepo(context.TODO(), did, bs)

	root, rev, err := r.Commit(context.TODO(), urepo.SignFor)
	if err != nil {
		s.logger.Error("error committing", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := bs.UpdateRepo(context.TODO(), root, rev); err != nil {
		s.logger.Error("error updating repo after commit", "error", err)
		return helpers.ServerError(e, nil)
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoHandle: &atproto.SyncSubscribeRepos_Handle{
			Did:    urepo.Did,
			Handle: request.Handle,
			Seq:    time.Now().UnixMicro(), // TODO: no
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:    urepo.Did,
			Handle: to.StringPtr(request.Handle),
			Seq:    time.Now().UnixMicro(), // TODO: no
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	if err := s.db.Create(&actor, nil).Error; err != nil {
		s.logger.Error("error inserting new actor", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := s.db.Raw("UPDATE invite_codes SET remaining_use_count = remaining_use_count - 1 WHERE code = ?", nil, request.InviteCode).Scan(&ic).Error; err != nil {
		s.logger.Error("error decrementing use count", "error", err)
		return helpers.ServerError(e, nil)
	}

	sess, err := s.createSession(&urepo)
	if err != nil {
		s.logger.Error("error creating new session", "error", err)
		return helpers.ServerError(e, nil)
	}

	go func() {
		if err := s.sendEmailVerification(urepo.Email, actor.Handle, *urepo.EmailVerificationCode); err != nil {
			s.logger.Error("error sending email verification email", "error", err)
		}
		if err := s.sendWelcomeMail(urepo.Email, actor.Handle); err != nil {
			s.logger.Error("error sending welcome email", "error", err)
		}
	}()

	return e.JSON(200, ComAtprotoServerCreateAccountResponse{
		AccessJwt:  sess.AccessToken,
		RefreshJwt: sess.RefreshToken,
		Handle:     request.Handle,
		Did:        did,
	})
}
