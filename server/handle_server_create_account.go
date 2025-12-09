package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/repo"
	"github.com/bluesky-social/indigo/util"
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
	
	var signupDid string
	if request.Did != nil {
		signupDid = *request.Did;
		
		token := strings.TrimSpace(strings.Replace(e.Request().Header.Get("authorization"), "Bearer ", "", 1))
		if token == "" {
			return helpers.UnauthorizedError(e, to.StringPtr("must authenticate to use an existing did"))
		}
		authDid, err := s.validateServiceAuth(e.Request().Context(), token, "com.atproto.server.createAccount")

		if err != nil {
			s.logger.Warn("error validating authorization token", "endpoint", "com.atproto.server.createAccount", "error", err)
			return helpers.UnauthorizedError(e, to.StringPtr("invalid authorization token"))
		}

		if authDid != signupDid {
			return helpers.ForbiddenError(e, to.StringPtr("auth did did not match signup did"))
		}
	}

	// see if the handle is already taken
	actor, err := s.getActorByHandle(request.Handle)
	if err != nil && err != gorm.ErrRecordNotFound {
		s.logger.Error("error looking up handle in db", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}
	if err == nil && actor.Did != signupDid {
		return helpers.InputError(e, to.StringPtr("HandleNotAvailable"))
	}

	if did, err := s.passport.ResolveHandle(e.Request().Context(), request.Handle); err == nil && did != signupDid {
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
	existingRepo, err := s.getRepoByEmail(request.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		s.logger.Error("error looking up email in db", "endpoint", "com.atproto.server.createAccount", "error", err)
		return helpers.ServerError(e, nil)
	}
	if err == nil && existingRepo.Did != signupDid {
		return helpers.InputError(e, to.StringPtr("EmailNotAvailable"))
	}

	// TODO: unsupported domains

	var k *atcrypto.PrivateKeyK256

	if signupDid != "" {
		reservedKey, err := s.getReservedKey(signupDid)
		if err != nil {
			s.logger.Error("error looking up reserved key", "error", err)
		}
		if reservedKey != nil {
			k, err = atcrypto.ParsePrivateBytesK256(reservedKey.PrivateKey)
			if err != nil {
				s.logger.Error("error parsing reserved key", "error", err)
				k = nil
			} else {
				defer func() {
					if delErr := s.deleteReservedKey(reservedKey.KeyDid, reservedKey.Did); delErr != nil {
						s.logger.Error("error deleting reserved key", "error", delErr)
					}
				}()
			}
		}
	}

	if k == nil {
		k, err = atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			s.logger.Error("error creating signing key", "endpoint", "com.atproto.server.createAccount", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	if signupDid == "" {
		did, op, err := s.plcClient.CreateDID(k, "", request.Handle)
		if err != nil {
			s.logger.Error("error creating operation", "endpoint", "com.atproto.server.createAccount", "error", err)
			return helpers.ServerError(e, nil)
		}

		if err := s.plcClient.SendOperation(e.Request().Context(), did, op); err != nil {
			s.logger.Error("error sending plc op", "endpoint", "com.atproto.server.createAccount", "error", err)
			return helpers.ServerError(e, nil)
		}
		signupDid = did
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		s.logger.Error("error hashing password", "error", err)
		return helpers.ServerError(e, nil)
	}

	urepo := models.Repo{
		Did:                   signupDid,
		CreatedAt:             time.Now(),
		Email:                 request.Email,
		EmailVerificationCode: to.StringPtr(fmt.Sprintf("%s-%s", helpers.RandomVarchar(6), helpers.RandomVarchar(6))),
		Password:              string(hashed),
		SigningKey:            k.Bytes(),
	}

	if actor == nil {
		actor = &models.Actor{
			Did:    signupDid,
			Handle: request.Handle,
		}

		if err := s.db.Create(&urepo, nil).Error; err != nil {
			s.logger.Error("error inserting new repo", "error", err)
			return helpers.ServerError(e, nil)
		}
	
		if err := s.db.Create(&actor, nil).Error; err != nil {
			s.logger.Error("error inserting new actor", "error", err)
			return helpers.ServerError(e, nil)
		}
	} else {
		if err := s.db.Save(&actor, nil).Error; err != nil {
			s.logger.Error("error inserting new actor", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	if request.Did == nil || *request.Did == "" {
		bs := s.getBlockstore(signupDid)
		r := repo.NewRepo(context.TODO(), signupDid, bs)

		root, rev, err := r.Commit(context.TODO(), urepo.SignFor)
		if err != nil {
			s.logger.Error("error committing", "error", err)
			return helpers.ServerError(e, nil)
		}

		if err := s.UpdateRepo(context.TODO(), urepo.Did, root, rev); err != nil {
			s.logger.Error("error updating repo after commit", "error", err)
			return helpers.ServerError(e, nil)
		}

		s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
			RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
				Did:    urepo.Did,
				Handle: to.StringPtr(request.Handle),
				Seq:    time.Now().UnixMicro(), // TODO: no
				Time:   time.Now().Format(util.ISO8601),
			},
		})
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
		Did:        signupDid,
	})
}
