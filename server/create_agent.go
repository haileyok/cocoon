package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"golang.org/x/crypto/bcrypt"
)

// agentEmailDomain is the placeholder domain for agent account emails.
const agentEmailDomain = "agents.invalid"

// CreateAgentArgs describes an agent account to create.
type CreateAgentArgs struct {
	// Handle for the agent account, e.g. name.agents.example.com.
	Handle string
	// RecoveryKey is a did:key the agent's operator holds offline. It lands
	// FIRST in the genesis PLC operation's rotationKeys, before the PDS's own
	// key, so the agent can't move or keep its identity without the operator.
	RecoveryKey string
}

// CreateAgentResult reports the created agent account.
type CreateAgentResult struct {
	Did    string
	Handle string
}

// CreateAgent creates an account for an automated agent on this PDS,
// mirroring what com.atproto.server.createAccount does: the PLC genesis
// operation (with the recovery key first), the account and an empty repo.
// The email is a placeholder under agents.invalid and the password is random
// and never printed: agents sign in with OAuth. It writes no records; what an
// agent publishes about itself is up to the software that runs it.
func (s *Server) CreateAgent(ctx context.Context, args CreateAgentArgs) (*CreateAgentResult, error) {
	logger := s.logger.With("name", "CreateAgent")

	handle := strings.ToLower(strings.TrimSpace(args.Handle))
	if _, err := syntax.ParseHandle(handle); err != nil {
		return nil, fmt.Errorf("invalid handle: %w", err)
	}

	recovery := strings.TrimSpace(args.RecoveryKey)
	if recovery != "" {
		if _, err := atcrypto.ParsePublicDIDKey(recovery); err != nil {
			return nil, fmt.Errorf("invalid recovery key: %w", err)
		}
	}

	// The handle must be free here, like createAccount.
	if actor, err := s.getActorByHandle(ctx, handle); err == nil && actor.Did != "" {
		return nil, fmt.Errorf("handle not available: %s", handle)
	}
	email := handle + "@" + agentEmailDomain
	if existing, err := s.getRepoByEmail(ctx, email); err == nil && existing.Did != "" {
		return nil, fmt.Errorf("email not available: %s", email)
	}

	// A random password the agent never needs (it signs in via OAuth).
	password := fmt.Sprintf("%s-%s", helpers.RandomVarchar(12), helpers.RandomVarchar(12))
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return nil, err
	}

	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		return nil, err
	}

	kemKey, kemDidKey, err := newKemKey()
	if err != nil {
		return nil, err
	}

	did, op, err := s.plcClient.CreateDID(k, kemDidKey, recovery, handle)
	if err != nil {
		logger.Error("error creating plc operation", "error", err)
		return nil, err
	}
	if err := s.plcClient.SendOperation(ctx, did, op); err != nil {
		logger.Error("error sending plc op", "error", err)
		return nil, err
	}

	urepo := models.Repo{
		Did:                   did,
		CreatedAt:             time.Now(),
		Email:                 email,
		EmailVerificationCode: nil, // no email to verify
		Password:              string(hashed),
		SigningKey:            k.Bytes(),
		KemKey:                kemKey.Bytes(),
	}
	actor := models.Actor{Did: did, Handle: handle}
	if err := s.db.Create(ctx, &urepo, nil).Error; err != nil {
		return nil, err
	}
	if err := s.db.Create(ctx, &actor, nil).Error; err != nil {
		return nil, err
	}

	// Commit an empty repo head, like createAccount's genesis repo, so the
	// first record write has a valid root to apply on.
	if _, _, err := s.initializeGenesisRepo(ctx, did, urepo.SigningKey); err != nil {
		return nil, fmt.Errorf("initializing genesis repo: %w", err)
	}

	// Announce the new identity and repo head on the firehose, like
	// createAccount does for an active account.
	if s.evtman != nil {
		s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
			RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
				Did:    did,
				Handle: &handle,
				Time:   time.Now().Format(util.ISO8601),
			},
		})
		if root, err := cid.Cast(urepo.Root); err == nil {
			if err := s.emitRepoSync(ctx, did, urepo.Rev, root); err != nil {
				logger.Error("error emitting repo sync event", "error", err)
			}
		}
	}

	return &CreateAgentResult{Did: did, Handle: handle}, nil
}
