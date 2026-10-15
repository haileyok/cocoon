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

// Agent record types (namespace garden.engram.agents). An agent publishes a
// declaration record naming its operator; the operator's repo lists the agent
// in a matching operated record (a two-way check, like handle verification).
const (
	agentDeclarationCollection = "garden.engram.agents.declaration"
	agentDeclarationRkey       = "self"
	agentOperatedCollection    = "garden.engram.agents.operated"
	// agentEmailDomain is the placeholder domain for agent account emails.
	agentEmailDomain = "agents.invalid"
)

// CreateAgentArgs describes an agent account to create.
type CreateAgentArgs struct {
	// Handle for the agent account, e.g. name.agents.example.com.
	Handle string
	// Operator is the operator's DID. The agent's declaration record names it;
	// if the operator is an account on this PDS, their repo also gets an
	// operated record listing the agent.
	Operator string
	// RecoveryKey is a did:key held by the operator offline. It lands FIRST in
	// the genesis PLC operation's rotationKeys, before the PDS's own key, so
	// the agent cannot move or keep its identity without the operator.
	RecoveryKey string
	// Description is an optional string on the declaration record.
	Description string
}

// CreateAgentResult reports the created agent account.
type CreateAgentResult struct {
	Did    string
	Handle string
	// OperatedWritten reports whether the operator's operated record was
	// written (only when the operator is an account on this PDS).
	OperatedWritten bool
}

// CreateAgent creates an agent account on this PDS, mirroring what
// com.atproto.server.createAccount does, and publishes the agent records:
// the agent's garden.engram.agents.declaration/self record and, when the
// operator is an account here, the operator's garden.engram.agents.operated
// record listing the agent. The email is a placeholder under agents.invalid
// and the password is random and never printed: agents sign in via OAuth.
func (s *Server) CreateAgent(ctx context.Context, args CreateAgentArgs) (*CreateAgentResult, error) {
	logger := s.logger.With("name", "CreateAgent")

	handle := strings.ToLower(strings.TrimSpace(args.Handle))
	if _, err := syntax.ParseHandle(handle); err != nil {
		return nil, fmt.Errorf("invalid handle: %w", err)
	}

	operator := strings.TrimSpace(args.Operator)
	if _, err := syntax.ParseDID(operator); err != nil {
		return nil, fmt.Errorf("invalid operator did: %w", err)
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

	did, op, err := s.plcClient.CreateDID(k, recovery, handle)
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

	agentRepoActor, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		return nil, err
	}

	// The agent's declaration record, written through the same repo-write path
	// the XRPC handlers use.
	decl := MarshalableMap{
		"$type":     agentDeclarationCollection,
		"operator":  operator,
		"createdAt": time.Now().Format(time.RFC3339Nano),
	}
	if args.Description != "" {
		decl["description"] = args.Description
	}
	rkey := agentDeclarationRkey
	if _, err := s.applyWritesForRepo(ctx, agentRepoActor.Repo, Op{
		Type:       OpTypeCreate,
		Collection: agentDeclarationCollection,
		Rkey:       &rkey,
		Record:     &decl,
	}); err != nil {
		return nil, fmt.Errorf("writing declaration record: %w", err)
	}

	result := &CreateAgentResult{Did: did, Handle: handle}

	// The operator's operated record, when the operator is an account here.
	opRepo, err := s.getRepoActorByDid(ctx, operator)
	if err == nil && opRepo.Repo.Did != "" {
		operated := MarshalableMap{
			"$type":     agentOperatedCollection,
			"agent":     did,
			"createdAt": time.Now().Format(time.RFC3339Nano),
		}
		oprkey := s.repoman.clock.Next().String()
		if _, err := s.applyWritesForRepo(ctx, opRepo.Repo, Op{
			Type:       OpTypeCreate,
			Collection: agentOperatedCollection,
			Rkey:       &oprkey,
			Record:     &operated,
		}); err != nil {
			return nil, fmt.Errorf("writing operated record: %w", err)
		}
		result.OperatedWritten = true
	}

	return result, nil
}

// applyWritesForRepo applies one op to an account's repo through the shared
// applyWrites path, the same one the repo XRPC handlers use.
func (s *Server) applyWritesForRepo(ctx context.Context, repo models.Repo, op Op) ([]ApplyWriteResult, error) {
	if s.repoman == nil {
		return nil, fmt.Errorf("repoman not initialized")
	}
	return s.repoman.applyWrites(ctx, repo, []Op{op}, nil, nil)
}
