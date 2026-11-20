package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
	"github.com/labstack/echo/v4"
)

// createAgentNSID creates an agent account for the caller, its principal,
// in one step: the account (its DID document declaring it an agent of the
// caller, https://ident.link), and the caller's endorsement of it.
const createAgentNSID = "at.hailey.cocoon.createAgent"

// endorsementCollection is ident.link's endorsement record, kept in the
// principal's repo under the agent's DID.
const endorsementCollection = "link.ident.endorsement"

type createAgentInput struct {
	// Handle is the agent's handle under this PDS's domain; empty picks one.
	Handle string `json:"handle,omitempty"`
	// RecoveryKey is a did:key the principal holds offline, put first in
	// the agent's rotation keys.
	RecoveryKey string `json:"recoveryKey,omitempty"`
}

type createAgentOutput struct {
	Did    string `json:"did"`
	Handle string `json:"handle"`
	// Password signs in as the agent. It's returned once and stored
	// nowhere in the clear. An agent account can't change its identity,
	// whatever it signs in with.
	Password string `json:"password"`
	// Endorsement is the URI of the caller's link.ident.endorsement.
	// Endorsed is false when writing it failed after the account was made:
	// the caller writes it with com.atproto.repo.putRecord.
	Endorsement string `json:"endorsement,omitempty"`
	Endorsed    bool   `json:"endorsed"`
}

// agentLimiter counts agents created per principal over the last hour.
type agentLimiter struct {
	mu   sync.Mutex
	made map[string][]time.Time
}

// take records one creation for did, unless it already made limit this hour.
func (l *agentLimiter) take(did string, limit int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.made == nil {
		l.made = map[string][]time.Time{}
	}
	recent := l.made[did][:0]
	for _, t := range l.made[did] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) >= limit {
		l.made[did] = recent
		return false
	}
	l.made[did] = append(recent, now)
	return true
}

// handleCreateAgentXrpc creates an agent account for the signed-in account.
// The principal is whoever calls: the declaration can only name the caller,
// and only callers in COCOON_AGENT_PRINCIPALS may create agents, so no
// invite code is involved. An OAuth caller needs
// rpc:at.hailey.cocoon.createAgent?aud=<this PDS's DID> and
// repo:link.ident.endorsement.
func (s *Server) handleCreateAgentXrpc(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleCreateAgentXrpc")
	repo, ok := e.Get("repo").(*models.RepoActor)
	if !ok {
		return helpers.InvalidTokenError(e)
	}
	principal := repo.Repo.Did

	if !s.hasRPCScope(e, s.config.Did, createAgentNSID) {
		return helpers.InsufficientScopeError(e, "rpc:"+createAgentNSID+"?aud="+s.config.Did)
	}
	if !s.hasRepoScope(e, endorsementCollection, "create") {
		return helpers.InsufficientScopeError(e, "repo:"+endorsementCollection+"?action=create")
	}
	if isAgentRepo(&repo.Repo) {
		return e.JSON(403, map[string]string{"error": "Forbidden", "message": "agents can't create agents"})
	}
	if !slices.Contains(s.config.AgentPrincipals, principal) {
		return e.JSON(403, map[string]string{"error": "Forbidden", "message": "this account may not create agents here"})
	}

	var in createAgentInput
	if err := e.Bind(&in); err != nil {
		return helpers.InputError(e, nil)
	}
	domain := "." + s.config.Hostname
	handle := strings.ToLower(strings.TrimSpace(in.Handle))
	if handle == "" {
		handle = "a-" + strings.ToLower(helpers.RandomVarchar(10)) + domain
	}
	if !strings.HasSuffix(handle, domain) || len(handle) <= len(domain) {
		return e.JSON(400, map[string]string{"error": "InvalidHandle", "message": "an agent's handle ends in " + domain})
	}
	if in.RecoveryKey != "" {
		if _, err := atcrypto.ParsePublicDIDKey(in.RecoveryKey); err != nil {
			return e.JSON(400, map[string]string{"error": "InvalidRequest", "message": "recoveryKey must be a did:key"})
		}
	}
	limit := s.config.AgentsPerHour
	if limit <= 0 {
		limit = 120
	}
	if !s.agentLimits.take(principal, limit, time.Now()) {
		return e.JSON(429, map[string]string{"error": "RateLimitExceeded", "message": fmt.Sprintf("at most %d agents an hour", limit)})
	}

	res, err := s.CreateAgent(ctx, CreateAgentArgs{
		Handle:      handle,
		RecoveryKey: in.RecoveryKey,
		AlsoKnownAs: []string{plc.IdentLinkAgentOfPrefix + principal},
	})
	if err != nil {
		if strings.Contains(err.Error(), "not available") {
			return e.JSON(400, map[string]string{"error": "HandleNotAvailable", "message": err.Error()})
		}
		logger.Error("creating an agent failed", "principal", principal, "error", err)
		return helpers.ServerError(e, nil)
	}
	out := createAgentOutput{Did: res.Did, Handle: res.Handle, Password: res.Password}

	// The principal's half: the endorsement, in their own repo.
	rkey := res.Did
	record := MarshalableMap{"$type": endorsementCollection, "agent": res.Did}
	results, err := s.repoman.applyWrites(ctx, repo.Repo, []Op{{
		Type: OpTypeCreate, Collection: endorsementCollection, Rkey: &rkey, Record: &record,
	}}, nil, s.repoWriteAuthorization(e))
	if err != nil {
		var scopeErr repoScopeError
		if !errors.As(err, &scopeErr) {
			logger.Error("writing an agent's endorsement failed", "principal", principal, "agent", res.Did, "error", err)
		}
	} else if len(results) > 0 && results[0].Uri != nil {
		out.Endorsement, out.Endorsed = *results[0].Uri, true
	}
	logger.Info("created an agent", "principal", principal, "agent", res.Did, "handle", res.Handle, "endorsed", out.Endorsed)
	return e.JSON(200, out)
}
