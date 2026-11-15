package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"gorm.io/gorm"
)

// Space policy management and authorization, following the reference PDS's
// space-policy/manager.ts, publish.ts and archive.ts at bluesky-social/atproto
// d4def6e9.
//
// The methods that change a space's configuration also publish it to readers
// when the policy asks for it. They return the commit to the authority's repo,
// which is owed a notifyRepoUpdate, or nil if nothing was published. The
// methods that manage members also return the writers they removed, whose
// removal is owed to registered syncers.

const (
	collPolicy = "com.atproto.space.policy"
	collMember = "com.atproto.memberspace.member"
	rkeyPolicy = "self"

	memberKeyPrefix = collMember + "/"
)

// publishedCollections are the collections the PDS publishes a space's
// configuration to.
var publishedCollections = []string{collPolicy, collMember}

// assertNotPolicyRecord refuses a direct write to a published collection in
// any repo: policy and member records are only written by the PDS.
func assertNotPolicyRecord(collection string) error {
	if collection == collPolicy || collection == collMember {
		return errInvalid("", "%s records are published by the PDS from a space's configuration and cannot be written directly", collection)
	}
	return nil
}

// A DID used as a record key, such as a member's published record. A record
// key can't contain %, so the percent-encoded port of a localhost did:web is
// left unencoded: did:web:localhost%3A2583 <-> did:web:localhost:2583. This is
// unambiguous because the unencoded form would otherwise be a did:web path,
// which atproto doesn't support. It only ever affects localhost DIDs.
func didToRecordKey(did string) string { return strings.ReplaceAll(did, "%3A", ":") }

var localhostDidKey = regexp.MustCompile(`^(did:web:[^:]+):(\d+)$`)

func recordKeyToDid(rkey string) string { return localhostDidKey.ReplaceAllString(rkey, "$1%3A$2") }

type memberAccess struct{ Read, Write bool }

type memberEntry struct {
	Did   string
	Read  bool
	Write bool
}

// removedWriter is a repo removed from a space's writer set, at its place in
// the space sequence.
type removedWriter struct {
	Repo         string
	SpaceRev     string
	PrevSpaceRev string
}

// publishing ---------------------------------------------------------------

func preparePublishedPut(st *spaceStore, ref space.Ref, collection, rkey string, record map[string]any) (spaceWrite, error) {
	uri := ref.RecordURI(ref.Authority, collection, rkey)
	exists, err := st.hasRecord(uri)
	if err != nil {
		return spaceWrite{}, err
	}
	sr, err := space.SerializeRecord(collection, rkey, record)
	if err != nil {
		return spaceWrite{}, err
	}
	action := "create"
	if exists {
		action = "update"
	}
	return spaceWrite{Action: action, Collection: collection, Rkey: rkey, Uri: uri, Record: &sr}, nil
}

func preparePublishedDeleteIfExists(st *spaceStore, ref space.Ref, collection, rkey string) ([]spaceWrite, error) {
	uri := ref.RecordURI(ref.Authority, collection, rkey)
	exists, err := st.hasRecord(uri)
	if err != nil || !exists {
		return nil, err
	}
	return []spaceWrite{{Action: "delete", Collection: collection, Rkey: rkey, Uri: uri}}, nil
}

// preparePolicyRecordWrites publishes, updates or withdraws the policy record
// to match the policy.
func preparePolicyRecordWrites(st *spaceStore, ref space.Ref, p *spacePolicy) ([]spaceWrite, error) {
	if p.policyPublished() {
		w, err := preparePublishedPut(st, ref, collPolicy, rkeyPolicy, map[string]any{"$type": collPolicy, "policy": p.lex()})
		return []spaceWrite{w}, err
	}
	return preparePublishedDeleteIfExists(st, ref, collPolicy, rkeyPolicy)
}

// prepareMemberRecordWrites publishes, updates or withdraws a member's record
// to match their entry in the member list. access is nil for a DID that is no
// longer a member.
func prepareMemberRecordWrites(st *spaceStore, ref space.Ref, p *spacePolicy, did string, access *memberAccess) ([]spaceWrite, error) {
	rkey := didToRecordKey(did)
	if access != nil && p.membersPublished() {
		w, err := preparePublishedPut(st, ref, collMember, rkey, map[string]any{"$type": collMember, "read": access.Read, "write": access.Write})
		return []spaceWrite{w}, err
	}
	return preparePublishedDeleteIfExists(st, ref, collMember, rkey)
}

// prepareMemberListWrites publishes or withdraws the whole member list to
// match the policy.
func prepareMemberListWrites(st *spaceStore, ref space.Ref, p *spacePolicy) ([]spaceWrite, error) {
	members, err := st.listMembers(ref.String(), 0, "")
	if err != nil {
		return nil, err
	}
	var out []spaceWrite
	for _, m := range members {
		ws, err := prepareMemberRecordWrites(st, ref, p, m.MemberDid, &memberAccess{m.Read, m.Write})
		if err != nil {
			return nil, err
		}
		out = append(out, ws...)
	}
	return out, nil
}

// lifecycle ----------------------------------------------------------------

// inAuthorityTx runs fn in a transaction on the authority's space store, under
// the account's write lock, since the authority's own repo may be written.
func (s *Server) inAuthorityTx(ctx context.Context, authority string, fn func(st *spaceStore) error) error {
	unlock := s.lockRepoWrite(authority)
	defer unlock()
	return s.db.Client().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(s.spaceStore(tx, authority))
	})
}

func (s *Server) createSpace(ctx context.Context, ref space.Ref, rawPolicy map[string]any) (*spaceCommit, error) {
	policy, err := normalizePolicy(rawPolicy)
	if err != nil {
		return nil, err
	}
	var commit *spaceCommit
	err = s.inAuthorityTx(ctx, ref.Authority, func(st *spaceStore) error {
		existing, err := st.getSpacePolicy(ref.String())
		if err != nil {
			return err
		}
		if existing != nil {
			return errInvalid("SpaceAlreadyExists", "Space already exists")
		}
		if err := st.createSpace(ref, policy); err != nil {
			return err
		}
		writes, err := preparePolicyRecordWrites(st, ref, policy)
		if err != nil {
			return err
		}
		commit, err = st.applyWrites(ref, writes)
		return err
	})
	return commit, err
}

// updateSpace replaces the policy wholesale. A policy of the same $type is a
// configuration change. A different $type migrates the space: state held by
// the previous policy is discarded, so migrating back does not restore it.
func (s *Server) updateSpace(ctx context.Context, ref space.Ref, rawPolicy map[string]any) (*spaceCommit, error) {
	next, err := normalizePolicy(rawPolicy)
	if err != nil {
		return nil, err
	}
	var commit *spaceCommit
	err = s.inAuthorityTx(ctx, ref.Authority, func(st *spaceStore) error {
		uri := ref.String()
		current, err := st.getActiveSpacePolicy(uri)
		if err != nil {
			return err
		}
		writes, err := preparePolicyRecordWrites(st, ref, next)
		if err != nil {
			return err
		}
		// Only memberspace has a member list, so this also withdraws a
		// published list when a migration discards it.
		if current.membersPublished() != next.membersPublished() {
			memberWrites, err := prepareMemberListWrites(st, ref, next)
			if err != nil {
				return err
			}
			writes = append(writes, memberWrites...)
		}
		if err := st.putSpacePolicy(uri, next); err != nil {
			return err
		}
		if current.Type != next.Type {
			if err := st.removeAllMembers(uri); err != nil {
				return err
			}
		}
		commit, err = st.applyWrites(ref, writes)
		return err
	})
	return commit, err
}

func (s *Server) putMembers(ctx context.Context, ref space.Ref, members []memberEntry) (*spaceCommit, []removedWriter, error) {
	// Keyed by DID, so that a DID listed twice takes its last entry rather than
	// having its record written twice in the same commit.
	var order []string
	access := map[string]memberAccess{}
	for _, m := range members {
		if _, seen := access[m.Did]; !seen {
			order = append(order, m.Did)
		}
		access[m.Did] = memberAccess{m.Read, m.Write}
	}
	var commit *spaceCommit
	var removed []removedWriter
	err := s.inAuthorityTx(ctx, ref.Authority, func(st *spaceStore) error {
		uri := ref.String()
		policy, err := st.getActiveSpacePolicy(uri)
		if err != nil {
			return err
		}
		if err := policy.assertMemberspace(); err != nil {
			return err
		}
		var writes []spaceWrite
		for _, did := range order {
			a := access[did]
			if err := st.putMember(uri, did, a.Read, a.Write); err != nil {
				return err
			}
			if !a.Write {
				seq, err := st.removeWriter(uri, did)
				if err != nil {
					return err
				}
				if seq != nil {
					removed = append(removed, removedWriter{did, seq.spaceRev, seq.prevSpaceRev})
				}
			}
			ws, err := prepareMemberRecordWrites(st, ref, policy, did, &a)
			if err != nil {
				return err
			}
			writes = append(writes, ws...)
		}
		commit, err = st.applyWrites(ref, writes)
		return err
	})
	return commit, removed, err
}

func (s *Server) removeMembers(ctx context.Context, ref space.Ref, dids []string) (*spaceCommit, []removedWriter, error) {
	var commit *spaceCommit
	var removed []removedWriter
	err := s.inAuthorityTx(ctx, ref.Authority, func(st *spaceStore) error {
		uri := ref.String()
		policy, err := st.getActiveSpacePolicy(uri)
		if err != nil {
			return err
		}
		if err := policy.assertMemberspace(); err != nil {
			return err
		}
		var writes []spaceWrite
		for _, did := range dids {
			// A DID that is not a member is ignored, leaving any writer set
			// entry alone.
			wasMember, err := st.removeMember(uri, did)
			if err != nil {
				return err
			}
			if !wasMember {
				continue
			}
			seq, err := st.removeWriter(uri, did)
			if err != nil {
				return err
			}
			if seq != nil {
				removed = append(removed, removedWriter{did, seq.spaceRev, seq.prevSpaceRev})
			}
			ws, err := prepareMemberRecordWrites(st, ref, policy, did, nil)
			if err != nil {
				return err
			}
			writes = append(writes, ws...)
		}
		commit, err = st.applyWrites(ref, writes)
		return err
	})
	return commit, removed, err
}

// removeWriter removes a repo from a governed space's writer set.
func (s *Server) removeWriter(ctx context.Context, ref space.Ref, repo string) (*removedWriter, error) {
	var removed *removedWriter
	err := s.inAuthorityTx(ctx, ref.Authority, func(st *spaceStore) error {
		uri := ref.String()
		if _, err := st.getActiveSpacePolicy(uri); err != nil {
			return err
		}
		seq, err := st.removeWriter(uri, repo)
		if err != nil || seq == nil {
			return err
		}
		removed = &removedWriter{repo, seq.spaceRev, seq.prevSpaceRev}
		return nil
	})
	return removed, err
}

// deleteSpace deletes the authority's own repo in the space along with it: no
// other party's data is involved. A member's records stay where they are, as
// records nobody can obtain a credential to read — their PDS is not notified,
// and the application is what tells the user their space is gone.
//
// The space row stays as a tombstone so authorizeSpaceSync keeps answering
// SpaceDeleted, which is how a syncer that missed the notification finds out.
//
// It returns the syncers registered at the time of deletion, including lapsed
// registrations, which are owed a deletion notice.
func (s *Server) deleteSpace(ctx context.Context, ref space.Ref) ([]models.SpaceNotifyRegistration, error) {
	var regs []models.SpaceNotifyRegistration
	err := s.inAuthorityTx(ctx, ref.Authority, func(st *spaceStore) error {
		// Serialized with registrations, which take the same lock, so one
		// can't commit between reading the recipients and the tombstone.
		if err := st.lockSpace(ref.String()); err != nil {
			return err
		}
		var err error
		if regs, err = st.getNotifyRegistrations(ref.String()); err != nil {
			return err
		}
		return st.deleteSpace(ref.String())
	})
	return regs, err
}

// clearRecords deletes the account's records in a space but those in the keep
// collections.
func (s *Server) clearRecords(ctx context.Context, did string, ref space.Ref, fn func(st *spaceStore, collections []string) error, keep []string) (*spaceCommit, error) {
	var commit *spaceCommit
	err := s.inAuthorityTx(ctx, did, func(st *spaceStore) error {
		cols, err := st.listCollections(ref.String())
		if err != nil {
			return err
		}
		if err := fn(st, cols); err != nil {
			return err
		}
		commit, err = st.clearRecords(ref.String(), keep)
		return err
	})
	return commit, err
}

// archive -------------------------------------------------------------------

func memberStateEntry(did string, a memberAccess) space.PolicyStateEntry {
	return space.PolicyStateEntry{
		Key:   memberKeyPrefix + didToRecordKey(did),
		Value: map[string]any{"$type": collMember, "read": a.Read, "write": a.Write},
	}
}

// parsePolicyState reads the members out of an archive's policy state. A key
// the policy doesn't define is refused rather than dropped, since dropping it
// would quietly change who has access to the space.
func parsePolicyState(p *spacePolicy, entries []space.PolicyStateEntry) ([]memberEntry, error) {
	out := make([]memberEntry, 0, len(entries))
	for _, e := range entries {
		rkey, ok := strings.CutPrefix(e.Key, memberKeyPrefix)
		did := recordKeyToDid(rkey)
		if _, err := syntax.ParseDID(did); !ok || err != nil || !p.isMember() {
			return nil, errInvalid("InvalidSpaceMeta", "Unrecognized policy state: %s", e.Key)
		}
		if t, ok := e.Value["$type"]; ok && t != collMember {
			return nil, errInvalid("InvalidSpaceMeta", "Invalid member at %s: $type must be %s", e.Key, collMember)
		}
		read, ok1 := e.Value["read"].(bool)
		write, ok2 := e.Value["write"].(bool)
		if !ok1 || !ok2 {
			return nil, errInvalid("InvalidSpaceMeta", "Invalid member at %s: read and write must be booleans", e.Key)
		}
		out = append(out, memberEntry{Did: did, Read: read, Write: write})
	}
	return out, nil
}

// exportSpaceMeta is the space's host-side state, for migrating its
// authority's account.
func (s *Server) exportSpaceMeta(ctx context.Context, ref space.Ref) (*space.SpaceMetaArchive, error) {
	st := s.spaceStore(s.db.Client().WithContext(ctx), ref.Authority)
	uri := ref.String()
	policy, err := st.getActiveSpacePolicy(uri)
	if err != nil {
		return nil, err
	}
	archive := &space.SpaceMetaArchive{Space: uri, Policy: policy.lex()}
	if policy.isMember() {
		members, err := st.listMembers(uri, 0, "")
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			archive.PolicyState = append(archive.PolicyState, memberStateEntry(m.MemberDid, memberAccess{m.Read, m.Write}))
		}
	}
	// Removed writers are left behind, as the archive carries only the writer
	// set itself. Like garbage collection, this drops removals not yet seen by
	// syncers.
	writers, err := st.listWriters(uri, 0, "")
	if err != nil {
		return nil, err
	}
	for _, w := range writers {
		if w.RemovedAt != nil {
			continue
		}
		archive.Writers = append(archive.Writers, space.SpaceMetaWriter{Did: w.WriterDid, RepoRev: w.RepoRev, Data: w.Data, SpaceRev: w.SpaceRev})
	}
	return archive, nil
}

// importSpaceMeta imports a space exported by its previous host, as its
// authority's account migrates here, replacing whatever this host held for it.
// The policy and member list are published to readers by records in the
// authority's repo, which arrives afterwards with importRepo, so nothing is
// published here.
func (s *Server) importSpaceMeta(ctx context.Context, ref space.Ref, archive *space.SpaceMetaArchive) error {
	policy, err := parseArchivedPolicy(archive.Policy)
	if err != nil {
		return err
	}
	members, err := parsePolicyState(policy, archive.PolicyState)
	if err != nil {
		return err
	}
	return s.inAuthorityTx(ctx, ref.Authority, func(st *spaceStore) error {
		uri := ref.String()
		if err := st.createSpace(ref, policy); err != nil {
			return err
		}
		if err := st.removeAllMembers(uri); err != nil {
			return err
		}
		for _, m := range members {
			if err := st.putMember(uri, m.Did, m.Read, m.Write); err != nil {
				return err
			}
		}
		return st.importWriters(uri, archive.Writers)
	})
}

// authorization --------------------------------------------------------------

// authorizeCredential checks both perimeters a credential has to clear. The
// account goes first, and an account the policy refuses is answered as though
// the space does not exist, so that a refusal discloses nothing about the
// space to someone without access to it.
//
// repo is empty when the request carries no delegation token.
func (s *Server) authorizeCredential(ctx context.Context, ref space.Ref, policy *spacePolicy, repo, clientID string) error {
	ok, err := s.authorizeRepo(ctx, ref, policy, repo, "read", clientID)
	if err != nil {
		return err
	}
	if !ok {
		return errSpaceNotFound()
	}
	if !policy.appAuthorized(clientID) {
		return errInvalid("AppNotAuthorized", "Application not authorized for this space")
	}
	return nil
}

// authorizeRepo reports whether the policy authorizes an account to read or
// write. repo is empty for a read with no delegation token, which a policy
// authorizes only if it does not gate on the account.
func (s *Server) authorizeRepo(ctx context.Context, ref space.Ref, policy *spacePolicy, repo, access, clientID string) (bool, error) {
	// Under every policy the authority is authorized. It is the only party who
	// can reconfigure the space, so it must not be able to lock itself out.
	if repo != "" && repo == ref.Authority {
		return true, nil
	}
	switch policy.Type {
	case policyPersonal:
		return false, nil
	case policyMember:
		if access == "read" && policy.PublicRead {
			return true, nil
		}
		if repo == "" {
			return false, nil
		}
		m, err := s.spaceStore(nil, ref.Authority).getMember(ref.String(), repo)
		if err != nil {
			return false, err
		}
		if access == "read" {
			return m != nil && m.Read, nil
		}
		// A member without write access stays excluded even under
		// publicWrite.
		if m != nil {
			return m.Write, nil
		}
		return policy.PublicWrite, nil
	case policyManaged:
		read, write, err := s.checkManagingApp(ctx, ref, policy.ManagingApp, repo, clientID)
		if err != nil {
			return false, err
		}
		if access == "read" {
			return read, nil
		}
		return write, nil
	}
	return false, nil
}

const lxmCheckAccess = "com.atproto.managedspace.checkAccess"

// checkManagingApp asks a managed space's managing app for an account's
// access. repo is empty for a read with no delegation token, and clientID is
// empty for writes, since a repo update notification does not identify the app
// that made the write.
//
// Without an answer from the app, it fails with UpstreamFailure. Failing open
// would hand out credentials for the spaces that asked for the strictest gate,
// but denying would be taken as a loss of access: a syncer's registration
// would be withdrawn, and a repo host would drop its write notification
// rather than retry.
func (s *Server) checkManagingApp(ctx context.Context, ref space.Ref, app, repo, clientID string) (read, write bool, err error) {
	fail := func(cause error) (bool, bool, error) {
		s.logger.Warn("managing app check failed", "space", ref.String(), "managingApp", app, "repo", repo, "err", cause)
		return false, false, &xrpcError{Status: http.StatusBadGateway, Name: "UpstreamFailure", Message: "Managing app did not answer"}
	}
	target, err := s.resolveNotifyTarget(ctx, ref.Authority, app, lxmCheckAccess)
	if err != nil {
		return fail(err)
	}
	if target == nil {
		return fail(errNoTarget)
	}
	q := url.Values{"space": {ref.String()}}
	if repo != "" {
		q.Set("repo", repo)
	}
	if clientID != "" {
		q.Set("clientId", clientID)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.endpoint+"/xrpc/"+lxmCheckAccess+"?"+q.Encode(), nil)
	if err != nil {
		return fail(err)
	}
	for k, v := range target.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.spaceClient().Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(&xrpcCallError{Status: resp.StatusCode})
	}
	var out struct {
		Read  *bool `json:"read"`
		Write *bool `json:"write"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Read == nil || out.Write == nil {
		return fail(errNoTarget)
	}
	return *out.Read, *out.Write, nil
}
