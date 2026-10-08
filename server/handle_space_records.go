package server

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// Space record writes and reads (com.atproto.space.*), following the
// reference PDS (packages/pds/src/api/com/atproto/space) at
// bluesky-social/atproto 5b95b2f2.

const spaceMaxWrites = 200

func (s *Server) accountSigner(repo models.Repo) (atcrypto.PrivateKey, error) {
	return atcrypto.ParsePrivateBytesK256(repo.SigningKey)
}

// prepareSpaceWrite builds a create or update: it checks $type against the
// collection, fills in a TID rkey for a create, encodes the record and works
// out its validation status. The PDS validates only against schemas it knows,
// and knows none for space collections, so a validated write reports
// "unknown", or fails when validation is demanded.
func prepareSpaceWrite(did string, ref space.Ref, action, collection, rkey string, raw json.RawMessage, validate *bool) (spaceWrite, error) {
	w := spaceWrite{Action: action, Collection: collection, Rkey: rkey}
	if len(raw) == 0 || string(raw) == "null" {
		return w, errInvalid("", "Input must have the property \"record\"")
	}
	rec, err := atdata.UnmarshalJSON(raw)
	if err != nil {
		return w, errInvalid("InvalidRecord", "Invalid record: %v", err)
	}
	switch t := rec["$type"].(type) {
	case nil:
		rec["$type"] = collection
	case string:
		if t != collection {
			return w, errInvalid("InvalidRecord", "Invalid $type: expected %s, got %s", collection, t)
		}
	default:
		return w, errInvalid("InvalidRecord", "Invalid $type")
	}
	if w.Rkey == "" {
		w.Rkey = nextTID("")
	}
	if _, err := parseRkeyParam("rkey", w.Rkey, true); err != nil {
		return w, err
	}
	if validate == nil || *validate {
		if validate != nil && *validate {
			return w, errInvalid("InvalidRecord", "Unknown lexicon type: %s", collection)
		}
		w.Status = "unknown"
	}
	sr, err := space.SerializeRecord(collection, w.Rkey, rec)
	if err != nil {
		return w, errInvalid("InvalidRecord", "Invalid record: %v", err)
	}
	w.Record = &sr
	for _, b := range atdata.ExtractBlobs(rec) {
		w.Blobs = append(w.Blobs, b.Ref.CID())
	}
	w.Uri = ref.RecordURI(did, collection, w.Rkey)
	return w, nil
}

func prepareSpaceDelete(did string, ref space.Ref, collection, rkey string) spaceWrite {
	return spaceWrite{Action: "delete", Collection: collection, Rkey: rkey, Uri: ref.RecordURI(did, collection, rkey)}
}

// commitSpaceWrites applies writes to the caller's repo in one transaction,
// under the account's write lock, then sends notifyWrite to the authority.
func (s *Server) commitSpaceWrites(e echo.Context, did string, ref space.Ref, fn func(st *spaceStore) ([]spaceWrite, error)) (*spaceCommit, []spaceWrite, error) {
	unlock := s.lockRepoWrite(did)
	defer unlock()
	var commit *spaceCommit
	var writes []spaceWrite
	err := s.db.Client().WithContext(e.Request().Context()).Transaction(func(tx *gorm.DB) error {
		st := s.spaceStore(tx, did)
		var err error
		writes, err = fn(st)
		if err != nil {
			return err
		}
		commit, err = st.applyWrites(ref, writes)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if commit != nil {
		// As in the reference, a notification that could neither be sent
		// nor queued fails the request, though the write has landed.
		if err := s.notifySpaceWrite(ref, did, commit); err != nil {
			return nil, nil, err
		}
	}
	return commit, writes, nil
}

func writeResult(w spaceWrite) map[string]any {
	out := map[string]any{"uri": w.Uri, "cid": w.Record.Cid.String()}
	if w.Status != "" {
		out["validationStatus"] = w.Status
	}
	return out
}

type spaceRecordInput struct {
	Space      string          `json:"space"`
	Repo       string          `json:"repo"`
	Collection string          `json:"collection"`
	Rkey       string          `json:"rkey"`
	Validate   *bool           `json:"validate"`
	Record     json.RawMessage `json:"record"`
}

func (in *spaceRecordInput) check(rkeyRequired bool) (space.Ref, error) {
	ref, err := parseSpaceParam("space", in.Space)
	if err != nil {
		return ref, err
	}
	if _, err := parseDIDParam("repo", in.Repo); err != nil {
		return ref, err
	}
	if _, err := parseNSIDParam("collection", in.Collection, true); err != nil {
		return ref, err
	}
	if _, err := parseRkeyParam("rkey", in.Rkey, rkeyRequired); err != nil {
		return ref, err
	}
	return ref, nil
}

func (s *Server) handleSpaceCreateRecord(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in spaceRecordInput
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := in.check(false)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		if in.Repo != a.did {
			return nil, errForbidden("repo must match authenticated user")
		}
		if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Action: "create", Collection: in.Collection}); err != nil {
			return nil, err
		}
		w, err := prepareSpaceWrite(a.did, ref, "create", in.Collection, in.Rkey, in.Record, in.Validate)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.commitSpaceWrites(e, a.did, ref, func(*spaceStore) ([]spaceWrite, error) { return []spaceWrite{w}, nil }); err != nil {
			return nil, err
		}
		return writeResult(w), nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpacePutRecord(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in spaceRecordInput
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := in.check(true)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		if in.Repo != a.did {
			return nil, errForbidden("repo must match authenticated user")
		}
		var w spaceWrite
		_, _, err = s.commitSpaceWrites(e, a.did, ref, func(st *spaceStore) ([]spaceWrite, error) {
			// Resolve to what this write is, so an app granted only update
			// isn't asked for create too.
			exists, err := st.hasRecord(ref.RecordURI(a.did, in.Collection, in.Rkey))
			if err != nil {
				return nil, err
			}
			action := "create"
			if exists {
				action = "update"
			}
			if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Action: action, Collection: in.Collection}); err != nil {
				return nil, err
			}
			w, err = prepareSpaceWrite(a.did, ref, action, in.Collection, in.Rkey, in.Record, in.Validate)
			if err != nil {
				return nil, err
			}
			return []spaceWrite{w}, nil
		})
		if err != nil {
			return nil, err
		}
		return writeResult(w), nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceDeleteRecord(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in spaceRecordInput
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := in.check(true)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		if in.Repo != a.did {
			return nil, errForbidden("repo must match authenticated user")
		}
		if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Action: "delete", Collection: in.Collection}); err != nil {
			return nil, err
		}
		w := prepareSpaceDelete(a.did, ref, in.Collection, in.Rkey)
		// Idempotent, as com.atproto.repo.deleteRecord is.
		_, _, err = s.commitSpaceWrites(e, a.did, ref, func(st *spaceStore) ([]spaceWrite, error) {
			exists, err := st.hasRecord(w.Uri)
			if err != nil || !exists {
				return nil, err
			}
			return []spaceWrite{w}, nil
		})
		return nil, err
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceApplyWrites(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		var in struct {
			Space    string            `json:"space"`
			Repo     string            `json:"repo"`
			Validate *bool             `json:"validate"`
			Writes   []json.RawMessage `json:"writes"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if _, err := parseDIDParam("repo", in.Repo); err != nil {
			return nil, err
		}
		if in.Writes == nil {
			return nil, errInvalid("", "Input must have the property \"writes\"")
		}
		type rawWrite struct {
			Type       string          `json:"$type"`
			Collection string          `json:"collection"`
			Rkey       string          `json:"rkey"`
			Value      json.RawMessage `json:"value"`
		}
		parsed := make([]rawWrite, len(in.Writes))
		for i, raw := range in.Writes {
			var w rawWrite
			if err := json.Unmarshal(raw, &w); err != nil {
				return nil, errInvalid("", "Input/writes/%d must be an object", i)
			}
			switch w.Type {
			case "com.atproto.space.applyWrites#create", "com.atproto.space.applyWrites#update", "com.atproto.space.applyWrites#delete":
			default:
				return nil, errInvalid("", "Input/writes/%d must be an object which includes the \"$type\" property. Expected one of com.atproto.space.applyWrites#create, com.atproto.space.applyWrites#update, com.atproto.space.applyWrites#delete at $.writes[%d]", i, i)
			}
			if _, err := parseNSIDParam(fmt.Sprintf("writes[%d].collection", i), w.Collection, true); err != nil {
				return nil, err
			}
			rkeyRequired := w.Type != "com.atproto.space.applyWrites#create"
			if _, err := parseRkeyParam(fmt.Sprintf("writes[%d].rkey", i), w.Rkey, rkeyRequired); err != nil {
				return nil, err
			}
			parsed[i] = w
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		if in.Repo != a.did {
			return nil, errForbidden("repo must match authenticated user")
		}
		if len(parsed) > spaceMaxWrites {
			return nil, errInvalid("", "Too many writes. Max: %d", spaceMaxWrites)
		}
		prepared := make([]spaceWrite, len(parsed))
		for i, w := range parsed {
			action := strings.TrimPrefix(w.Type, "com.atproto.space.applyWrites#")
			if action == "delete" {
				prepared[i] = prepareSpaceDelete(a.did, ref, w.Collection, w.Rkey)
			} else {
				p, err := prepareSpaceWrite(a.did, ref, action, w.Collection, w.Rkey, w.Value, in.Validate)
				if err != nil {
					return nil, err
				}
				prepared[i] = p
			}
		}
		for _, w := range prepared {
			if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Action: w.Action, Collection: w.Collection}); err != nil {
				return nil, err
			}
		}
		if _, _, err := s.commitSpaceWrites(e, a.did, ref, func(*spaceStore) ([]spaceWrite, error) { return prepared, nil }); err != nil {
			return nil, err
		}
		results := make([]map[string]any, len(prepared))
		for i, w := range prepared {
			switch w.Action {
			case "delete":
				results[i] = map[string]any{"$type": "com.atproto.space.applyWrites#deleteResult"}
			default:
				r := writeResult(w)
				r["$type"] = "com.atproto.space.applyWrites#" + w.Action + "Result"
				results[i] = r
			}
		}
		return map[string]any{"results": results}, nil
	}()
	return writeSpaceResult(e, body, err)
}

// assertSpaceWriter refuses writes from an account that may not write now.
func (s *Server) assertSpaceWriter(a *spaceAuth) error {
	if a.repo != nil && a.repo.Repo.Deactivated {
		return errInvalid("AccountDeactivated", "Account is deactivated")
	}
	return s.assertNotTakenDown(a.did)
}

// assertRepoAvailability checks the repo being read exists and is available.
// The owner may read their own deactivated repo.
func (s *Server) assertRepoAvailability(e echo.Context, did string, isSelf bool) (*models.RepoActor, error) {
	repo, err := s.getRepoActorByDid(e.Request().Context(), did)
	if err != nil {
		if notFound(err) {
			return nil, errInvalid("RepoNotFound", "Could not find repo for DID: %s", did)
		}
		return nil, err
	}
	if takenDown, err := s.isTakenDown(did); err != nil {
		return nil, err
	} else if takenDown {
		return nil, errInvalid("RepoTakendown", "Repo has been takendown: %s", did)
	}
	if repo.Repo.Deactivated && !isSelf {
		return nil, errInvalid("RepoDeactivated", "Repo has been deactivated: %s", did)
	}
	return repo, nil
}

type spaceReadParams struct {
	auth *spaceAuth
	ref  space.Ref
	repo string
}

// spaceReadAuth authenticates a space read (an account session or a space
// credential) and checks the caller may read the repo it names.
func (s *Server) spaceReadAuth(e echo.Context) (*spaceReadParams, error) {
	a, err := s.spaceAuthFromRequest(e)
	if err != nil {
		return nil, err
	}
	q := e.QueryParams()
	ref, err := parseSpaceParam("space", q.Get("space"))
	if err != nil {
		return nil, err
	}
	repo, err := parseDIDParam("repo", q.Get("repo"))
	if err != nil {
		return nil, err
	}
	if err := assertSpaceRead(a, ref, repo); err != nil {
		return nil, err
	}
	if _, err := s.assertRepoAvailability(e, repo, isSpaceSelfRead(a, repo)); err != nil {
		return nil, err
	}
	return &spaceReadParams{auth: a, ref: ref, repo: repo}, nil
}

func decodeSpaceValue(b []byte) (map[string]any, error) {
	return atdata.UnmarshalCBOR(b)
}

func (s *Server) handleSpaceGetRecord(e echo.Context) error {
	body, err := func() (any, error) {
		p, err := s.spaceReadAuth(e)
		if err != nil {
			return nil, err
		}
		q := e.QueryParams()
		collection, err := parseNSIDParam("collection", q.Get("collection"), true)
		if err != nil {
			return nil, err
		}
		rkey, err := parseRkeyParam("rkey", q.Get("rkey"), true)
		if err != nil {
			return nil, err
		}
		uri := p.ref.RecordURI(p.repo, collection, rkey)
		rec, err := s.spaceStore(nil, p.repo).getRecord(uri)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			return nil, errInvalid("RecordNotFound", "Could not locate record: %s", uri)
		}
		val, err := decodeSpaceValue(rec.Value)
		if err != nil {
			return nil, err
		}
		return map[string]any{"uri": uri, "cid": rec.Cid, "value": val}, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceListRecords(e echo.Context) error {
	body, err := func() (any, error) {
		p, err := s.spaceReadAuth(e)
		if err != nil {
			return nil, err
		}
		q := e.QueryParams()
		collection, err := parseNSIDParam("collection", q.Get("collection"), false)
		if err != nil {
			return nil, err
		}
		limit, err := parseLimitParam(q.Get("limit"), 50, 1, 1000)
		if err != nil {
			return nil, err
		}
		reverse, err := parseBoolParam(q.Get("reverse"))
		if err != nil {
			return nil, err
		}
		excludeValues, err := parseBoolParam(q.Get("excludeValues"))
		if err != nil {
			return nil, err
		}
		rows, err := s.spaceStore(nil, p.repo).listRecords(p.ref.String(), limit, q.Get("cursor"), reverse, collection)
		if err != nil {
			return nil, err
		}
		recs := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			out := map[string]any{"collection": r.Collection, "rkey": r.Rkey, "cid": r.Cid}
			if !excludeValues {
				v, err := decodeSpaceValue(r.Value)
				if err != nil {
					return nil, err
				}
				out["value"] = v
			}
			recs = append(recs, out)
		}
		res := map[string]any{"records": recs}
		if len(rows) >= limit && len(rows) > 0 {
			res["cursor"] = rows[len(rows)-1].Uri
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceListRepoOps(e echo.Context) error {
	body, err := func() (any, error) {
		p, err := s.spaceReadAuth(e)
		if err != nil {
			return nil, err
		}
		q := e.QueryParams()
		since, err := parseTIDParam("since", q.Get("since"))
		if err != nil {
			return nil, err
		}
		limit, err := parseLimitParam(q.Get("limit"), 100, 1, 1000)
		if err != nil {
			return nil, err
		}
		excludeValues, err := parseBoolParam(q.Get("excludeValues"))
		if err != nil {
			return nil, err
		}
		var cursorRev string
		var cursorIdx int
		hasCursor := false
		if c := q.Get("cursor"); c != "" {
			rev, idxStr, _ := strings.Cut(c, "/")
			if _, err := fmt.Sscanf(idxStr, "%d", &cursorIdx); err != nil {
				return nil, errInvalid("MalformedCursor", "Malformed cursor")
			}
			cursorRev, hasCursor = rev, true
		}
		st := s.spaceStore(nil, p.repo)
		ops, err := st.listRepoOps(p.ref.String(), limit, since, cursorRev, cursorIdx, hasCursor)
		if err != nil {
			return nil, err
		}
		// A full page leaves the commit off: the caller isn't at head yet.
		var commit *space.SignedCommit
		if len(ops) < limit {
			repoActor, err := s.getRepoActorByDid(e.Request().Context(), p.repo)
			if err != nil {
				return nil, err
			}
			state, err := st.getRepoState(p.ref.String())
			if err != nil {
				return nil, err
			}
			key, err := s.accountSigner(repoActor.Repo)
			if err != nil {
				return nil, err
			}
			if commit, err = buildSignedCommit(p.ref, p.repo, state, key); err != nil {
				return nil, err
			}
		}
		out := make([]map[string]any, 0, len(ops))
		for _, op := range ops {
			m := map[string]any{"rev": op.Rev, "collection": op.Collection, "rkey": op.Rkey, "cid": op.Cid, "prev": op.Prev}
			if !excludeValues && op.Value != nil {
				v, err := decodeSpaceValue(op.Value)
				if err != nil {
					return nil, err
				}
				m["value"] = v
			}
			out = append(out, m)
		}
		res := map[string]any{"ops": out}
		if commit != nil {
			res["commit"] = commit
		} else if len(ops) > 0 {
			last := ops[len(ops)-1]
			res["cursor"] = fmt.Sprintf("%s/%d", last.Rev, last.Idx)
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceGetLatestCommit(e echo.Context) error {
	body, err := func() (any, error) {
		p, err := s.spaceReadAuth(e)
		if err != nil {
			return nil, err
		}
		repoActor, err := s.getRepoActorByDid(e.Request().Context(), p.repo)
		if err != nil {
			return nil, err
		}
		state, err := s.spaceStore(nil, p.repo).getRepoState(p.ref.String())
		if err != nil {
			return nil, err
		}
		key, err := s.accountSigner(repoActor.Repo)
		if err != nil {
			return nil, err
		}
		commit, err := buildSignedCommit(p.ref, p.repo, state, key)
		if err != nil {
			return nil, err
		}
		if commit == nil {
			return nil, errInvalid("RepoNotFound", "Could not find repo for space: %s", p.ref)
		}
		return map[string]any{"commit": commit}, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceListSpaces(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		q := e.QueryParams()
		spaceType, err := parseNSIDParam("spaceType", q.Get("spaceType"), false)
		if err != nil {
			return nil, err
		}
		authority := q.Get("did")
		if authority != "" {
			if _, err := parseDIDParam("did", authority); err != nil {
				return nil, err
			}
		}
		limit, err := parseLimitParam(q.Get("limit"), 50, 1, 100)
		if err != nil {
			return nil, err
		}
		// The filters are the target: an unfiltered listing needs a wildcard
		// grant. Only the caller's own spaces are listed, so read_self fits.
		m := scopes.SpaceMatch{Type: spaceType, Authority: authority, Skey: "*", Action: "read_self"}
		if m.Type == "" {
			m.Type = "*"
		}
		if m.Authority == "" {
			m.Authority = "*"
		}
		if err := a.assertSpace(m); err != nil {
			return nil, err
		}
		rows, err := s.spaceStore(nil, a.did).listSpaces(limit, q.Get("cursor"), spaceType, authority)
		if err != nil {
			return nil, err
		}
		spaces := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			spaces = append(spaces, map[string]any{"uri": r.Uri})
		}
		res := map[string]any{"spaces": spaces}
		if len(rows) >= limit && len(rows) > 0 {
			res["cursor"] = rows[len(rows)-1].Uri
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}
