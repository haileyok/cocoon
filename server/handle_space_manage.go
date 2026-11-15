package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// com.atproto.space.{createSpace,updateSpace,getSpace,deleteSpace,
// removeWriter,clearRecords,importRepo,exportSpaceMeta,importSpaceMeta} and
// com.atproto.memberspace.*: the lifecycle of the spaces an account governs
// and the member list of its memberspaces, following the reference PDS
// (api/com/atproto/{space,memberspace}) at bluesky-social/atproto d4def6e9.

// maxMemberBatch is how many entries putMembers and removeMembers take.
const maxMemberBatch = 100

func (s *Server) handleSpaceCreateSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		var in struct {
			SpaceType string         `json:"spaceType"`
			Skey      string         `json:"skey"`
			Policy    map[string]any `json:"policy"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		if _, err := parseNSIDParam("spaceType", in.SpaceType, true); err != nil {
			return nil, err
		}
		if in.Skey == "" {
			in.Skey = nextTID("")
		}
		if _, err := parseRkeyParam("skey", in.Skey, true); err != nil {
			return nil, err
		}
		if in.Policy == nil {
			return nil, errInvalid("", "Input must have the property \"policy\"")
		}
		ref := space.Ref{Authority: a.did, Type: in.SpaceType, Skey: in.Skey}
		if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Manage: "create"}); err != nil {
			return nil, err
		}
		commit, err := s.createSpace(e.Request().Context(), ref, in.Policy)
		if err != nil {
			return nil, err
		}
		if err := s.fireNotifyRepoUpdate(ref, a.did, commit); err != nil {
			return nil, err
		}
		return map[string]any{"space": ref.String()}, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceUpdateSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		var in struct {
			Space  string         `json:"space"`
			Policy map[string]any `json:"policy"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if in.Policy == nil {
			return nil, errInvalid("", "Input must have the property \"policy\"")
		}
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		commit, err := s.updateSpace(e.Request().Context(), ref, in.Policy)
		if err != nil {
			return nil, err
		}
		return nil, s.fireNotifyRepoUpdate(ref, a.did, commit)
	}()
	return writeSpaceResult(e, body, err)
}

// handleSpaceGetSpace is OAuth only: the policy is the authority's own state,
// so a space credential does not reach it. A policy can publish itself to
// readers instead.
func (s *Server) handleSpaceGetSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", e.QueryParam("space"))
		if err != nil {
			return nil, err
		}
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Action: "read_self"}); err != nil {
			return nil, err
		}
		policy, err := s.spaceStore(nil, ref.Authority).getActiveSpacePolicy(ref.String())
		if err != nil {
			return nil, err
		}
		return map[string]any{"space": ref.String(), "policy": policy.lex()}, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceDeleteSpace(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		var in struct {
			Space string `json:"space"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Manage: "delete"}); err != nil {
			return nil, err
		}
		sp, err := s.spaceStore(nil, a.did).getSpace(ref.String())
		if err != nil {
			return nil, err
		}
		if sp == nil {
			return nil, errSpaceNotFound()
		}
		if sp.DeletedAt != nil {
			return nil, nil
		}
		regs, err := s.deleteSpace(e.Request().Context(), ref)
		if err != nil {
			return nil, err
		}
		s.goSpace(func(ctx context.Context) {
			s.notifySyncers(ctx, ref, regs, syncerNotice{deleted: true})
		})
		return nil, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceRemoveWriter(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		var in struct {
			Space string `json:"space"`
			Repo  string `json:"repo"`
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
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		removed, err := s.removeWriter(e.Request().Context(), ref, in.Repo)
		if err != nil {
			return nil, err
		}
		if removed != nil {
			s.forwardWriterRemoved(ref, *removed)
		}
		return nil, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceClearRecords(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		var in struct {
			Space string `json:"space"`
			Repo  string `json:"repo"`
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
		if in.Repo != a.did {
			return nil, errForbidden("repo must match authenticated user")
		}
		// In the authority's own repo, the published policy and member records
		// are the PDS's copy of the space's configuration rather than the
		// account's records, so they stay, and keeping them takes no grant.
		var keep []string
		if ref.Authority == a.did {
			keep = publishedCollections
		}
		commit, err := s.clearRecords(e.Request().Context(), a.did, ref, func(_ *spaceStore, collections []string) error {
			for _, c := range collections {
				if containsString(keep, c) {
					continue
				}
				if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Action: "delete", Collection: c}); err != nil {
					return err
				}
			}
			return nil
		}, keep)
		if err != nil {
			return nil, err
		}
		if err := s.fireNotifyRepoUpdate(ref, a.did, commit); err != nil {
			return nil, err
		}
		return map[string]any{}, nil
	}()
	return writeSpaceResult(e, body, err)
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// readImportBody reads an archive request body, up to the same size limit as
// com.atproto.repo.importRepo.
func (s *Server) readImportBody(e echo.Context) (io.Reader, error) {
	b, err := io.ReadAll(http.MaxBytesReader(e.Response(), e.Request().Body, importRepoMaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, &xrpcError{Status: http.StatusRequestEntityTooLarge, Name: "RequestEntityTooLarge", Message: "imported archive exceeds the size limit"}
		}
		return nil, errInvalid("", "could not read the request body")
	}
	return bytes.NewReader(b), nil
}

// archiveError reports a malformed archive under the error name the method
// declares for it.
func archiveError(err error, name string) error {
	var pe *space.StarParseError
	var ve *space.RepoVerificationError
	var me *space.SpaceMetaArchiveError
	if errors.As(err, &pe) || errors.As(err, &ve) || errors.As(err, &me) {
		return errInvalid(name, "%s", err.Error())
	}
	return err
}

func (s *Server) handleSpaceImportRepo(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertNotTakenDown(a.did); err != nil {
			return nil, err
		}
		if err := checkImportContentType(e); err != nil {
			return nil, err
		}
		in, err := s.readImportBody(e)
		if err != nil {
			return nil, err
		}
		// Read whole before the transaction, as com.atproto.repo.importRepo
		// does with its CAR.
		rr, err := space.ReadRepoStar(in)
		if err != nil {
			return nil, archiveError(err, "InvalidRepoFile")
		}
		var records []space.VerifiedRecord
		for {
			rec, err := rr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, archiveError(err, "InvalidRepoFile")
			}
			records = append(records, *rec)
		}
		if rr.Commit.Repo != a.did {
			return nil, errInvalid("RepoMismatch", "Repo does not match the authenticated account")
		}
		ref, err := space.ParseRef(rr.Commit.Space)
		if err != nil {
			return nil, archiveError(&space.RepoVerificationError{Message: "invalid space"}, "InvalidRepoFile")
		}
		seen := map[string]bool{}
		for _, rec := range records {
			if seen[rec.Collection] {
				continue
			}
			seen[rec.Collection] = true
			if err := a.assertSpaceRef(ref, scopes.SpaceMatch{Action: "create", Collection: rec.Collection}); err != nil {
				return nil, err
			}
		}
		unlock := s.lockRepoWrite(a.did)
		defer unlock()
		return nil, s.db.Client().WithContext(e.Request().Context()).Transaction(func(tx *gorm.DB) error {
			return s.spaceStore(tx, a.did).importRepo(ref, records)
		})
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceExportSpaceMeta(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", e.QueryParam("space"))
		if err != nil {
			return nil, err
		}
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Action: "read_self"}); err != nil {
			return nil, err
		}
		archive, err := s.exportSpaceMeta(e.Request().Context(), ref)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := space.WriteSpaceMetaStar(&buf, *archive); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}()
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	return e.Blob(http.StatusOK, starContentType, body.([]byte))
}

func (s *Server) handleSpaceImportSpaceMeta(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertNotTakenDown(a.did); err != nil {
			return nil, err
		}
		if err := checkImportContentType(e); err != nil {
			return nil, err
		}
		in, err := s.readImportBody(e)
		if err != nil {
			return nil, err
		}
		archive, err := space.ReadSpaceMetaStar(in)
		if err != nil {
			return nil, archiveError(err, "InvalidSpaceMeta")
		}
		ref, err := space.ParseRef(archive.Space)
		if err != nil {
			return nil, archiveError(&space.SpaceMetaArchiveError{Message: "invalid space"}, "InvalidSpaceMeta")
		}
		// Importing both creates the space on this host and sets its
		// configuration.
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Manage: "create"}); err != nil {
			return nil, err
		}
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		return nil, s.importSpaceMeta(e.Request().Context(), ref, archive)
	}()
	return writeSpaceResult(e, body, err)
}

// checkImportContentType requires the STAR content type an archive is sent
// with.
func checkImportContentType(e echo.Context) error {
	ct := e.Request().Header.Get("Content-Type")
	if mt, _, _ := mime.ParseMediaType(ct); mt != starContentType {
		return errInvalid("", "Content-Type must be %s", starContentType)
	}
	return nil
}

// com.atproto.memberspace.*

type memberInput struct {
	Did   string `json:"did"`
	Read  *bool  `json:"read"`
	Write *bool  `json:"write"`
}

func (s *Server) handleMemberspacePutMembers(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		var in struct {
			Space   string        `json:"space"`
			Members []memberInput `json:"members"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if in.Members == nil {
			return nil, errInvalid("", "Input must have the property \"members\"")
		}
		if len(in.Members) > maxMemberBatch {
			return nil, errInvalid("", "Input/members must not have more than %d elements", maxMemberBatch)
		}
		members := make([]memberEntry, len(in.Members))
		for i, m := range in.Members {
			if _, err := parseDIDParam("members/"+strconv.Itoa(i)+"/did", m.Did); err != nil {
				return nil, err
			}
			if m.Read == nil || m.Write == nil {
				return nil, errInvalid("", "Input/members/%d must have the properties \"read\" and \"write\"", i)
			}
			members[i] = memberEntry{Did: m.Did, Read: *m.Read, Write: *m.Write}
		}
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		commit, removed, err := s.putMembers(e.Request().Context(), ref, members)
		if err != nil {
			return nil, err
		}
		for _, r := range removed {
			s.forwardWriterRemoved(ref, r)
		}
		return nil, s.fireNotifyRepoUpdate(ref, a.did, commit)
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleMemberspaceRemoveMembers(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		if err := s.assertSpaceWriter(a); err != nil {
			return nil, err
		}
		var in struct {
			Space string   `json:"space"`
			Dids  []string `json:"dids"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if in.Dids == nil {
			return nil, errInvalid("", "Input must have the property \"dids\"")
		}
		if len(in.Dids) > maxMemberBatch {
			return nil, errInvalid("", "Input/dids must not have more than %d elements", maxMemberBatch)
		}
		for i, d := range in.Dids {
			if _, err := parseDIDParam("dids/"+strconv.Itoa(i), d); err != nil {
				return nil, err
			}
		}
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Manage: "update"}); err != nil {
			return nil, err
		}
		commit, removed, err := s.removeMembers(e.Request().Context(), ref, in.Dids)
		if err != nil {
			return nil, err
		}
		for _, r := range removed {
			s.forwardWriterRemoved(ref, r)
		}
		return nil, s.fireNotifyRepoUpdate(ref, a.did, commit)
	}()
	return writeSpaceResult(e, body, err)
}

// handleMemberspaceListMembers is OAuth only: the member list is the
// authority's own state, so a space credential does not reach it.
func (s *Server) handleMemberspaceListMembers(e echo.Context) error {
	body, err := func() (any, error) {
		a, err := accountAuth(e)
		if err != nil {
			return nil, err
		}
		q := e.QueryParams()
		ref, err := parseSpaceParam("space", q.Get("space"))
		if err != nil {
			return nil, err
		}
		limit, err := parseLimitParam(q.Get("limit"), 100, 1, 1000)
		if err != nil {
			return nil, err
		}
		cursor := q.Get("cursor")
		if err := assertSpaceAuthority(a, ref, scopes.SpaceMatch{Action: "read_self"}); err != nil {
			return nil, err
		}
		if cursor != "" && !validDID(cursor) {
			return nil, errInvalid("InvalidCursor", "Malformed cursor")
		}
		st := s.spaceStore(nil, a.did)
		policy, err := st.getActiveSpacePolicy(ref.String())
		if err != nil {
			return nil, err
		}
		if err := policy.assertMemberspace(); err != nil {
			return nil, err
		}
		rows, err := st.listMembers(ref.String(), limit, cursor)
		if err != nil {
			return nil, err
		}
		members := make([]map[string]any, 0, len(rows))
		for _, m := range rows {
			members = append(members, map[string]any{"did": m.MemberDid, "read": m.Read, "write": m.Write})
		}
		res := map[string]any{"members": members}
		if len(rows) > 0 {
			res["cursor"] = rows[len(rows)-1].MemberDid
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}

func validDID(s string) bool {
	_, err := syntax.ParseDID(s)
	return err == nil
}
