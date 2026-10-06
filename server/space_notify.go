package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Write notifications, following the reference PDS's space-notifications.ts,
// notifyWrite.ts, registerNotify.ts, unregisterNotify.ts and listRepos.ts at
// bluesky-social/atproto 5b95b2f2.
//
// A writer's PDS sends notifyWrite to the space authority right after each
// commit. Retryable failures are coalesced per repo and space in
// space_notification_retries, and a worker resends the newest state with
// backoff for up to a day. The authority records the writer (sequencing it
// with a spaceRev) and fans the notification out to registered services.

const (
	lxmNotifyWrite         = "com.atproto.space.notifyWrite"
	registrationTTL        = 24 * time.Hour
	notifyRetryWindow      = 24 * time.Hour
	notifyRetryPollEvery   = 10 * time.Second
	notifyFutureRevAllowed = 5 * time.Minute
)

// notifyRetryBase is the first retry pause; tests shorten it.
var notifyRetryBase = time.Minute

var retryableStatus = map[int]bool{408: true, 425: true, 429: true, 500: true, 502: true, 503: true, 504: true, 522: true, 524: true}

type notifyWriteBody struct {
	Space        string         `json:"space"`
	Repo         string         `json:"repo"`
	RepoRev      string         `json:"repoRev"`
	Hash         space.LexBytes `json:"hash"`
	SpaceRev     string         `json:"spaceRev,omitempty"`
	PrevSpaceRev string         `json:"prevSpaceRev,omitempty"`
}

// notifySpaceWrite sends a write notification for a new commit, queueing a
// retry if it fails retryably.
// It returns an error only when a retryable failure could not be queued.
func (s *Server) notifySpaceWrite(ref space.Ref, did string, commit *spaceCommit) error {
	h, err := space.LtHashFromState(commit.SetHash)
	if err != nil {
		return err
	}
	d := h.Digest()
	body := notifyWriteBody{Space: ref.String(), Repo: did, RepoRev: commit.Rev, Hash: d[:]}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.notifyAndQueue(ctx, body)
}

// notifyAndQueue sends a notification, queueing it for retry if it fails
// retryably. It returns an error only when the retry could not be queued.
func (s *Server) notifyAndQueue(ctx context.Context, body notifyWriteBody) error {
	err := s.deliverNotify(ctx, body)
	if err == nil {
		s.clearNotifyRetry(ctx, body.Repo, body.Space, body.RepoRev)
		return nil
	}
	if !isRetryableNotify(err) {
		s.clearNotifyRetry(ctx, body.Repo, body.Space, body.RepoRev)
		s.logger.Warn("space notification will not be retried", "space", body.Space, "repo", body.Repo, "err", err)
		return nil
	}
	row := models.SpaceNotificationRetry{
		Repo: body.Repo, Space: body.Space, RepoRev: body.RepoRev, Hash: body.Hash,
		Attempts: 1, RetryAt: nextRetryAt(1).UnixMilli(), ExpiresAt: time.Now().Add(notifyRetryWindow).UnixMilli(),
	}
	if err := s.db.Client().WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "repo"}, {Name: "space"}},
		DoUpdates: clause.AssignmentColumns([]string{"repo_rev", "hash", "attempts", "retry_at", "expires_at"}),
		Where:     clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "space_notification_retries.repo_rev < excluded.repo_rev"}}},
	}).Create(&row).Error; err != nil {
		s.logger.Error("could not queue space notification", "space", body.Space, "repo", body.Repo, "err", err)
		return fmt.Errorf("could not queue space notification: %w", err)
	}
	s.logger.Warn("space notification queued for retry", "space", body.Space, "repo", body.Repo, "err", err)
	return nil
}

func isRetryableNotify(err error) bool {
	var ce *xrpcCallError
	if errors.As(err, &ce) {
		return retryableStatus[ce.Status]
	}
	var xe *xrpcError
	if errors.As(err, &xe) {
		return retryableStatus[xe.Status]
	}
	// Resolution and storage failures can precede a request.
	return true
}

// nextRetryAt doubles the base pause per attempt up to an hour, with 50-100%
// jitter.
func nextRetryAt(attempts int) time.Time {
	n := attempts - 1
	if n > 6 {
		n = 6
	}
	delay := notifyRetryBase * time.Duration(1<<n)
	if delay > time.Hour {
		delay = time.Hour
	}
	return time.Now().Add(time.Duration(float64(delay) * (0.5 + rand.Float64()/2)))
}

func (s *Server) clearNotifyRetry(ctx context.Context, repo, spaceURI, rev string) {
	if err := s.db.Client().WithContext(ctx).Where("repo = ? AND space = ? AND repo_rev <= ?", repo, spaceURI, rev).Delete(&models.SpaceNotificationRetry{}).Error; err != nil {
		s.logger.Error("could not clear space notification retry", "err", err)
	}
}

// deliverNotify processes the notification here when this host is the
// authority, else sends it to the authority's space host.
func (s *Server) deliverNotify(ctx context.Context, body notifyWriteBody) error {
	ref, err := space.ParseRef(body.Space)
	if err != nil {
		return err
	}
	if _, err := s.getRepoActorByDid(ctx, ref.Authority); err == nil {
		return s.processNotifyWrite(ctx, body)
	}
	target, err := s.resolveNotifyTarget(ctx, body.Repo, ref.HostAud(), lxmNotifyWrite)
	if err != nil {
		return err
	}
	if target == nil {
		return errors.New("could not resolve space host")
	}
	_, err = s.postXRPC(ctx, target, lxmNotifyWrite, body)
	return err
}

// processNotifyWrite handles a write notification when this host is the
// space authority.
func (s *Server) processNotifyWrite(ctx context.Context, body notifyWriteBody) error {
	ref, err := space.ParseRef(body.Space)
	if err != nil {
		return errInvalid("InvalidSpaceUri", "Not a space uri: %s", body.Space)
	}
	if _, err := s.assertSpaceHost(ctx, ref); err != nil {
		return err
	}
	tid, err := syntax.ParseTID(body.RepoRev)
	if err != nil {
		return errInvalid("", "repoRev must be a valid tid")
	}
	if tid.Time().After(time.Now().Add(notifyFutureRevAllowed)) {
		return errInvalid("FutureRev", "Repo revision is in the future")
	}
	st := s.spaceStore(nil, ref.Authority)
	sp, err := st.getSpace(ref.String())
	if err != nil {
		return err
	}
	cfg, err := st.getSpaceConfig(ref.String())
	if err != nil {
		return err
	}
	if cfg == nil || sp == nil || sp.DeletedAt != nil {
		return errSpaceNotFound()
	}
	recipients, err := st.activeRecipients(ref.String())
	if err != nil {
		return err
	}
	// The same user perimeter as minting a credential; notifyWrite comes from
	// a PDS rather than an app, so there is no attestation to check.
	ok, err := s.authorizeSpaceUser(ctx, cfg, body.Repo, "write", "")
	if err != nil {
		return err
	}
	if !ok {
		return errForbidden("notifyWrite writer is not authorized")
	}
	var seq *writerSequence
	err = s.db.Client().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		seq, err = s.spaceStore(tx, ref.Authority).recordWriter(ref.String(), body.Repo, body.RepoRev, body.Hash)
		return err
	})
	if err != nil || seq == nil {
		return err
	}
	fan := body
	fan.SpaceRev, fan.PrevSpaceRev = seq.spaceRev, seq.prevSpaceRev
	s.goSpace(func(ctx context.Context) {
		for _, r := range recipients {
			if err := s.sendNotify(ctx, ref.Authority, r.ServiceDid, lxmNotifyWrite, fan); err != nil {
				s.logger.Warn("notify failed", "space", ref.String(), "service", r.ServiceDid, "lxm", lxmNotifyWrite, "err", err)
			}
		}
	})
	return nil
}

type writerSequence struct {
	spaceRev     string
	prevSpaceRev string
}

// recordWriter records a newer repo state for a writer and advances the
// space's sequence. Nil when the state is not newer than the last.
func (st *spaceStore) recordWriter(uri, writer, repoRev string, hash []byte) (*writerSequence, error) {
	sp, err := st.getSpace(uri)
	if err != nil {
		return nil, err
	}
	if sp == nil || sp.DeletedAt != nil {
		return nil, errSpaceNotFound()
	}
	var cur models.SpaceWriter
	err = st.db.Where("did = ? AND space = ? AND writer_did = ?", st.did, uri, writer).Take(&cur).Error
	if err == nil && cur.RepoRev >= repoRev {
		return nil, nil
	}
	if err != nil && !notFound(err) {
		return nil, err
	}
	var latest []models.SpaceWriter
	if err := st.db.Where("did = ? AND space = ?", st.did, uri).Order("space_rev desc").Limit(1).Find(&latest).Error; err != nil {
		return nil, err
	}
	prev := ""
	if len(latest) > 0 {
		prev = latest[0].SpaceRev
	}
	rev := nextTID(prev)
	row := models.SpaceWriter{Did: st.did, Space: uri, WriterDid: writer, RepoRev: repoRev, SpaceRev: rev, Hash: hash}
	if err := st.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&row).Error; err != nil {
		return nil, err
	}
	return &writerSequence{spaceRev: rev, prevSpaceRev: prev}, nil
}

func (st *spaceStore) listWriters(uri string, limit int, cursor string) ([]models.SpaceWriter, error) {
	q := st.db.Where("did = ? AND space = ?", st.did, uri).Order("space_rev asc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if cursor != "" {
		q = q.Where("space_rev > ?", cursor)
	}
	var rows []models.SpaceWriter
	return rows, q.Find(&rows).Error
}

func (s *Server) handleSpaceNotifyWrite(e echo.Context) error {
	body, err := func() (any, error) {
		var in notifyWriteBody
		raw, err := readBody(e)
		if err != nil {
			return nil, err
		}
		// A repoRev that is not a TID is refused before any auth check.
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, errInvalid("", "Invalid request body: %v", err)
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if _, err := parseDIDParam("repo", in.Repo); err != nil {
			return nil, err
		}
		if _, err := syntax.ParseTID(in.RepoRev); err != nil {
			return nil, errInvalid("", "Input/repoRev must be a valid TID")
		}
		claims, err := s.verifyServiceAuth(e, lxmNotifyWrite)
		if err != nil {
			return nil, err
		}
		// The signer must be the writer, so a PDS can't notify on another
		// account's behalf.
		if claims.Iss != in.Repo {
			return nil, errForbidden("notifyWrite iss does not match claimed writer")
		}
		if claims.Aud != ref.Authority && claims.Aud != ref.HostAud() {
			return nil, errForbidden("notifyWrite aud does not match the space authority")
		}
		in.SpaceRev, in.PrevSpaceRev = "", ""
		return nil, s.processNotifyWrite(e.Request().Context(), in)
	}()
	return writeSpaceResult(e, body, err)
}

func readBody(e echo.Context) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(e.Response(), e.Request().Body, 1<<20)); err != nil {
		return nil, errInvalid("", "could not read the request body")
	}
	return buf.Bytes(), nil
}

// credentialAuth requires a space credential for the request's space,
// addressed to its authority.
func (s *Server) credentialAuth(e echo.Context, ref space.Ref) (*spaceCredentialAuth, error) {
	if !isSpaceCredentialRequest(e) {
		return nil, errAuthRequired("MissingJwt", "missing space credential")
	}
	c, err := s.verifySpaceCredentialRequest(e)
	if err != nil {
		return nil, err
	}
	if err := assertCredentialSpace(c, ref, ""); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Server) handleSpaceRegisterNotify(e echo.Context) error {
	body, err := func() (any, error) {
		var in struct {
			Space   string `json:"space"`
			Service string `json:"service"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if in.Service == "" {
			return nil, errInvalid("", "Input must have the property \"service\"")
		}
		if _, err := s.credentialAuth(e, ref); err != nil {
			return nil, err
		}
		ctx := e.Request().Context()
		if _, err := s.assertSpaceHost(ctx, ref); err != nil {
			return nil, err
		}
		ep, ok := s.resolveServiceEndpoint(ctx, in.Service)
		if !ok {
			return nil, errInvalid("ServiceNotResolvable", "Could not resolve a service endpoint for %s", in.Service)
		}
		st := s.spaceStore(nil, ref.Authority)
		if _, err := st.getActiveSpaceConfig(ref.String()); err != nil {
			return nil, err
		}
		expiresAt := time.Now().Add(registrationTTL).UTC().Format("2006-01-02T15:04:05.000Z")
		row := models.SpaceCredentialRecipient{Did: ref.Authority, Space: ref.String(), ServiceDid: in.Service, ServiceEndpoint: ep, ExpiresAt: expiresAt}
		if err := s.db.Client().WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&row).Error; err != nil {
			return nil, err
		}
		return map[string]any{"expiresAt": expiresAt}, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceUnregisterNotify(e echo.Context) error {
	body, err := func() (any, error) {
		var in struct {
			Space   string `json:"space"`
			Service string `json:"service"`
		}
		if err := bindSpaceJSON(e, &in); err != nil {
			return nil, err
		}
		ref, err := parseSpaceParam("space", in.Space)
		if err != nil {
			return nil, err
		}
		if in.Service == "" {
			return nil, errInvalid("", "Input must have the property \"service\"")
		}
		if _, err := s.credentialAuth(e, ref); err != nil {
			return nil, err
		}
		ctx := e.Request().Context()
		if _, err := s.assertSpaceHost(ctx, ref); err != nil {
			return nil, err
		}
		if _, err := s.spaceStore(nil, ref.Authority).getActiveSpaceConfig(ref.String()); err != nil {
			return nil, err
		}
		// Not resolved: a service whose DID document changed must still be
		// able to withdraw. Succeeds when nothing was registered.
		return nil, s.db.Client().WithContext(ctx).Where("did = ? AND space = ? AND service_did = ?", ref.Authority, ref.String(), in.Service).Delete(&models.SpaceCredentialRecipient{}).Error
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceListRepos(e echo.Context) error {
	body, err := func() (any, error) {
		q := e.QueryParams()
		ref, err := parseSpaceParam("space", q.Get("space"))
		if err != nil {
			return nil, err
		}
		limit, err := parseLimitParam(q.Get("limit"), 100, 1, 1000)
		if err != nil {
			return nil, err
		}
		if _, err := s.credentialAuth(e, ref); err != nil {
			return nil, err
		}
		if _, err := s.assertSpaceHost(e.Request().Context(), ref); err != nil {
			return nil, err
		}
		st := s.spaceStore(nil, ref.Authority)
		if _, err := st.getActiveSpaceConfig(ref.String()); err != nil {
			return nil, err
		}
		rows, err := st.listWriters(ref.String(), limit, q.Get("cursor"))
		if err != nil {
			return nil, err
		}
		repos := make([]map[string]any, 0, len(rows))
		for _, w := range rows {
			repos = append(repos, map[string]any{"did": w.WriterDid, "repoRev": w.RepoRev, "hash": space.LexBytes(w.Hash), "spaceRev": w.SpaceRev})
		}
		res := map[string]any{"repos": repos}
		if len(rows) > 0 {
			res["cursor"] = rows[len(rows)-1].SpaceRev
		}
		return res, nil
	}()
	return writeSpaceResult(e, body, err)
}

func (s *Server) handleSpaceGetRepo(e echo.Context) error {
	p, err := s.spaceReadAuth(e)
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	excludeValues, err := parseBoolParam(e.QueryParam("excludeValues"))
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	repoActor, err := s.getRepoActorByDid(e.Request().Context(), p.repo)
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	st := s.spaceStore(nil, p.repo)
	state, err := st.getRepoState(p.ref.String())
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	key, err := s.accountSigner(repoActor.Repo)
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	commit, err := buildSignedCommit(p.ref, p.repo, state, key)
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	if commit == nil {
		return writeSpaceResult(e, nil, errInvalid("RepoNotFound", "Could not find repo for space: %s", p.ref))
	}
	rows, err := st.allRecords(p.ref.String())
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	recs := make([]space.SerializedRecord, 0, len(rows))
	for _, r := range rows {
		c, err := cid.Decode(r.Cid)
		if err != nil {
			return writeSpaceResult(e, nil, err)
		}
		recs = append(recs, space.SerializedRecord{Collection: r.Collection, Rkey: r.Rkey, Cid: c, Bytes: r.Value})
	}
	var buf bytes.Buffer
	if err := space.SerializeRepo(&buf, *commit, recs, excludeValues); err != nil {
		return writeSpaceResult(e, nil, err)
	}
	return e.Blob(http.StatusOK, "application/vnd.ipld.car", buf.Bytes())
}

// The retry worker -------------------------------------------------------

type spaceWorker struct {
	once sync.Once
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex // one retry pass at a time
}

// startSpaceWorkers starts the notification retry worker.
func (s *Server) startSpaceWorkers() {
	s.spaceWorker.once.Do(func() {
		s.spaceWorker.stop = make(chan struct{})
		s.spaceWorker.done = make(chan struct{})
		go func() {
			defer close(s.spaceWorker.done)
			t := time.NewTicker(notifyRetryPollEvery)
			defer t.Stop()
			for {
				s.retrySpaceNotifications(context.Background())
				select {
				case <-s.spaceWorker.stop:
					return
				case <-t.C:
				}
			}
		}()
	})
}

// stopSpaceWorkers stops the retry worker and waits for background work.
func (s *Server) stopSpaceWorkers() {
	if s.spaceWorker.stop != nil {
		select {
		case <-s.spaceWorker.stop:
		default:
			close(s.spaceWorker.stop)
		}
		<-s.spaceWorker.done
	}
	s.spaceJobs.Wait()
}

// retrySpaceNotifications resends due notifications.
func (s *Server) retrySpaceNotifications(ctx context.Context) {
	s.spaceWorker.mu.Lock()
	defer s.spaceWorker.mu.Unlock()
	for {
		var due []models.SpaceNotificationRetry
		if err := s.db.Client().WithContext(ctx).Where("retry_at <= ?", time.Now().UnixMilli()).Order("retry_at").Limit(5).Find(&due).Error; err != nil || len(due) == 0 {
			return
		}
		for _, r := range due {
			s.retryNotifyOne(ctx, r)
		}
	}
}

func (s *Server) retryNotifyOne(ctx context.Context, r models.SpaceNotificationRetry) {
	db := s.db.Client().WithContext(ctx)
	if r.ExpiresAt <= time.Now().UnixMilli() {
		db.Where("repo = ? AND space = ? AND expires_at <= ?", r.Repo, r.Space, time.Now().UnixMilli()).Delete(&models.SpaceNotificationRetry{})
		s.logger.Warn("space notification expired after 24 hours", "repo", r.Repo, "space", r.Space)
		return
	}
	repo, err := s.getRepoActorByDid(ctx, r.Repo)
	if err != nil {
		s.clearNotifyRetry(ctx, r.Repo, r.Space, r.RepoRev)
		return
	}
	if repo.Repo.Deactivated || repo.Repo.TakedownRef != nil {
		s.rescheduleNotify(ctx, r)
		return
	}
	body := notifyWriteBody{Space: r.Space, Repo: r.Repo, RepoRev: r.RepoRev, Hash: r.Hash}
	if err := s.deliverNotify(ctx, body); err != nil {
		if !isRetryableNotify(err) {
			s.clearNotifyRetry(ctx, r.Repo, r.Space, r.RepoRev)
			s.logger.Warn("space notification will not be retried", "space", r.Space, "repo", r.Repo, "err", err)
			return
		}
		s.rescheduleNotify(ctx, r)
		return
	}
	s.clearNotifyRetry(ctx, r.Repo, r.Space, r.RepoRev)
}

func (s *Server) rescheduleNotify(ctx context.Context, r models.SpaceNotificationRetry) {
	at := nextRetryAt(r.Attempts + 1).UnixMilli()
	if at > r.ExpiresAt {
		at = r.ExpiresAt
	}
	s.db.Client().WithContext(ctx).Model(&models.SpaceNotificationRetry{}).
		Where("repo = ? AND space = ? AND repo_rev = ? AND attempts = ? AND expires_at = ?", r.Repo, r.Space, r.RepoRev, r.Attempts, r.ExpiresAt).
		Updates(map[string]any{"attempts": r.Attempts + 1, "retry_at": at})
}
