package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
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

// Repo update notifications and syncer notices, following the reference PDS's
// space-notifications.ts and api/com/atproto/space/{notifyRepoUpdate,
// listWriters,util}.ts at bluesky-social/atproto d4def6e9.
//
// A writer's PDS sends notifyRepoUpdate to the space authority right after
// each commit. Retryable failures are coalesced per repo and space in
// space_notification_retries, and a worker resends the newest state with
// backoff for up to a day. The authority records the writer (sequencing it
// with a spaceRev) and forwards the sequenced update, with removals, to the
// endpoints registered through authorizeSpaceSync (notifySpaceUpdate).
//
// Notices to syncers, of a space's deletion or a registration's expiry, are
// retried the same way, but on a slower schedule and for at least 72 hours.

const (
	lxmNotifyRepoUpdate    = "com.atproto.space.notifyRepoUpdate"
	lxmNotifySpaceUpdate   = "com.atproto.space.notifySpaceUpdate"
	lxmConfirmRegistration = "com.atproto.space.confirmRegistration"

	notifyRetryWindow      = 24 * time.Hour
	notifyRetryPollEvery   = 10 * time.Second
	notifyFutureRevAllowed = 5 * time.Minute

	// syncerNotifyConcurrency is how many syncer endpoints a fan-out notifies
	// at once.
	syncerNotifyConcurrency = 50
	syncerNoticeRetryWindow = 72 * time.Hour

	typeRepoWrite           = "com.atproto.space.defs#repoWrite"
	typeRepoRemoved         = "com.atproto.space.defs#repoRemoved"
	typeSpaceDeleted        = "com.atproto.space.notifySpaceUpdate#spaceDeleted"
	typeRegistrationExpired = "com.atproto.space.notifySpaceUpdate#registrationExpired"
)

// syncerNoticeRetryDelays is the pause after each failed delivery of a syncer
// notice in turn, repeating the last. Tests shorten it.
var syncerNoticeRetryDelays = []time.Duration{time.Minute, 10 * time.Minute, time.Hour, 6 * time.Hour, 12 * time.Hour}

// notifyRetryBase is the first retry pause; tests shorten it.
var notifyRetryBase = time.Minute

var retryableStatus = map[int]bool{408: true, 425: true, 429: true, 500: true, 502: true, 503: true, 504: true, 522: true, 524: true}

type notifyRepoUpdateBody struct {
	Space   string         `json:"space"`
	Repo    string         `json:"repo"`
	RepoRev string         `json:"repoRev"`
	Data    space.LexBytes `json:"data"`
}

// fireNotifyRepoUpdate sends a repo update notification for a new commit
// right after it, queueing a retry if it fails retryably. It returns an error
// only when a retryable failure could not be queued. A nil commit, when there
// was nothing to write, sends nothing.
func (s *Server) fireNotifyRepoUpdate(ref space.Ref, did string, commit *spaceCommit) error {
	if commit == nil {
		return nil
	}
	h, err := space.LtHashFromState(commit.SetHash)
	if err != nil {
		return err
	}
	d := h.Digest()
	body := notifyRepoUpdateBody{Space: ref.String(), Repo: did, RepoRev: commit.Rev, Data: d[:]}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.notifyAndQueue(ctx, body)
}

// notifyAndQueue sends a notification, queueing it for retry if it fails
// retryably. It returns an error only when the retry could not be queued.
func (s *Server) notifyAndQueue(ctx context.Context, body notifyRepoUpdateBody) error {
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
		Repo: body.Repo, Space: body.Space, RepoRev: body.RepoRev, Data: body.Data,
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
func (s *Server) deliverNotify(ctx context.Context, body notifyRepoUpdateBody) error {
	ref, err := space.ParseRef(body.Space)
	if err != nil {
		return err
	}
	if _, err := s.getRepoActorByDid(ctx, ref.Authority); err == nil {
		return s.processNotifyRepoUpdate(ctx, body)
	}
	target, err := s.resolveNotifyTarget(ctx, body.Repo, ref.HostAud(), lxmNotifyRepoUpdate)
	if err != nil {
		return err
	}
	if target == nil {
		return errors.New("could not resolve space host")
	}
	_, err = s.postXRPC(ctx, target, lxmNotifyRepoUpdate, body)
	return err
}

// processNotifyRepoUpdate handles a repo update notification when this host is
// the space authority.
func (s *Server) processNotifyRepoUpdate(ctx context.Context, body notifyRepoUpdateBody) error {
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
	policy, err := st.getActiveSpacePolicy(ref.String())
	if err != nil {
		return err
	}
	// The same account perimeter used when minting credentials. The
	// notification comes from a PDS rather than an app, so there is no app
	// attestation to check.
	ok, err := s.authorizeRepo(ctx, ref, policy, body.Repo, "write", "")
	if err != nil {
		return err
	}
	if !ok {
		return errForbidden("Repo is not authorized to write to the space")
	}
	var seq *writerSequence
	err = s.db.Client().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		seq, err = s.spaceStore(tx, ref.Authority).recordWriter(ref.String(), body.Repo, body.RepoRev, body.Data)
		return err
	})
	if err != nil || seq == nil {
		return err
	}
	update := map[string]any{
		"$type": typeRepoWrite, "repo": body.Repo, "repoRev": body.RepoRev,
		"data": body.Data, "spaceRev": seq.spaceRev,
	}
	if seq.prevSpaceRev != "" {
		update["prevSpaceRev"] = seq.prevSpaceRev
	}
	s.forwardSpaceUpdate(ref, update, seq.spaceRev)
	return nil
}

// forwardWriterRemoved tells the syncers registered for a space that a repo
// left its writer set.
func (s *Server) forwardWriterRemoved(ref space.Ref, removed removedWriter) {
	update := map[string]any{"$type": typeRepoRemoved, "repo": removed.Repo, "spaceRev": removed.SpaceRev}
	if removed.PrevSpaceRev != "" {
		update["prevSpaceRev"] = removed.PrevSpaceRev
	}
	s.forwardSpaceUpdate(ref, update, removed.SpaceRev)
}

// forwardSpaceUpdate forwards a sequenced change to the writer set to the
// syncers registered for the space. Fan-out stays in the background so
// neither a local write nor a remote PDS waits on downstream syncing services.
func (s *Server) forwardSpaceUpdate(ref space.Ref, update map[string]any, spaceRev string) {
	s.goSpace(func(ctx context.Context) {
		s.deliverSpaceUpdate(ctx, ref, update, spaceRev)
	})
}

// deliverSpaceUpdate delivers an update to each active registration, on a
// best-effort basis. A registration that has lapsed since the last update is
// sent an expiry notice in place of the update, which is delivered reliably.
func (s *Server) deliverSpaceUpdate(ctx context.Context, ref space.Ref, update map[string]any, spaceRev string) {
	uri := ref.String()
	st := s.spaceStore(nil, ref.Authority)
	regs, err := st.getNotifyRegistrations(uri)
	if err != nil {
		s.logger.Error("could not read space notify registrations", "space", uri, "err", err)
		return
	}
	now := nowISO()
	var active []models.SpaceNotifyRegistration
	for _, r := range regs {
		if r.ExpiresAt > now {
			active = append(active, r)
		}
	}
	// In parallel, so a slow endpoint doesn't hold up delivery to the others.
	s.forEachSyncer(active, func(r models.SpaceNotifyRegistration) {
		if err := s.sendSyncerUpdate(ctx, r.Endpoint, uri, r.Token, update); err != nil {
			s.logger.Warn("notify failed", "space", uri, "endpoint", r.Endpoint, "err", err)
		}
	})

	var lapsed []models.SpaceNotifyRegistration
	err = s.db.Client().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		lapsed, err = s.spaceStore(tx, ref.Authority).claimLapsedNotifyRegistrations(uri, now)
		return err
	})
	if err != nil {
		s.logger.Error("could not claim lapsed space registrations", "space", uri, "err", err)
		return
	}
	if len(lapsed) > 0 {
		s.notifySyncers(ctx, ref, lapsed, syncerNotice{expiredAt: spaceRev})
	}
}

// forEachSyncer runs fn for each registration, syncerNotifyConcurrency at a
// time.
func (s *Server) forEachSyncer(regs []models.SpaceNotifyRegistration, fn func(models.SpaceNotifyRegistration)) {
	sem := make(chan struct{}, syncerNotifyConcurrency)
	var wg sync.WaitGroup
	for _, r := range regs {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(r)
		}()
	}
	wg.Wait()
}

// sendSyncerUpdate posts a notifySpaceUpdate to an endpoint the syncer chose,
// which is fetched as untrusted. It carries no service auth: the token in the
// body authenticates it.
func (s *Server) sendSyncerUpdate(ctx context.Context, endpoint, spaceURI, token string, update map[string]any) error {
	_, err := s.postXRPC(ctx, &notifyTarget{endpoint: strings.TrimRight(endpoint, "/")}, lxmNotifySpaceUpdate,
		map[string]any{"space": spaceURI, "token": token, "update": update})
	return err
}

// syncerNotice is an update the space host must reliably deliver to a
// registered syncer: the space's deletion, or a registration's expiry.
type syncerNotice struct {
	deleted   bool
	expiredAt string // the spaceRev of a registrationExpired notice
}

func (n syncerNotice) update() map[string]any {
	if n.deleted {
		return map[string]any{"$type": typeSpaceDeleted}
	}
	return map[string]any{"$type": typeRegistrationExpired, "spaceRev": n.expiredAt}
}

func parseSyncerNotice(raw string) (syncerNotice, error) {
	var u struct {
		Type     string `json:"$type"`
		SpaceRev string `json:"spaceRev"`
	}
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		return syncerNotice{}, err
	}
	switch u.Type {
	case typeSpaceDeleted:
		return syncerNotice{deleted: true}, nil
	case typeRegistrationExpired:
		return syncerNotice{expiredAt: u.SpaceRev}, nil
	}
	return syncerNotice{}, fmt.Errorf("unknown syncer notice %q", u.Type)
}

// notifySyncers sends a notice to each of the given syncers, persisting
// retryable failures. If a syncer rejects its expiry notice, or can't be
// reached within the retry window, its registration is dropped.
func (s *Server) notifySyncers(ctx context.Context, ref space.Ref, regs []models.SpaceNotifyRegistration, notice syncerNotice) {
	uri := ref.String()
	s.forEachSyncer(regs, func(r models.SpaceNotifyRegistration) {
		err := s.sendSyncerUpdate(ctx, r.Endpoint, uri, r.Token, notice.update())
		if err == nil {
			return
		}
		if !isRetryableNotify(err) {
			s.abandonSyncerNotice(ctx, uri, r.Endpoint, r.Token, notice)
			s.logger.Warn("syncer notification will not be retried", "space", uri, "endpoint", r.Endpoint, "err", err)
			return
		}
		s.queueSyncerNotice(ctx, uri, r.Endpoint, r.Token, notice)
		s.logger.Warn("syncer notification queued for retry", "space", uri, "endpoint", r.Endpoint, "err", err)
	})
}

func (s *Server) queueSyncerNotice(ctx context.Context, uri, endpoint, token string, notice syncerNotice) {
	// Persisting a retry must not fail because the fan-out's own deadline
	// passed while it waited on slow endpoints, but it gets a deadline of its
	// own so a stalled database can't hold the job (and shutdown) forever.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	b, _ := json.Marshal(notice.update())
	row := models.SpaceSyncerNotificationRetry{
		Space: uri, Endpoint: endpoint, Token: token, NoticeJson: string(b), Attempts: 1,
		RetryAt: nextSyncerRetryAt(1).UnixMilli(), ExpiresAt: time.Now().Add(syncerNoticeRetryWindow).UnixMilli(),
	}
	oc := clause.OnConflict{Columns: []clause.Column{{Name: "space"}, {Name: "endpoint"}, {Name: "token"}}}
	if notice.deleted {
		// A deletion notice replaces whatever is pending.
		oc.DoUpdates = clause.AssignmentColumns([]string{"notice_json", "attempts", "retry_at", "expires_at"})
	} else {
		// An expiry notice never replaces a pending notice, so a deletion
		// notice is never lost.
		oc.DoNothing = true
	}
	if err := s.db.Client().WithContext(ctx).Clauses(oc).Create(&row).Error; err != nil {
		s.logger.Error("could not queue syncer notification", "space", uri, "endpoint", endpoint, "err", err)
	}
}

// abandonSyncerNotice gives up on delivering a notice. A syncer that rejects
// its expiry notice, or can't be reached, is unregistered, unless it has
// renewed since. A deleted space's registrations were already dropped with it.
func (s *Server) abandonSyncerNotice(ctx context.Context, uri, endpoint, token string, notice syncerNotice) {
	if notice.deleted {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	ref, err := space.ParseRef(uri)
	if err != nil {
		return
	}
	if err := s.spaceStore(s.db.Client().WithContext(ctx), ref.Authority).removeLapsedNotifyRegistration(uri, endpoint, token, time.Now()); err != nil {
		s.logger.Error("could not drop a syncer registration", "space", uri, "endpoint", endpoint, "err", err)
	}
}

func nextSyncerRetryAt(attempts int) time.Time {
	delays := syncerNoticeRetryDelays
	delay := delays[min(attempts, len(delays))-1]
	return time.Now().Add(time.Duration(float64(delay) * (0.5 + rand.Float64()/2)))
}

func (s *Server) handleSpaceNotifyRepoUpdate(e echo.Context) error {
	body, err := func() (any, error) {
		var in notifyRepoUpdateBody
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
		if in.Data == nil {
			return nil, errInvalid("", "Input must have the property \"data\"")
		}
		claims, err := s.verifyServiceAuth(e, lxmNotifyRepoUpdate)
		if err != nil {
			return nil, err
		}
		// iss is the signer, so requiring it to match keeps a PDS from
		// notifying on another account's behalf.
		if claims.Iss != in.Repo {
			return nil, errForbidden("Notification iss does not match the repo")
		}
		// A PDS answers for many authorities, so the audience is only
		// knowable from the space the body names.
		if claims.Aud != ref.Authority && claims.Aud != ref.HostAud() {
			return nil, errForbidden("Notification aud does not match the space authority")
		}
		return nil, s.processNotifyRepoUpdate(e.Request().Context(), in)
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
	if err := checkAuthScheme(e); err != nil {
		return nil, err
	}
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

func (s *Server) handleSpaceListWriters(e echo.Context) error {
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
		cursor := q.Get("cursor")
		if _, err := s.credentialAuth(e, ref); err != nil {
			return nil, err
		}
		if err := s.assertActiveSpaceHost(e.Request().Context(), ref); err != nil {
			return nil, err
		}
		st := s.spaceStore(nil, ref.Authority)
		if _, err := st.getActiveSpacePolicy(ref.String()); err != nil {
			return nil, err
		}
		rows, err := st.listWriters(ref.String(), limit, cursor)
		if err != nil {
			return nil, err
		}
		repos := make([]map[string]any, 0, len(rows))
		for _, w := range rows {
			if w.RemovedAt != nil {
				repos = append(repos, map[string]any{"$type": typeRepoRemoved, "repo": w.WriterDid, "spaceRev": w.SpaceRev})
				continue
			}
			repos = append(repos, map[string]any{"$type": typeRepoWrite, "repo": w.WriterDid, "repoRev": w.RepoRev, "data": space.LexBytes(w.Data), "spaceRev": w.SpaceRev})
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
	mac, err := s.spaceMacRequest(e, p, space.CommitMacProfile)
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	st := s.spaceStore(nil, p.repo)
	state, err := st.getRepoState(p.ref.String())
	if err != nil {
		return writeSpaceResult(e, nil, err)
	}
	commit, err := buildCommit(p.ref, p.repo, state)
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
	// The archive needs strict path order. Sorting here rather than in SQL
	// keeps the order bytewise whatever the database's collation.
	sort.Slice(recs, func(i, j int) bool {
		return space.FormatRecordPath(recs[i].Collection, recs[i].Rkey) < space.FormatRecordPath(recs[j].Collection, recs[j].Rkey)
	})
	var buf bytes.Buffer
	if err := space.SerializeRepo(&buf, *commit, recs); err != nil {
		return writeSpaceResult(e, nil, err)
	}
	setCommitMac(e, mac, *commit)
	return e.Blob(http.StatusOK, starContentType, buf.Bytes())
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
	s.retrySyncerNotices(ctx)
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
	body := notifyRepoUpdateBody{Space: r.Space, Repo: r.Repo, RepoRev: r.RepoRev, Data: r.Data}
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

// retrySyncerNotices resends due syncer notices.
func (s *Server) retrySyncerNotices(ctx context.Context) {
	// Bounded: a row whose reschedule fails would otherwise be reselected
	// forever, holding up the write-notification retries on this worker.
	for pass := 0; pass < 100; pass++ {
		var due []models.SpaceSyncerNotificationRetry
		if err := s.db.Client().WithContext(ctx).Where("retry_at <= ?", time.Now().UnixMilli()).Order("retry_at").Limit(5).Find(&due).Error; err != nil || len(due) == 0 {
			return
		}
		for _, r := range due {
			s.retrySyncerNotice(ctx, r)
		}
	}
}

func (s *Server) retrySyncerNotice(ctx context.Context, r models.SpaceSyncerNotificationRetry) {
	notice, err := parseSyncerNotice(r.NoticeJson)
	ref, err2 := space.ParseRef(r.Space)
	if err != nil || err2 != nil {
		s.clearSyncerRetry(ctx, r)
		return
	}
	authority, err := s.getRepoActorByDid(ctx, ref.Authority)
	if err != nil {
		if notFound(err) {
			// Deleting the authority's account deleted its spaces with it,
			// which syncers learn from the account event.
			s.clearSyncerRetry(ctx, r)
		} else {
			s.rescheduleSyncerRetry(ctx, r, notice)
		}
		return
	}
	if authority.Repo.Deactivated || authority.Repo.TakedownRef != nil {
		s.rescheduleSyncerRetry(ctx, r, notice)
		return
	}
	owed, err := s.isSyncerNoticeOwed(ctx, ref, r, notice)
	if err != nil {
		s.rescheduleSyncerRetry(ctx, r, notice)
		return
	}
	if !owed {
		s.clearSyncerRetry(ctx, r)
		return
	}
	if err := s.sendSyncerUpdate(ctx, r.Endpoint, r.Space, r.Token, notice.update()); err != nil {
		if !isRetryableNotify(err) {
			s.clearSyncerRetry(ctx, r)
			s.abandonSyncerNotice(ctx, r.Space, r.Endpoint, r.Token, notice)
			s.logger.Warn("syncer notification will not be retried", "space", r.Space, "endpoint", r.Endpoint, "err", err)
			return
		}
		s.rescheduleSyncerRetry(ctx, r, notice)
		s.logger.Warn("syncer notification retry failed", "space", r.Space, "endpoint", r.Endpoint, "err", err)
		return
	}
	s.clearSyncerRetry(ctx, r)
}

// isSyncerNoticeOwed reports whether a notice still applies. One that no
// longer does is dropped rather than sent.
func (s *Server) isSyncerNoticeOwed(ctx context.Context, ref space.Ref, r models.SpaceSyncerNotificationRetry, notice syncerNotice) (bool, error) {
	st := s.spaceStore(s.db.Client().WithContext(ctx), ref.Authority)
	if !notice.deleted {
		// Not owed if the syncer has renewed since.
		reg, err := st.getNotifyRegistration(r.Space, r.Endpoint, r.Token)
		if err != nil {
			return false, err
		}
		return reg != nil && reg.ExpiresAt <= nowISO(), nil
	}
	// Not owed if the space has been recreated since.
	sp, err := st.getSpace(r.Space)
	if err != nil {
		return false, err
	}
	return sp != nil && sp.DeletedAt != nil, nil
}

// rescheduleSyncerRetry: retries aren't scheduled to stop at the end of the
// window, so the last one lands after it. Once that one has failed too, the
// notice is abandoned.
func (s *Server) rescheduleSyncerRetry(ctx context.Context, r models.SpaceSyncerNotificationRetry, notice syncerNotice) {
	if r.ExpiresAt <= time.Now().UnixMilli() {
		s.clearSyncerRetry(ctx, r)
		s.abandonSyncerNotice(ctx, r.Space, r.Endpoint, r.Token, notice)
		s.logger.Warn("syncer notification expired after 72 hours", "space", r.Space, "endpoint", r.Endpoint)
		return
	}
	attempts := r.Attempts + 1
	// Matching retry_at leaves alone a row re-queued since.
	if err := s.db.Client().WithContext(ctx).Model(&models.SpaceSyncerNotificationRetry{}).
		Where("space = ? AND endpoint = ? AND token = ? AND retry_at = ?", r.Space, r.Endpoint, r.Token, r.RetryAt).
		Updates(map[string]any{"attempts": attempts, "retry_at": nextSyncerRetryAt(attempts).UnixMilli()}).Error; err != nil {
		s.logger.Error("could not reschedule syncer notification", "space", r.Space, "endpoint", r.Endpoint, "err", err)
	}
}

func (s *Server) clearSyncerRetry(ctx context.Context, r models.SpaceSyncerNotificationRetry) {
	if err := s.db.Client().WithContext(ctx).Where("space = ? AND endpoint = ? AND token = ? AND retry_at = ?", r.Space, r.Endpoint, r.Token, r.RetryAt).Delete(&models.SpaceSyncerNotificationRetry{}).Error; err != nil {
		s.logger.Error("could not clear syncer notification retry", "err", err)
	}
}
