package server

// Ported from the reference PDS's Spaces notification tests
// (bluesky-social/atproto d4def6e9):
//
//   - packages/pds/tests/space/notifications.test.ts: the write-notification
//     retry queue (describe "space notification retries") and reliable syncer
//     notices (describe "syncer notices": spaceDeleted / registrationExpired
//     delivery, backoff and abandonment).
//   - the describe "notify registration" block of
//     packages/pds/tests/space/policy.test.ts: registering an endpoint through
//     authorizeSpaceSync, the confirmRegistration challenge, renewal, lapse and
//     the expiry notice, withdrawal, and the notifySpaceUpdate bodies.
//   - two notifySpaceUpdate body cases from packages/pds/tests/space/sync.test.ts
//     ("chains forwarded notifications across local and remote writers" and
//     "forwards a removal from the writer set, in the space sequence").
//
// The reference drives a SpaceNotifications class with jest-spied
// collaborators; Cocoon's equivalent is server/space_notify.go, driven here
// through notifyAndQueue (the reference's awaited notify()), notifySyncers (its
// notifySyncers()), and retrySpaceNotifications (its retryPending(); the
// background worker goroutine is not started by this harness, so a retry pass
// runs only when a case calls it).
//
// Where the reference injects a failure with a jest spy, this port uses the
// closest seam that needs no change to non-test code:
//   - a failing DID resolution: the shared DID directory taken down,
//   - a failing local storage read: the space_policies table dropped for the
//     duration of one delivery (recreated with its rows afterwards), which is
//     the retryable storage failure the reference's actorStore.read spy
//     produces,
//   - a failing queue write: the retry table dropped,
//   - a delivery paused mid-request: a mock response held on a channel, so a
//     second notification can run while the first is in flight,
//   - a lapsed registration: expires_at moved into the past in the database
//     (the reference's lapseRegistration helper), never a sleep.
//
// Not applicable to Cocoon, with the reason:
//   - "elects one retry worker and allows takeover after its lease expires":
//     there is no retry lease; one worker takes a mutex (retrySpaceNotifications
//     in server/space_notify.go).
//   - "retries local HTTP %s failures": Cocoon's local notify path never
//     answers with a retryable HTTP status (its local refusals are 400/403 XRPC
//     errors, its local failures are storage errors), so the portable part — a
//     local failure is queued and retried with no HTTP call — is ported through
//     a storage failure instead.
//
// The reference puts its member actors on other PDSes; here members share the
// authority's PDS, which changes only the transport of a member's write
// notification (in-process rather than over HTTP), not the fan-out.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
)

// notifNet is the network for the write-notification retry cases: a writer and
// an outsider on one PDS, a space the writer governs locally, and a mock
// service standing in for a remote space host whose answers each case controls.
type notifNet struct {
	net              *spaceNet
	pds1             *spacePDS
	writer, outsider *actor
	host             *mockService
	spaceURI         string // ungoverned: the authority is the mock's DID
	localSpace       string // governed by the writer, on pds1

	mu             sync.Mutex
	status         int
	errName        string
	defaultRespond func(*http.Request, mockCall) (int, any)
}

// newNotifNet is the reference's beforeAll: the writer's local space, and a
// mock service that the reference mounts as a space host.
func newNotifNet(t *testing.T) *notifNet {
	t.Helper()
	n := &notifNet{net: newSpaceNet(t), status: 200}
	n.pds1 = n.net.newPDS()
	n.writer = n.pds1.createActor("writer")
	n.outsider = n.pds1.createActor("outsider")
	n.localSpace = createSpace(t, n.writer, spaceOpts{skey: "notifications"})
	n.defaultRespond = func(r *http.Request, c mockCall) (int, any) {
		n.mu.Lock()
		status, errName := n.status, n.errName
		n.mu.Unlock()
		body := any(map[string]any{})
		if errName != "" {
			body = map[string]any{"error": errName}
		}
		return status, body
	}
	n.host = n.net.newMockService("atproto_pds", n.defaultRespond)
	n.spaceURI = "at://" + n.host.did + "/space/" + testSpaceType + "/notifications"
	return n
}

// setResponse controls the mock space host's answer, restoring the previous one
// when the returned func is called.
func (n *notifNet) setResponse(status int, errName string) func() {
	n.mu.Lock()
	s0, e0 := n.status, n.errName
	n.status, n.errName = status, errName
	n.mu.Unlock()
	return func() {
		n.mu.Lock()
		n.status, n.errName = s0, e0
		n.mu.Unlock()
	}
}

// reset is the reference's beforeEach: the default answer and no queued work.
func (n *notifNet) reset(t *testing.T) {
	t.Helper()
	n.setResponse(200, "")()
	n.host.setRespond(n.defaultRespond)
	n.host.mu.Lock()
	n.host.calls = n.host.calls[:0]
	n.host.mu.Unlock()
	for _, m := range []any{&models.SpaceNotificationRetry{}, &models.SpaceSyncerNotificationRetry{}} {
		if err := n.pds1.s.db.Client().Where("1 = 1").Delete(m).Error; err != nil {
			t.Fatal(err)
		}
	}
}

// notifyBody is the notifyRepoUpdate body for a commit, built without the
// testing.T so it is safe to call from a helper goroutine.
func (n *notifNet) notifyBody(spaceURI, did string, commit *notifCommit) (notifyRepoUpdateBody, bool) {
	h, err := space.LtHashFromState(commit.setHash)
	if err != nil {
		return notifyRepoUpdateBody{}, false
	}
	d := h.Digest()
	return notifyRepoUpdateBody{Space: spaceURI, Repo: did, RepoRev: commit.rev, Data: d[:]}, true
}

// notifyNow sends one notification synchronously, as the reference's awaited
// notifications.notify does.
func (n *notifNet) notifyNow(t *testing.T, spaceURI, did string, commit *notifCommit) {
	t.Helper()
	body, ok := n.notifyBody(spaceURI, did, commit)
	if !ok {
		t.Fatal("could not build the notification body")
	}
	if err := n.pds1.s.notifyAndQueue(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	n.net.waitSpaceJobs()
}

// retryPass runs one retry pass, as the reference's awaited retryPending does.
func (n *notifNet) retryPass(t *testing.T) {
	t.Helper()
	n.pds1.s.retrySpaceNotifications(context.Background())
	n.net.waitSpaceJobs()
}

// notifCommit is the reference's makeCommit(): a fresh rev with the empty set
// hash state. Setting setHash[0] = 1 varies the digest, as the reference's does.
type notifCommit struct {
	rev     string
	setHash []byte
}

func makeNotifCommit() *notifCommit {
	return &notifCommit{rev: nextTID(""), setHash: space.NewLtHash().State()}
}

func notifDigest(t *testing.T, c *notifCommit) []byte {
	t.Helper()
	h, err := space.LtHashFromState(c.setHash)
	if err != nil {
		t.Fatal(err)
	}
	d := h.Digest()
	return d[:]
}

// notifRetryRows are the queued write-notification retries.
func notifRetryRows(t *testing.T, n *notifNet) []models.SpaceNotificationRetry {
	t.Helper()
	var rows []models.SpaceNotificationRetry
	if err := n.pds1.s.db.Client().Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// notifRetryRow returns the single queued retry row, failing on none or many.
func notifRetryRow(t *testing.T, n *notifNet) models.SpaceNotificationRetry {
	t.Helper()
	rows := notifRetryRows(t, n)
	if len(rows) != 1 {
		t.Fatalf("expected one retry row, got %d", len(rows))
	}
	return rows[0]
}

// notifMakeDue makes every retry row due now, as the reference's makeDue does.
func notifMakeDue(t *testing.T, n *notifNet) {
	t.Helper()
	if err := n.pds1.s.db.Client().
		Model(&models.SpaceNotificationRetry{}).
		Where("1 = 1").
		Update("retry_at", time.Now().Add(-time.Second).UnixMilli()).Error; err != nil {
		t.Fatal(err)
	}
}

// notifHashEquals asserts a queued hash is the digest of the commit's set hash.
func notifHashEquals(t *testing.T, hash []byte, commit *notifCommit) {
	t.Helper()
	if string(hash) != string(notifDigest(t, commit)) {
		t.Fatal("the queued hash does not match the commit digest")
	}
}

// notifDropPolicies makes a local delivery fail retryably, as the reference's
// actorStore.read spy does: the local notify path reads the space's policy, and
// a missing table is a storage error, which is retryable. The returned func
// recreates the table with its rows.
func notifDropPolicies(t *testing.T, p *spacePDS) func() {
	t.Helper()
	db := p.s.db
	var rows []models.SpacePolicy
	if err := db.Client().Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(context.Background(), "DROP TABLE space_policies", nil).Error; err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := db.AutoMigrate(&models.SpacePolicy{}); err != nil {
				t.Fatal(err)
			}
			if len(rows) > 0 {
				if err := db.Client().Create(&rows).Error; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// holdDelivery wraps the mock's responder so the delivery of the commit with
// rev holdRev is paused until release is called, letting a second notification
// run while the first is in flight, as the reference's once-only resolver spy
// does. started returns once the held request has reached the mock. Holding by
// rev (rather than by arrival order) keeps the hold deterministic.
func (n *notifNet) holdDelivery(holdRev string) (started, release func(), restore func()) {
	startedCh, releaseCh := make(chan struct{}), make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	n.host.setRespond(func(r *http.Request, c mockCall) (int, any) {
		if rev, _ := c.body["repoRev"].(string); rev == holdRev {
			startedOnce.Do(func() { close(startedCh) })
			<-releaseCh
		}
		return n.defaultRespond(r, c)
	})
	return func() { <-startedCh }, func() { releaseOnce.Do(func() { close(releaseCh) }) }, func() {
		releaseOnce.Do(func() { close(releaseCh) })
		n.host.setRespond(n.defaultRespond)
	}
}

func TestSpaceNotificationsRepoUpdateRetries(t *testing.T) {
	n := newNotifNet(t)

	t.Run("sends immediately without queueing a successful notification", func(t *testing.T) {
		n.reset(t)
		commit := makeNotifCommit()
		n.notifyNow(t, n.spaceURI, n.writer.did, commit)
		calls := n.host.callsTo(lxmNotifyRepoUpdate)
		if len(calls) != 1 {
			t.Fatalf("expected 1 notifyRepoUpdate call, got %d", len(calls))
		}
		if got := calls[0].body["space"]; got != n.spaceURI {
			t.Fatalf("space %v, want %s", got, n.spaceURI)
		}
		if got := calls[0].body["repo"]; got != n.writer.did {
			t.Fatalf("repo %v, want %s", got, n.writer.did)
		}
		if rev, _ := calls[0].body["repoRev"].(string); rev != commit.rev {
			t.Fatalf("repoRev %q, want %q", rev, commit.rev)
		}
		if rows := notifRetryRows(t, n); len(rows) != 0 {
			t.Fatalf("queued %d retry rows", len(rows))
		}
	})

	t.Run("clears an older queued notification when a new write succeeds immediately", func(t *testing.T) {
		n.reset(t)
		older := makeNotifCommit()
		restore := n.setResponse(503, "")
		n.notifyNow(t, n.spaceURI, n.writer.did, older)
		restore()
		if row := notifRetryRow(t, n); row.RepoRev != older.rev {
			t.Fatalf("repoRev %q, want %q", row.RepoRev, older.rev)
		}

		n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
			t.Fatalf("expected 2 notifyRepoUpdate calls, got %d", len(calls))
		}
		if rows := notifRetryRows(t, n); len(rows) != 0 {
			t.Fatalf("queued %d retry rows", len(rows))
		}
	})

	for _, code := range []int{408, 425, 429, 500, 502, 503, 504, 522, 524} {
		t.Run(fmt.Sprintf("persists an HTTP %d response for retry", code), func(t *testing.T) {
			n.reset(t)
			restore := n.setResponse(code, "")
			defer restore()
			commit := makeNotifCommit()
			before := time.Now()
			n.notifyNow(t, n.spaceURI, n.writer.did, commit)
			row := notifRetryRow(t, n)
			if row.Space != n.spaceURI || row.Repo != n.writer.did || row.RepoRev != commit.rev || row.Attempts != 1 {
				t.Fatalf("row %+v", row)
			}
			if row.ExpiresAt < before.Add(24*time.Hour).UnixMilli() || row.ExpiresAt > time.Now().Add(24*time.Hour).UnixMilli() {
				t.Fatalf("expiresAt %d not within a day", row.ExpiresAt)
			}
			notifHashEquals(t, row.Data, commit)

			notifMakeDue(t, n)
			n.retryPass(t)
			if row := notifRetryRow(t, n); row.Attempts != 2 {
				t.Fatalf("attempts %d, want 2", row.Attempts)
			}
			if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
				t.Fatalf("expected 2 notifyRepoUpdate calls, got %d", len(calls))
			}
		})
	}

	t.Run("uses the HTTP status even when the XRPC error name suggests a rejection", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "Forbidden")
		n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
		if row := notifRetryRow(t, n); row.Attempts != 1 {
			t.Fatalf("attempts %d, want 1", row.Attempts)
		}
		notifMakeDue(t, n)
		n.retryPass(t)
		if row := notifRetryRow(t, n); row.Attempts != 2 {
			t.Fatalf("attempts %d, want 2", row.Attempts)
		}
	})

	for _, code := range []int{400, 401, 403, 404, 422, 501} {
		t.Run(fmt.Sprintf("stops retrying HTTP %d with an unfamiliar XRPC error name", code), func(t *testing.T) {
			n.reset(t)
			n.setResponse(code, "CustomRejection")
			n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
			if rows := notifRetryRows(t, n); len(rows) != 0 {
				t.Fatalf("queued %d retry rows", len(rows))
			}

			// A retryable failure queues a fresh row to clear.
			n.setResponse(503, "")
			n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
			if row := notifRetryRow(t, n); row.Attempts != 1 {
				t.Fatalf("attempts %d, want 1", row.Attempts)
			}
			notifMakeDue(t, n)
			n.setResponse(code, "CustomRejection")
			n.retryPass(t)
			if rows := notifRetryRows(t, n); len(rows) != 0 {
				t.Fatalf("queued %d retry rows", len(rows))
			}
			if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 3 {
				t.Fatalf("expected 3 notifyRepoUpdate calls, got %d", len(calls))
			}
		})
	}

	// The reference's "retries local HTTP %s failures" (429, 503) spies the
	// local actor store to reject with an XRPCError carrying a retryable status
	// and a rejecting name. Cocoon's local notify path answers no retryable
	// HTTP status (its local refusals are 400/403 and its failures are storage
	// errors), so the local-status aspect is N/A; the portable part — a local
	// failure is queued and retried with no HTTP call — is ported as a local
	// storage failure, the seam the reference's rejection case also uses.
	for _, code := range []int{429, 503} {
		t.Run(fmt.Sprintf("retries local failures (reference: local HTTP %d)", code), func(t *testing.T) {
			n.reset(t)
			restoreTable := notifDropPolicies(t, n.pds1)
			t.Cleanup(restoreTable)
			n.notifyNow(t, n.localSpace, n.writer.did, makeNotifCommit())
			if row := notifRetryRow(t, n); row.Attempts != 1 {
				t.Fatalf("attempts %d, want 1", row.Attempts)
			}
			notifMakeDue(t, n)
			n.retryPass(t)
			if row := notifRetryRow(t, n); row.Attempts != 2 {
				t.Fatalf("attempts %d, want 2", row.Attempts)
			}
			if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 0 {
				t.Fatalf("expected 0 notifyRepoUpdate calls, got %d", len(calls))
			}
			restoreTable()
		})
	}

	for _, tc := range []struct {
		code   int
		reason string
	}{
		{403, "Forbidden"},
		{400, "SpaceNotFound"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			t.Run("does not queue a rejected notification", func(t *testing.T) {
				n.reset(t)
				n.setResponse(tc.code, tc.reason)
				n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
				if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 1 {
					t.Fatalf("expected 1 notifyRepoUpdate call, got %d", len(calls))
				}
				if rows := notifRetryRows(t, n); len(rows) != 0 {
					t.Fatalf("queued %d retry rows", len(rows))
				}
			})

			for _, attempt := range []string{"notify", "retry"} {
				t.Run("clears queued work when "+attempt+" is rejected", func(t *testing.T) {
					n.reset(t)
					n.setResponse(503, "")
					n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
					notifMakeDue(t, n)
					n.setResponse(tc.code, tc.reason)
					if attempt == "notify" {
						n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
					} else {
						n.retryPass(t)
					}
					if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
						t.Fatalf("expected 2 notifyRepoUpdate calls, got %d", len(calls))
					}
					if rows := notifRetryRows(t, n); len(rows) != 0 {
						t.Fatalf("queued %d retry rows", len(rows))
					}
					n.retryPass(t)
					if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
						t.Fatalf("expected 2 notifyRepoUpdate calls after another pass, got %d", len(calls))
					}
				})
			}

			t.Run("stops on local authority rejections too", func(t *testing.T) {
				n.reset(t)
				target := n.localSpace
				if tc.reason != "Forbidden" {
					target = n.localSpace + "-missing"
				}
				n.notifyNow(t, target, n.outsider.did, makeNotifCommit())
				if rows := notifRetryRows(t, n); len(rows) != 0 {
					t.Fatalf("queued %d retry rows", len(rows))
				}

				// The reference makes the local storage read fail once with a
				// retryable error; the dropped policy table is that one-off
				// failure, restored before the retry pass so the retry reaches
				// the same definitive rejection the first notify would.
				restoreTable := notifDropPolicies(t, n.pds1)
				n.notifyNow(t, target, n.outsider.did, makeNotifCommit())
				restoreTable()
				row := notifRetryRow(t, n)
				if row.Space != target || row.Repo != n.outsider.did || row.Attempts != 1 {
					t.Fatalf("row %+v", row)
				}
				notifMakeDue(t, n)
				n.retryPass(t)
				if rows := notifRetryRows(t, n); len(rows) != 0 {
					t.Fatalf("queued %d retry rows", len(rows))
				}
				if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 0 {
					t.Fatalf("expected 0 notifyRepoUpdate calls, got %d", len(calls))
				}
			})
		})
	}

	t.Run("persists failures before the HTTP request", func(t *testing.T) {
		n.reset(t)
		// The reference makes DID resolution fail; the directory being down
		// fails the same resolution step for the space host.
		commit := makeNotifCommit()
		n.net.dir.down.Store(true)
		n.notifyNow(t, n.spaceURI, n.writer.did, commit)
		n.net.dir.down.Store(false)
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 0 {
			t.Fatalf("expected 0 notifyRepoUpdate calls, got %d", len(calls))
		}
		if row := notifRetryRow(t, n); row.RepoRev != commit.rev {
			t.Fatalf("repoRev %q, want %q", row.RepoRev, commit.rev)
		}
	})

	t.Run("surfaces an error if the failed delivery cannot be queued", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "")
		// The reference mocks the queue write to fail once and expects notify to
		// reject with the error; here the queue table is gone.
		db := n.pds1.s.db
		if err := db.Exec(context.Background(), "DROP TABLE space_notification_retries", nil).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := db.AutoMigrate(&models.SpaceNotificationRetry{}); err != nil {
				t.Fatal(err)
			}
		})
		body, ok := n.notifyBody(n.spaceURI, n.writer.did, makeNotifCommit())
		if !ok {
			t.Fatal("could not build the notification body")
		}
		if err := n.pds1.s.notifyAndQueue(context.Background(), body); err == nil {
			t.Fatal("a failed queue write was not surfaced")
		}
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 1 {
			t.Fatalf("expected 1 notifyRepoUpdate call, got %d", len(calls))
		}
		if err := db.AutoMigrate(&models.SpaceNotificationRetry{}); err != nil {
			t.Fatal(err)
		}
		if rows := notifRetryRows(t, n); len(rows) != 0 {
			t.Fatalf("queued %d retry rows", len(rows))
		}
	})

	t.Run("starts a fresh retry flow for a newer revision and ignores older or equal revisions", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "")
		older := makeNotifCommit()
		newer := makeNotifCommit()
		newer.setHash[0] = 1
		n.notifyNow(t, n.spaceURI, n.writer.did, older)
		if err := n.pds1.s.db.Client().
			Model(&models.SpaceNotificationRetry{}).
			Where("1 = 1").
			Updates(map[string]any{
				"attempts":   5,
				"retry_at":   time.Now().Add(time.Hour).UnixMilli(),
				"expires_at": time.Now().Add(12 * time.Hour).UnixMilli(),
			}).Error; err != nil {
			t.Fatal(err)
		}
		before := time.Now()
		n.notifyNow(t, n.spaceURI, n.writer.did, newer)
		row := notifRetryRow(t, n)
		if row.RepoRev != newer.rev || row.Attempts != 1 {
			t.Fatalf("row %+v", row)
		}
		if row.RetryAt < before.Add(30*time.Second).UnixMilli() || row.RetryAt > time.Now().Add(time.Minute).UnixMilli() {
			t.Fatalf("retryAt %d not within the first backoff pause", row.RetryAt)
		}
		if row.ExpiresAt < before.Add(24*time.Hour).UnixMilli() || row.ExpiresAt > time.Now().Add(24*time.Hour).UnixMilli() {
			t.Fatalf("expiresAt %d not within a day", row.ExpiresAt)
		}
		notifHashEquals(t, row.Data, newer)

		n.notifyNow(t, n.spaceURI, n.writer.did, older)
		n.notifyNow(t, n.spaceURI, n.writer.did, newer)
		after := notifRetryRow(t, n)
		if after.RepoRev != row.RepoRev || after.Attempts != row.Attempts || after.RetryAt != row.RetryAt ||
			after.ExpiresAt != row.ExpiresAt || string(after.Data) != string(row.Data) {
			t.Fatalf("row changed: %+v vs %+v", after, row)
		}
	})

	for _, tc := range []struct {
		code   int
		reason string
	}{
		{200, ""},
		{403, "Forbidden"},
		{400, "SpaceNotFound"},
	} {
		t.Run(fmt.Sprintf("keeps newer queued work when an older delivery finishes with %d", tc.code), func(t *testing.T) {
			n.reset(t)
			older := makeNotifCommit()
			newer := makeNotifCommit()

			// Hold the older delivery at the mock until the newer notify has
			// queued its row, as the reference's once-only resolver spy does.
			started, release, restoreRespond := n.holdDelivery(older.rev)
			defer restoreRespond()
			done := make(chan struct{})
			go func() {
				defer close(done)
				body, ok := n.notifyBody(n.spaceURI, n.writer.did, older)
				if !ok {
					return
				}
				_ = n.pds1.s.notifyAndQueue(context.Background(), body)
				n.net.waitSpaceJobs()
			}()
			started()

			n.setResponse(503, "")
			n.notifyNow(t, n.spaceURI, n.writer.did, newer)
			n.setResponse(tc.code, tc.reason)
			release()
			<-done
			restoreRespond()

			if row := notifRetryRow(t, n); row.RepoRev != newer.rev {
				t.Fatalf("repoRev %q, want %q", row.RepoRev, newer.rev)
			}
			n.notifyNow(t, n.spaceURI, n.writer.did, newer)
			if rows := notifRetryRows(t, n); len(rows) != 0 {
				t.Fatalf("queued %d retry rows", len(rows))
			}
		})
	}

	t.Run("backs off failed retries, caps the delay, and only reads due work", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "")
		n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
		// Not due yet: the pass delivers nothing, as the reference shows by its
		// actorStore.read spy staying untouched.
		n.retryPass(t)
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 1 {
			t.Fatalf("expected 1 notifyRepoUpdate call, got %d", len(calls))
		}

		notifMakeDue(t, n)
		before := time.Now()
		n.retryPass(t)
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
			t.Fatalf("expected 2 notifyRepoUpdate calls, got %d", len(calls))
		}
		row := notifRetryRow(t, n)
		if row.Attempts != 2 {
			t.Fatalf("attempts %d, want 2", row.Attempts)
		}
		// nextRetryAt(2) doubles the base pause, with 50-100% jitter.
		if row.RetryAt < before.Add(time.Minute).UnixMilli() || row.RetryAt > time.Now().Add(2*time.Minute).UnixMilli() {
			t.Fatalf("retryAt %d not within one to two minutes", row.RetryAt)
		}

		if err := n.pds1.s.db.Client().
			Model(&models.SpaceNotificationRetry{}).
			Where("1 = 1").
			Updates(map[string]any{"attempts": 20, "retry_at": time.Now().Add(-time.Second).UnixMilli()}).Error; err != nil {
			t.Fatal(err)
		}
		beforeCapped := time.Now()
		n.retryPass(t)
		capped := notifRetryRow(t, n)
		if capped.Attempts != 21 {
			t.Fatalf("attempts %d, want 21", capped.Attempts)
		}
		// The pause caps at an hour, with 50-100% jitter.
		if capped.RetryAt < beforeCapped.Add(30*time.Minute).UnixMilli() || capped.RetryAt > time.Now().Add(time.Hour).UnixMilli() {
			t.Fatalf("retryAt %d not within the capped pause", capped.RetryAt)
		}

		n.setResponse(200, "")
		notifMakeDue(t, n)
		n.retryPass(t)
		if rows := notifRetryRows(t, n); len(rows) != 0 {
			t.Fatalf("queued %d retry rows", len(rows))
		}
	})

	for _, tc := range []struct {
		code   int
		reason string
	}{
		{200, ""},
		{503, ""},
		{403, "Forbidden"},
		{400, "SpaceNotFound"},
	} {
		t.Run(fmt.Sprintf("preserves a fresh retry flow when an older retry finishes with %d", tc.code), func(t *testing.T) {
			n.reset(t)
			n.setResponse(503, "")
			older := makeNotifCommit()
			n.notifyNow(t, n.spaceURI, n.writer.did, older)
			notifMakeDue(t, n)

			// Hold the older retry's delivery at the mock until a newer notify
			// has queued its row, as the reference's once-only resolver spy
			// does.
			started, release, restoreRespond := n.holdDelivery(older.rev)
			defer restoreRespond()
			done := make(chan struct{})
			go func() {
				defer close(done)
				n.pds1.s.retrySpaceNotifications(context.Background())
				n.net.waitSpaceJobs()
			}()
			started()

			newer := makeNotifCommit()
			n.notifyNow(t, n.spaceURI, n.writer.did, newer)
			fresh := notifRetryRow(t, n)
			if fresh.RepoRev != newer.rev || fresh.Attempts != 1 {
				t.Fatalf("fresh row %+v", fresh)
			}
			n.setResponse(tc.code, tc.reason)
			release()
			<-done
			restoreRespond()

			after := notifRetryRow(t, n)
			if after.RepoRev != fresh.RepoRev || after.Attempts != fresh.Attempts || after.RetryAt != fresh.RetryAt ||
				after.ExpiresAt != fresh.ExpiresAt || string(after.Data) != string(fresh.Data) {
				t.Fatalf("row changed: %+v vs %+v", after, fresh)
			}
			if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 3 {
				t.Fatalf("expected 3 notifyRepoUpdate calls, got %d", len(calls))
			}
		})
	}

	t.Run("stops at the deadline and allows a later write to start a new retry window", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "")
		n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
		expiresAt := time.Now().Add(30 * time.Second)
		if err := n.pds1.s.db.Client().
			Model(&models.SpaceNotificationRetry{}).
			Where("1 = 1").
			Updates(map[string]any{"retry_at": 0, "expires_at": expiresAt.UnixMilli()}).Error; err != nil {
			t.Fatal(err)
		}
		n.retryPass(t)
		// The failed retry is clamped to the deadline rather than backed off
		// past it.
		if row := notifRetryRow(t, n); row.RetryAt != expiresAt.UnixMilli() {
			t.Fatalf("retryAt %d, want the deadline %d", row.RetryAt, expiresAt.UnixMilli())
		}
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
			t.Fatalf("expected 2 notifyRepoUpdate calls, got %d", len(calls))
		}

		// The reference mocks Date.now to the deadline; the same state is
		// reached here by making the row due and expired.
		notifMakeDue(t, n)
		if err := n.pds1.s.db.Client().
			Model(&models.SpaceNotificationRetry{}).
			Where("1 = 1").
			Update("expires_at", time.Now().Add(-time.Second).UnixMilli()).Error; err != nil {
			t.Fatal(err)
		}
		n.retryPass(t)
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
			t.Fatalf("expected 2 notifyRepoUpdate calls, got %d", len(calls))
		}
		if rows := notifRetryRows(t, n); len(rows) != 0 {
			t.Fatalf("queued %d retry rows", len(rows))
		}

		newer := makeNotifCommit()
		before := time.Now()
		n.notifyNow(t, n.spaceURI, n.writer.did, newer)
		row := notifRetryRow(t, n)
		if row.RepoRev != newer.rev || row.Attempts != 1 {
			t.Fatalf("row %+v", row)
		}
		if row.ExpiresAt < before.Add(24*time.Hour).UnixMilli() {
			t.Fatalf("expiresAt %d not within a day", row.ExpiresAt)
		}
	})

	// The reference's "elects one retry worker and allows takeover after its
	// lease expires" case is N/A for Cocoon: there is no retry lease, and one
	// worker goroutine serializes retry passes with a mutex
	// (retrySpaceNotifications in server/space_notify.go).

	t.Run("defers retries for inactive accounts and resumes after activation", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "")
		n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
		notifMakeDue(t, n)
		setDeactivated := func(on bool) {
			if err := n.pds1.s.db.Exec(context.Background(),
				"UPDATE repos SET deactivated = ? WHERE did = ?", nil, on, n.writer.did).Error; err != nil {
				t.Fatal(err)
			}
		}
		setDeactivated(true)
		func() {
			defer setDeactivated(false)
			n.setResponse(200, "")
			n.retryPass(t)
			if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 1 {
				t.Fatalf("expected 1 notifyRepoUpdate call, got %d", len(calls))
			}
			if row := notifRetryRow(t, n); row.Attempts != 2 {
				t.Fatalf("attempts %d, want 2", row.Attempts)
			}
		}()
		notifMakeDue(t, n)
		n.retryPass(t)
		if calls := n.host.callsTo(lxmNotifyRepoUpdate); len(calls) != 2 {
			t.Fatalf("expected 2 notifyRepoUpdate calls, got %d", len(calls))
		}
	})
}

// TestSpaceNotificationsSyncerNotices ports the reference's describe('syncer
// notices') (notifications.test.ts): reliable delivery of a space's deletion
// and of a registration's expiry, with retry, backoff and abandonment.
func TestSpaceNotificationsSyncerNotices(t *testing.T) {
	n := newSpaceNet(t)
	pds := n.newPDS()
	writer := pds.createActor("writer")
	ctx := context.Background()

	localSpace := createSpace(t, writer, spaceOpts{skey: "local"})
	deletedSpace := createSpace(t, writer, spaceOpts{skey: "deleted"})
	mustOK(t, writer.post("com.atproto.space.deleteSpace", map[string]any{"space": deletedSpace}))
	n.waitSpaceJobs()

	syncer := newNotifSyncer(n)
	ref := notifMustParseRef(t, deletedSpace)
	localRef := notifMustParseRef(t, localSpace)
	const token = "syncer-token"

	registration := func() models.SpaceNotifyRegistration {
		return models.SpaceNotifyRegistration{Did: writer.did, Space: localSpace, Endpoint: syncer.url, Token: token}
	}
	reset := func(t *testing.T) {
		t.Helper()
		syncer.reset(t)
		if err := pds.s.db.Client().Where("1 = 1").Delete(&models.SpaceSyncerNotificationRetry{}).Error; err != nil {
			t.Fatal(err)
		}
		if err := pds.s.db.Exec(ctx, "DELETE FROM space_notify_registrations WHERE space = ?", nil, localSpace).Error; err != nil {
			t.Fatal(err)
		}
	}
	notifyDeleted := func() {
		writer.pds.s.notifySyncers(ctx, ref, []models.SpaceNotifyRegistration{
			{Did: writer.did, Space: deletedSpace, Endpoint: syncer.url, Token: token},
		}, syncerNotice{deleted: true})
	}
	// Expiry notices go to a lapsed registration in a space that still exists.
	lapseRegistration := func(expiresAt time.Time) {
		t.Helper()
		notifPutRegistration(t, pds, localSpace, syncer.url, token, expiresAt)
	}
	notifyExpired := func() {
		writer.pds.s.notifySyncers(ctx, localRef, []models.SpaceNotifyRegistration{registration()},
			syncerNotice{expiredAt: nextTID("")})
	}
	getRegistration := func(t *testing.T) *models.SpaceNotifyRegistration {
		t.Helper()
		return notifRegistration(t, pds, localSpace, syncer.url, token)
	}
	pending := func(t *testing.T) []models.SpaceSyncerNotificationRetry {
		t.Helper()
		return notifSyncerRetries(t, pds)
	}
	makeDue := func(t *testing.T) {
		t.Helper()
		if err := pds.s.db.Client().Model(&models.SpaceSyncerNotificationRetry{}).
			Where("1 = 1").Update("retry_at", 0).Error; err != nil {
			t.Fatal(err)
		}
	}
	retryPass := func(t *testing.T) {
		t.Helper()
		pds.s.retrySpaceNotifications(ctx)
		n.waitSpaceJobs()
	}

	t.Run("sends immediately without queueing a successful notification", func(t *testing.T) {
		reset(t)
		notifyDeleted()
		delivered := syncer.callsTo(lxmNotifySpaceUpdate)
		if len(delivered) != 1 {
			t.Fatalf("expected 1 notifySpaceUpdate call, got %d", len(delivered))
		}
		if delivered[0].body["space"] != deletedSpace {
			t.Fatalf("space %v, want %s", delivered[0].body["space"], deletedSpace)
		}
		if delivered[0].body["token"] != token {
			t.Fatalf("token %v, want %s", delivered[0].body["token"], token)
		}
		updates := syncer.updates()
		if len(updates) != 1 || updates[0]["$type"] != typeSpaceDeleted {
			t.Fatalf("updates %+v", updates)
		}
		if len(updates[0]) != 1 {
			t.Fatalf("spaceDeleted carried more than its $type: %+v", updates[0])
		}
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
	})

	t.Run("retries a transient failure until delivered", func(t *testing.T) {
		reset(t)
		syncer.setStatus(503)
		before := time.Now()
		notifyDeleted()
		rows := pending(t)
		if len(rows) != 1 {
			t.Fatalf("expected one queued notice, got %+v", rows)
		}
		row := rows[0]
		if row.Space != deletedSpace || row.Endpoint != syncer.url || row.Token != token || row.Attempts != 1 {
			t.Fatalf("queued %+v", row)
		}
		if row.ExpiresAt < before.Add(72*time.Hour).UnixMilli() || row.ExpiresAt > time.Now().Add(72*time.Hour).UnixMilli() {
			t.Fatalf("expiresAt %d not within 72 hours", row.ExpiresAt)
		}

		makeDue(t)
		retryPass(t)
		if rows := pending(t); len(rows) != 1 || rows[0].Attempts != 2 {
			t.Fatalf("after a failed retry: %+v", rows)
		}

		syncer.setStatus(200)
		makeDue(t)
		retryPass(t)
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("after delivery: %+v", rows)
		}
		calls := syncer.callsTo(lxmNotifySpaceUpdate)
		if len(calls) != 3 {
			t.Fatalf("expected 3 notifySpaceUpdate calls, got %d", len(calls))
		}
		if calls[len(calls)-1].body["token"] != token {
			t.Fatalf("last delivery: %+v", calls[len(calls)-1].body)
		}
	})

	t.Run("does not retry a permanent failure", func(t *testing.T) {
		reset(t)
		syncer.setStatus(400)
		notifyDeleted()
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != 1 {
			t.Fatalf("expected 1 notifySpaceUpdate call, got %d", len(calls))
		}
	})

	t.Run("backs off from a minute to twelve hours", func(t *testing.T) {
		reset(t)
		syncer.setStatus(503)
		notifyDeleted()
		for _, delay := range []time.Duration{
			time.Minute,
			10 * time.Minute,
			time.Hour,
			6 * time.Hour,
			12 * time.Hour,
			12 * time.Hour,
		} {
			rows := pending(t)
			if len(rows) != 1 {
				t.Fatalf("expected one queued notice, got %+v", rows)
			}
			wait := time.Duration(rows[0].RetryAt-time.Now().UnixMilli()) * time.Millisecond
			if wait <= delay/2-time.Second || wait > delay {
				t.Fatalf("wait %s not within %s's 50-100%% band", wait, delay)
			}
			makeDue(t)
			retryPass(t)
		}
	})

	t.Run("stops retrying after a final retry past 72 hours", func(t *testing.T) {
		reset(t)
		syncer.setStatus(503)
		notifyDeleted()
		if err := pds.s.db.Client().Model(&models.SpaceSyncerNotificationRetry{}).
			Where("1 = 1").
			Updates(map[string]any{"retry_at": 0, "expires_at": time.Now().UnixMilli()}).Error; err != nil {
			t.Fatal(err)
		}
		retryPass(t)
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != 2 {
			t.Fatalf("expected 2 notifySpaceUpdate calls, got %d", len(calls))
		}
	})

	t.Run("drops retries once the authority account is gone", func(t *testing.T) {
		reset(t)
		gone := "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/space/" + testSpaceType + "/gone"
		notice, err := json.Marshal(map[string]any{"$type": typeSpaceDeleted})
		if err != nil {
			t.Fatal(err)
		}
		row := models.SpaceSyncerNotificationRetry{
			Space: gone, Endpoint: syncer.url, Token: token, NoticeJson: string(notice),
			Attempts: 1, RetryAt: 0, ExpiresAt: time.Now().Add(24 * time.Hour).UnixMilli(),
		}
		if err := pds.s.db.Client().Create(&row).Error; err != nil {
			t.Fatal(err)
		}
		retryPass(t)
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != 0 {
			t.Fatalf("expected 0 notifySpaceUpdate calls, got %d", len(calls))
		}
	})

	t.Run("defers retries while the authority is inactive", func(t *testing.T) {
		reset(t)
		syncer.setStatus(503)
		notifyDeleted()
		makeDue(t)
		setDeactivated := func(on bool) {
			if err := pds.s.db.Exec(ctx, "UPDATE repos SET deactivated = ? WHERE did = ?", nil, on, writer.did).Error; err != nil {
				t.Fatal(err)
			}
		}
		setDeactivated(true)
		func() {
			defer setDeactivated(false)
			syncer.setStatus(200)
			retryPass(t)
			if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != 1 {
				t.Fatalf("expected 1 notifySpaceUpdate call, got %d", len(calls))
			}
			if rows := pending(t); len(rows) != 1 || rows[0].Attempts != 2 {
				t.Fatalf("queued %+v", rows)
			}
		}()
		makeDue(t)
		retryPass(t)
		if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != 2 {
			t.Fatalf("expected 2 notifySpaceUpdate calls, got %d", len(calls))
		}
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
	})

	t.Run("drops a deletion notice once the space is recreated", func(t *testing.T) {
		reset(t)
		syncer.setStatus(503)
		notifyDeleted()
		makeDue(t)
		createSpace(t, writer, spaceOpts{skey: "deleted"})
		defer func() {
			mustOK(t, writer.post("com.atproto.space.deleteSpace", map[string]any{"space": deletedSpace}))
			n.waitSpaceJobs()
		}()
		syncer.setStatus(200)
		retryPass(t)
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != 1 {
			t.Fatalf("expected 1 notifySpaceUpdate call, got %d", len(calls))
		}
	})

	t.Run("keeps a newer retry when an older delivery finishes", func(t *testing.T) {
		reset(t)
		syncer.setStatus(503)
		notifyDeleted()
		makeDue(t)

		// Hold the retry's delivery at the mock, re-queue a notice for the same
		// registration while it is in flight, then let the older delivery
		// finish: the row queued meanwhile must survive.
		delivered, release, restore := syncer.hold(func(mockCall) bool { return true })
		defer restore()
		done := make(chan struct{})
		go func() {
			defer close(done)
			pds.s.retrySpaceNotifications(ctx)
			n.waitSpaceJobs()
		}()
		delivered()

		notifyDeleted()
		requeued := pending(t)
		if len(requeued) != 1 {
			t.Fatalf("expected one re-queued notice, got %+v", requeued)
		}
		release()
		<-done
		restore()
		if rows := pending(t); len(rows) != 1 || rows[0].RetryAt != requeued[0].RetryAt {
			t.Fatalf("re-queued notice lost: %+v vs %+v", rows, requeued)
		}
	})

	t.Run("drops a lapsed registration that rejects its expiry notice", func(t *testing.T) {
		reset(t)
		lapseRegistration(time.Now().Add(-time.Second))
		syncer.setStatus(400)
		notifyExpired()
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		if reg := getRegistration(t); reg != nil {
			t.Fatalf("registration kept: %+v", reg)
		}
	})

	t.Run("drops a lapsed registration once its expiry notice stops being retried", func(t *testing.T) {
		reset(t)
		lapseRegistration(time.Now().Add(-time.Second))
		syncer.setStatus(503)
		notifyExpired()
		if rows := pending(t); len(rows) != 1 {
			t.Fatalf("expected one queued notice, got %+v", rows)
		}
		if reg := getRegistration(t); reg == nil {
			t.Fatal("registration dropped before the retry window ended")
		}
		if err := pds.s.db.Client().Model(&models.SpaceSyncerNotificationRetry{}).
			Where("1 = 1").
			Updates(map[string]any{"retry_at": 0, "expires_at": time.Now().UnixMilli()}).Error; err != nil {
			t.Fatal(err)
		}
		retryPass(t)
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		if reg := getRegistration(t); reg != nil {
			t.Fatalf("registration kept: %+v", reg)
		}
	})

	t.Run("drops an expiry notice once the registration is renewed", func(t *testing.T) {
		reset(t)
		lapseRegistration(time.Now().Add(-time.Second))
		syncer.setStatus(503)
		notifyExpired()
		lapseRegistration(time.Now().Add(time.Hour))
		makeDue(t)

		syncer.setStatus(200)
		retryPass(t)
		if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != 1 {
			t.Fatalf("expected 1 notifySpaceUpdate call, got %d", len(calls))
		}
		if rows := pending(t); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		if reg := getRegistration(t); reg == nil {
			t.Fatal("a renewed registration was dropped")
		}
	})

	t.Run("lets a deletion notice supersede a pending expiry notice, but not the reverse", func(t *testing.T) {
		reset(t)
		lapseRegistration(time.Now().Add(-time.Second))
		syncer.setStatus(503)
		notifyExpired()
		writer.pds.s.notifySyncers(ctx, localRef, []models.SpaceNotifyRegistration{registration()}, syncerNotice{deleted: true})
		notifyExpired()
		rows := pending(t)
		if len(rows) != 1 {
			t.Fatalf("expected one queued notice, got %+v", rows)
		}
		notice, err := parseSyncerNotice(rows[0].NoticeJson)
		if err != nil {
			t.Fatal(err)
		}
		if !notice.deleted {
			t.Fatalf("queued notice is not the deletion: %s", rows[0].NoticeJson)
		}
	})
}

// TestSpaceNotificationsRegistration ports the reference's describe('notify
// registration') (policy.test.ts): how a syncing service registers for a
// space's updates through authorizeSpaceSync, and how a registration lapses,
// renews and is dropped.
func TestSpaceNotificationsRegistration(t *testing.T) {
	n := newSpaceNet(t)
	pds := n.newPDS()
	alice := pds.createActor("alice") // authority
	bob := pds.createActor("bob")
	carol := pds.createActor("carol")
	syncer := newNotifSyncer(n)

	// writeAndForward: a member's write reaches the authority before the
	// request resolves, which queues the fan-out.
	writeAndForward := func(t *testing.T, spaceURI string) {
		t.Helper()
		mustOK(t, doWrite(bob, spaceURI, writeOpts{}))
		n.waitSpaceJobs()
	}
	// newSpace is a space alice governs, with bob and carol as members who may
	// write, and no registrations left from an earlier case.
	newSpace := func(t *testing.T) string {
		t.Helper()
		syncer.reset(t)
		if err := pds.s.db.Client().Where("1 = 1").Delete(&models.SpaceNotifyRegistration{}).Error; err != nil {
			t.Fatal(err)
		}
		return createSpace(t, alice, spaceOpts{members: []*actor{bob, carol}})
	}
	register := func(t *testing.T, spaceURI, token string) xres {
		t.Helper()
		return exchangeWith(t, pds, spaceURI, delegationTokenFor(t, carol, spaceURI), newP256Key(t), "", syncer.reg(token))
	}
	subscribe := func(t *testing.T, spaceURI, token string) {
		t.Helper()
		mustOK(t, register(t, spaceURI, token))
	}
	updates := func() []map[string]any { return syncer.updates() }
	lapse := func(t *testing.T, spaceURI string, ago time.Duration) {
		t.Helper()
		if err := pds.s.db.Exec(context.Background(),
			"UPDATE space_notify_registrations SET expires_at = ? WHERE space = ? AND endpoint = ?",
			nil, isoTime(time.Now().Add(-ago)), spaceURI, syncer.url).Error; err != nil {
			t.Fatal(err)
		}
	}
	spaceRev := func(t *testing.T, spaceURI string) string {
		t.Helper()
		var rows []models.SpaceWriter
		if err := pds.s.db.Client().Where("space = ?", spaceURI).Order("space_rev desc").Limit(1).Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("the space has no writers")
		}
		return rows[0].SpaceRev
	}

	t.Run("confirms a new registration, and forwards writes with its token", func(t *testing.T) {
		spaceURI := newSpace(t)
		subscribe(t, spaceURI, "first-token")
		confirmations := syncer.callsTo(lxmConfirmRegistration)
		if len(confirmations) != 1 {
			t.Fatalf("expected 1 confirmRegistration call, got %d", len(confirmations))
		}
		if confirmations[0].body["space"] != spaceURI || confirmations[0].body["token"] != "first-token" {
			t.Fatalf("confirmation body: %+v", confirmations[0].body)
		}
		if ch, _ := confirmations[0].body["challenge"].(string); ch == "" {
			t.Fatalf("confirmation carried no challenge: %+v", confirmations[0].body)
		}

		writeAndForward(t, spaceURI)
		delivered := updates()
		if len(delivered) != 1 {
			t.Fatalf("expected 1 update, got %+v", delivered)
		}
		if delivered[0]["$type"] != typeRepoWrite || delivered[0]["repo"] != bob.did {
			t.Fatalf("update %+v", delivered[0])
		}
		if got := syncer.callsTo(lxmNotifySpaceUpdate)[0].body["token"]; got != "first-token" {
			t.Fatalf("token %v, want first-token", got)
		}

		// Renewing with the same token keeps a single registration, and needs no
		// confirmation.
		subscribe(t, spaceURI, "first-token")
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("expected 1 registration, got %+v", regs)
		}
		if got := syncer.callsTo(lxmConfirmRegistration); len(got) != 1 {
			t.Fatalf("expected 1 confirmRegistration call, got %d", len(got))
		}
	})

	t.Run("treats a different token as a separate registration", func(t *testing.T) {
		spaceURI := newSpace(t)
		for _, token := range []string{"first-token", "second-token"} {
			subscribe(t, spaceURI, token)
		}
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 2 {
			t.Fatalf("expected 2 registrations, got %+v", regs)
		}

		writeAndForward(t, spaceURI)
		var tokens []string
		for _, call := range syncer.callsTo(lxmNotifySpaceUpdate) {
			s, _ := call.body["token"].(string)
			tokens = append(tokens, s)
		}
		sort.Strings(tokens)
		if len(tokens) != 2 || tokens[0] != "first-token" || tokens[1] != "second-token" {
			t.Fatalf("delivered tokens %v", tokens)
		}
	})

	t.Run("refuses an authorization whose registration is not confirmed", func(t *testing.T) {
		spaceURI := newSpace(t)
		syncer.setNoEcho(true)
		expectErr(t, register(t, spaceURI, "syncer-token"), 400, "RegistrationNotConfirmed")
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 0 {
			t.Fatalf("expected no registrations, got %+v", regs)
		}
	})

	t.Run("returns the space's revision to the registrant", func(t *testing.T) {
		// The reference learns it from listWriters' cursor in its lapse case; the
		// response carries it so a syncer knows where its registration starts.
		spaceURI := newSpace(t)
		writeAndForward(t, spaceURI)
		_, res := credentialWithNotify(t, carol, pds, spaceURI, syncer.reg("syncer-token"))
		if got := res.str("spaceRev"); got == "" || got != spaceRev(t, spaceURI) {
			t.Fatalf("spaceRev %q, want %q", got, spaceRev(t, spaceURI))
		}
	})

	t.Run("sends a lapsed registration an expiry notice in place of the next update, then nothing more", func(t *testing.T) {
		spaceURI := newSpace(t)
		subscribe(t, spaceURI, "syncer-token")
		// However long ago it lapsed.
		lapse(t, spaceURI, 24*time.Hour+time.Minute)

		writeAndForward(t, spaceURI)
		delivered := updates()
		if len(delivered) != 1 {
			t.Fatalf("expected 1 update, got %+v", delivered)
		}
		if delivered[0]["$type"] != typeRegistrationExpired {
			t.Fatalf("update %+v", delivered[0])
		}
		if delivered[0]["spaceRev"] != spaceRev(t, spaceURI) {
			t.Fatalf("expiry notice carries spaceRev %v, want %s", delivered[0]["spaceRev"], spaceRev(t, spaceURI))
		}

		// The registration is kept, for a deletion notice, but sent no updates.
		writeAndForward(t, spaceURI)
		if got := updates(); len(got) != 1 {
			t.Fatalf("expected no further updates, got %+v", got)
		}
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("expected 1 registration, got %+v", regs)
		}

		// Reauthorizing renews it.
		subscribe(t, spaceURI, "syncer-token")
		writeAndForward(t, spaceURI)
		got := updates()
		if len(got) != 2 {
			t.Fatalf("expected a renewed update, got %+v", got)
		}
		if got[1]["$type"] != typeRepoWrite {
			t.Fatalf("renewed update %+v", got[1])
		}
	})

	t.Run("unregisters a syncer that rejects its expiry notice", func(t *testing.T) {
		spaceURI := newSpace(t)
		subscribe(t, spaceURI, "syncer-token")
		lapse(t, spaceURI, time.Second)
		syncer.setError(400, "InvalidToken")

		writeAndForward(t, spaceURI)
		if got := updates(); len(got) != 1 {
			t.Fatalf("expected 1 update, got %+v", got)
		}
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 0 {
			t.Fatalf("expected no registrations, got %+v", regs)
		}

		// Registering again is a new registration, so it is confirmed again.
		syncer.reset(t)
		subscribe(t, spaceURI, "syncer-token")
		if got := syncer.callsTo(lxmConfirmRegistration); len(got) != 1 {
			t.Fatalf("expected 1 confirmRegistration call, got %d", len(got))
		}
	})

	t.Run("retries an expiry notice through a transient failure", func(t *testing.T) {
		spaceURI := newSpace(t)
		subscribe(t, spaceURI, "syncer-token")
		lapse(t, spaceURI, time.Second)
		syncer.setStatus(503)

		writeAndForward(t, spaceURI)
		if rows := notifSyncerRetries(t, pds); len(rows) != 1 {
			t.Fatalf("expected one queued notice, got %+v", rows)
		}

		syncer.setStatus(200)
		if err := pds.s.db.Client().Model(&models.SpaceSyncerNotificationRetry{}).
			Where("1 = 1").Update("retry_at", 0).Error; err != nil {
			t.Fatal(err)
		}
		pds.s.retrySpaceNotifications(context.Background())
		n.waitSpaceJobs()
		if rows := notifSyncerRetries(t, pds); len(rows) != 0 {
			t.Fatalf("queued %+v", rows)
		}
		var expired int
		for _, u := range updates() {
			if u["$type"] == typeRegistrationExpired {
				expired++
			}
		}
		if expired != 2 {
			t.Fatalf("expected 2 expiry notices, got %+v", updates())
		}
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("expected 1 registration, got %+v", regs)
		}
	})

	t.Run("keeps an active registration through a rejected update", func(t *testing.T) {
		// Updates are best-effort. A syncer unregisters only by rejecting its
		// expiry notice.
		spaceURI := newSpace(t)
		subscribe(t, spaceURI, "syncer-token")
		syncer.setError(401, "InvalidToken")

		writeAndForward(t, spaceURI)
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("expected 1 registration, got %+v", regs)
		}

		syncer.reset(t)
		writeAndForward(t, spaceURI)
		if got := updates(); len(got) != 1 {
			t.Fatalf("expected 1 update, got %+v", got)
		}
	})

	t.Run("withdraws the registration carried by a refused authorization", func(t *testing.T) {
		spaceURI := newSpace(t)
		subscribe(t, spaceURI, "syncer-token")
		removeMember(t, alice, spaceURI, carol)

		// A different token names a different registration, so naming the
		// endpoint alone withdraws nothing.
		expectErr(t, register(t, spaceURI, "guessed-token"), 400, "SpaceNotFound")
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("expected 1 registration, got %+v", regs)
		}

		expectErr(t, register(t, spaceURI, "syncer-token"), 400, "SpaceNotFound")
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 0 {
			t.Fatalf("expected no registrations, got %+v", regs)
		}

		writeAndForward(t, spaceURI)
		if got := updates(); len(got) != 0 {
			t.Fatalf("expected no updates, got %+v", got)
		}
	})

	t.Run("keeps a registration through a managing app outage, and withdraws it on refusal", func(t *testing.T) {
		// A managing app that fails has not refused access, so the registration
		// stays; one that refuses access withdraws it, as any refusal does.
		var mu sync.Mutex
		answer := func() (int, any) { return 200, map[string]any{"read": true, "write": true} }
		set := func(status int, body any) {
			mu.Lock()
			answer = func() (int, any) { return status, body }
			mu.Unlock()
		}
		app := n.newMockService("atproto_forum", func(*http.Request, mockCall) (int, any) {
			mu.Lock()
			defer mu.Unlock()
			return answer()
		})
		syncer.reset(t)
		if err := pds.s.db.Client().Where("1 = 1").Delete(&models.SpaceNotifyRegistration{}).Error; err != nil {
			t.Fatal(err)
		}
		spaceURI := createSpace(t, alice, spaceOpts{policy: managedPolicy(app.serviceRef(), nil)})
		reauthorize := func() xres {
			return exchangeWith(t, pds, spaceURI, delegationTokenFor(t, carol, spaceURI), newP256Key(t), "", syncer.reg("syncer-token"))
		}
		mustOK(t, reauthorize())
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("expected 1 registration, got %+v", regs)
		}

		set(500, map[string]any{"error": "InternalError"})
		expectErr(t, reauthorize(), 502, "UpstreamFailure")
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("an outage withdrew the registration: %+v", regs)
		}

		set(200, map[string]any{"read": false, "write": false})
		expectErr(t, reauthorize(), 400, "SpaceNotFound")
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 0 {
			t.Fatalf("a refusal kept the registration: %+v", regs)
		}
	})

	t.Run("keeps a registration through a suspended authority", func(t *testing.T) {
		// A taken-down or deactivated authority cannot authorize, but neither is
		// a refusal of access, so the registration stays.
		spaceURI := newSpace(t)
		subscribe(t, spaceURI, "syncer-token")

		takedown(t, alice, true)
		expectErr(t, register(t, spaceURI, "syncer-token"), 400, "RepoTakendown")
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("a takedown withdrew the registration: %+v", regs)
		}
		takedown(t, alice, false)

		if err := pds.s.db.Exec(context.Background(),
			"UPDATE repos SET deactivated = true WHERE did = ?", nil, alice.did).Error; err != nil {
			t.Fatal(err)
		}
		expectErr(t, register(t, spaceURI, "syncer-token"), 400, "RepoDeactivated")
		if err := pds.s.db.Exec(context.Background(),
			"UPDATE repos SET deactivated = false WHERE did = ?", nil, alice.did).Error; err != nil {
			t.Fatal(err)
		}
		if regs := notifRegistrations(t, pds, spaceURI); len(regs) != 1 {
			t.Fatalf("a deactivation withdrew the registration: %+v", regs)
		}
	})

	t.Run("delivers to each registration without waiting on a slow one", func(t *testing.T) {
		spaceURI := newSpace(t)
		slowReleased := make(chan struct{})
		fastDelivered := make(chan struct{})
		var fastOnce, releaseOnce sync.Once
		syncer.setRespond(func(r *http.Request, c mockCall) (int, any) {
			if c.lxm == lxmConfirmRegistration {
				return 200, map[string]any{"challenge": c.body["challenge"]}
			}
			switch c.body["token"] {
			case "a-slow-token":
				<-slowReleased
			case "b-fast-token":
				fastOnce.Do(func() { close(fastDelivered) })
			}
			return 200, map[string]any{}
		})
		// Listed first, by token, so a serial delivery would wait on it first.
		for _, token := range []string{"a-slow-token", "b-fast-token"} {
			subscribe(t, spaceURI, token)
		}

		mustOK(t, doWrite(bob, spaceURI, writeOpts{}))
		select {
		case <-fastDelivered:
		case <-time.After(10 * time.Second):
			t.Fatal("the fast registration waited on the slow one")
		}
		releaseOnce.Do(func() { close(slowReleased) })
		n.waitSpaceJobs()
	})

	t.Run("chains forwarded notifications across writers", func(t *testing.T) {
		// From sync.test.ts, "chains forwarded notifications across local and
		// remote writers": each update names its predecessor.
		spaceURI := newSpace(t)
		dan := pds.createActor("dan")
		putMember(t, alice, spaceURI, dan, true, true)
		subscribe(t, spaceURI, "syncer-token")

		mustOK(t, doWrite(alice, spaceURI, writeOpts{}))
		mustOK(t, doWrite(bob, spaceURI, writeOpts{}))
		mustOK(t, doWrite(dan, spaceURI, writeOpts{}))
		n.waitSpaceJobs()

		var writes []map[string]any
		for _, u := range updates() {
			if u["$type"] == typeRepoWrite {
				writes = append(writes, u)
			}
		}
		if len(writes) != 3 {
			t.Fatalf("expected 3 repoWrite updates, got %+v", updates())
		}
		sort.Slice(writes, func(i, j int) bool {
			a, _ := writes[i]["spaceRev"].(string)
			b, _ := writes[j]["spaceRev"].(string)
			return a < b
		})
		if _, ok := writes[0]["prevSpaceRev"]; ok {
			t.Fatalf("the first update named a predecessor: %+v", writes[0])
		}
		for i := 1; i < len(writes); i++ {
			if writes[i]["prevSpaceRev"] != writes[i-1]["spaceRev"] {
				t.Fatalf("update %d prevSpaceRev %v, want %v", i, writes[i]["prevSpaceRev"], writes[i-1]["spaceRev"])
			}
		}
		if got := spaceRev(t, spaceURI); writes[len(writes)-1]["spaceRev"] != got {
			t.Fatalf("last update spaceRev %v, want %s", writes[len(writes)-1]["spaceRev"], got)
		}
	})

	t.Run("forwards a removal from the writer set, in the space sequence", func(t *testing.T) {
		// From sync.test.ts, "forwards a removal from the writer set, in the
		// space sequence".
		spaceURI := newSpace(t)
		dan := pds.createActor("dan2")
		putMember(t, alice, spaceURI, dan, true, true)
		subscribe(t, spaceURI, "syncer-token")

		mustOK(t, doWrite(dan, spaceURI, writeOpts{}))
		n.waitSpaceJobs()
		mustOK(t, removeWriter(alice, spaceURI, dan))
		n.waitSpaceJobs()

		var write, removal map[string]any
		for _, u := range updates() {
			switch u["$type"] {
			case typeRepoWrite:
				write = u
			case typeRepoRemoved:
				removal = u
			}
		}
		if write == nil || removal == nil {
			t.Fatalf("updates %+v", updates())
		}
		if removal["repo"] != dan.did {
			t.Fatalf("removal repo %v, want %s", removal["repo"], dan.did)
		}
		if removal["spaceRev"] != spaceRev(t, spaceURI) {
			t.Fatalf("removal spaceRev %v, want %s", removal["spaceRev"], spaceRev(t, spaceURI))
		}
		if removal["prevSpaceRev"] != write["spaceRev"] {
			t.Fatalf("removal prevSpaceRev %v, want %v", removal["prevSpaceRev"], write["spaceRev"])
		}
	})
}

// TestSpaceNotificationsFetchesUntrustedEndpoints checks the SSRF stance for
// the endpoints a registration names: the confirmRegistration check and the
// updates sent to a registered syncer go through the PDS's guarded space client
// (spaceClient in server/space_util.go), so a registration pointing at a
// loopback address is never fetched.
func TestSpaceNotificationsFetchesUntrustedEndpoints(t *testing.T) {
	n := newSpaceNet(t)
	pds := n.newPDS()
	alice := pds.createActor("alice")
	carol := pds.createActor("carol")
	syncer := newNotifSyncer(n)
	spaceURI := createSpace(t, alice, spaceOpts{members: []*actor{carol}})

	// Register while the test network's permissive client is still in place.
	mustOK(t, exchangeWith(t, pds, spaceURI, delegationTokenFor(t, carol, spaceURI), newP256Key(t), "", syncer.reg("syncer-token")))
	if calls := syncer.callsTo(lxmConfirmRegistration); len(calls) != 1 {
		t.Fatalf("expected the registration to be confirmed once, got %d calls", len(calls))
	}
	before := len(syncer.callsTo(lxmNotifySpaceUpdate))

	// Without the network's client, the PDS uses the strict one, which refuses
	// the loopback address the mock listens on.
	permissive := pds.s.spaceHTTP
	pds.s.spaceHTTP = nil
	pds.s.spaceHTTPOnce = sync.Once{}
	defer func() {
		pds.s.spaceHTTP = permissive
		pds.s.spaceHTTPOnce = sync.Once{}
	}()

	// An update for the registered syncer is not fetched.
	mustOK(t, doWrite(carol, spaceURI, writeOpts{}))
	n.waitSpaceJobs()
	if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != before {
		t.Fatalf("the update endpoint was fetched: %d calls", len(calls)-before)
	}

	// Nor is a notice, which a failed fetch defers to the retry queue instead.
	mustOK(t, alice.post("com.atproto.space.deleteSpace", map[string]any{"space": spaceURI}))
	n.waitSpaceJobs()
	if calls := syncer.callsTo(lxmNotifySpaceUpdate); len(calls) != before {
		t.Fatalf("the notice endpoint was fetched: %d calls", len(calls)-before)
	}
	if rows := notifSyncerRetries(t, pds); len(rows) != 1 {
		t.Fatalf("expected the undeliverable notice to be queued, got %+v", rows)
	}

	// A new registration's confirmation is not fetched either.
	other := createSpace(t, alice, spaceOpts{skey: "other", members: []*actor{carol}})
	res := exchangeWith(t, pds, other, delegationTokenFor(t, carol, other), newP256Key(t), "", syncer.reg("syncer-token"))
	expectErr(t, res, 400, "RegistrationNotConfirmed")
	if calls := syncer.callsTo(lxmConfirmRegistration); len(calls) != 1 {
		t.Fatalf("the registration endpoint was fetched: %d confirmations", len(calls))
	}
}

// notifSyncer is a mock syncing service: it confirms a registration by echoing
// the host's challenge, and records every call it receives.
type notifSyncer struct {
	*mockService
	stMu   sync.Mutex
	status int
	errMsg string
	noEcho bool
}

func newNotifSyncer(n *spaceNet) *notifSyncer {
	s := &notifSyncer{status: 200}
	s.mockService = n.newMockService("atproto_space_syncer", s.respond)
	return s
}

func (s *notifSyncer) respond(r *http.Request, c mockCall) (int, any) {
	s.stMu.Lock()
	status, errMsg, noEcho := s.status, s.errMsg, s.noEcho
	s.stMu.Unlock()
	if c.lxm == lxmConfirmRegistration {
		if noEcho {
			return 200, map[string]any{"challenge": "not-the-one"}
		}
		return 200, map[string]any{"challenge": c.body["challenge"]}
	}
	if errMsg != "" {
		return status, map[string]any{"error": errMsg}
	}
	return status, map[string]any{}
}

// reg is the reference's notifyRegistration(): this endpoint, with a token.
func (s *notifSyncer) reg(token string) *notifyReg {
	if token == "" {
		token = "syncer-token"
	}
	return &notifyReg{endpoint: s.url, token: token}
}

func (s *notifSyncer) setStatus(status int) {
	s.stMu.Lock()
	s.status, s.errMsg = status, ""
	s.stMu.Unlock()
}

func (s *notifSyncer) setError(status int, name string) {
	s.stMu.Lock()
	s.status, s.errMsg = status, name
	s.stMu.Unlock()
}

func (s *notifSyncer) setNoEcho(on bool) {
	s.stMu.Lock()
	s.noEcho = on
	s.stMu.Unlock()
}

// reset restores the default answers, forgets the recorded calls and drops any
// responder override.
func (s *notifSyncer) reset(t *testing.T) {
	t.Helper()
	s.setStatus(200)
	s.setNoEcho(false)
	s.setRespond(s.respond)
	s.mockService.mu.Lock()
	s.mockService.calls = s.mockService.calls[:0]
	s.mockService.mu.Unlock()
}

// updates are the update bodies of the notifySpaceUpdate calls received.
func (s *notifSyncer) updates() []map[string]any {
	var out []map[string]any
	for _, c := range s.callsTo(lxmNotifySpaceUpdate) {
		if u, ok := c.body["update"].(map[string]any); ok {
			out = append(out, u)
		}
	}
	return out
}

// hold pauses the first notifySpaceUpdate the mock receives until release, for
// a delivery held in flight. Later calls are answered as usual.
func (s *notifSyncer) hold(match func(mockCall) bool) (delivered, release, restore func()) {
	deliveredCh, releaseCh := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	var mu sync.Mutex
	held := false
	s.setRespond(func(r *http.Request, c mockCall) (int, any) {
		if c.lxm == lxmNotifySpaceUpdate && match(c) {
			mu.Lock()
			first := !held
			held = true
			mu.Unlock()
			if first {
				once.Do(func() { close(deliveredCh) })
				<-releaseCh
			}
		}
		return s.respond(r, c)
	})
	released := func() { releaseOnce.Do(func() { close(releaseCh) }) }
	return func() { <-deliveredCh }, released, func() {
		released()
		s.setRespond(s.respond)
	}
}

// notifRegistrations are the notify registrations the PDS holds for a space.
func notifRegistrations(t *testing.T, p *spacePDS, spaceURI string) []models.SpaceNotifyRegistration {
	t.Helper()
	var rows []models.SpaceNotifyRegistration
	if err := p.s.db.Client().Where("space = ?", spaceURI).Order("endpoint, token").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// notifRegistration is one registration, or nil.
func notifRegistration(t *testing.T, p *spacePDS, spaceURI, endpoint, token string) *models.SpaceNotifyRegistration {
	t.Helper()
	var rows []models.SpaceNotifyRegistration
	if err := p.s.db.Client().
		Where("space = ? AND endpoint = ? AND token = ?", spaceURI, endpoint, token).
		Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return nil
	}
	return &rows[0]
}

// notifPutRegistration writes a registration expiring at expiresAt, as an
// authorization that lapsed at that time would have left it.
func notifPutRegistration(t *testing.T, p *spacePDS, spaceURI, endpoint, token string, expiresAt time.Time) {
	t.Helper()
	ref := notifMustParseRef(t, spaceURI)
	st := p.s.spaceStore(p.s.db.Client(), ref.Authority)
	if err := st.putNotifyRegistration(spaceURI, endpoint, token, isoTime(expiresAt)); err != nil {
		t.Fatal(err)
	}
}

// notifSyncerRetries are the queued syncer notices.
func notifSyncerRetries(t *testing.T, p *spacePDS) []models.SpaceSyncerNotificationRetry {
	t.Helper()
	var rows []models.SpaceSyncerNotificationRetry
	if err := p.s.db.Client().Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// notifMustParseRef parses a space reference, failing the test.
func notifMustParseRef(t *testing.T, s string) space.Ref {
	t.Helper()
	ref, err := space.ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
