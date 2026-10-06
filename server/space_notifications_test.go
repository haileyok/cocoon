package server

// Ported from packages/pds/tests/space/notifications.test.ts
// (bluesky-social/atproto 5b95b2f2). The reference drives its SpaceNotifications
// class directly with jest-spied collaborators; Cocoon's equivalent is
// server/space_notify.go, driven here through notifyAndQueue (the reference's
// awaited notify()) and retrySpaceNotifications (the reference's retryPending();
// the background worker goroutine is not started by the test harness, so a
// pass runs only when a case calls it).
//
// Where the reference injects a failure with a jest spy, this port injects the
// closest seam available without touching non-test files:
//   - a failing DID resolution: the shared DID directory taken down,
//   - a failing local storage read: the table the local notify path reads
//     dropped for the duration of one delivery (recreated and its rows
//     restored afterwards),
//   - an in-flight delivery paused mid-request: a mock response held on a
//     channel, released by the test.
//
// N/A for Cocoon, noted per case: there is no lease, so the reference's
// "elects one retry worker and allows takeover after its lease expires" case
// has no counterpart, and Cocoon's local notify path never fails with a
// retryable HTTP status, so the "retries local HTTP %s failures" cases are
// ported as local storage failures instead (their status-over-name aspect is
// covered by "uses the HTTP status even when the XRPC error name suggests a
// rejection").

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/haileyok/cocoon/internal/space"
	"github.com/haileyok/cocoon/models"
)

// notificationsNet is one test network: a writer and an outsider with a local
// space, plus a mock service registered as a remote space host authority
// whose responses each case controls.
type notificationsNet struct {
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

func newNotificationsNet(t *testing.T) *notificationsNet {
	t.Helper()
	n := &notificationsNet{net: newSpaceNet(t), status: 200}
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
	n.host = n.net.newMockService("atproto_space_host", n.defaultRespond)
	n.spaceURI = "at://" + n.host.did + "/space/com.example.group/notifications"
	return n
}

// setResponse controls the mock space host's response, restoring the previous
// one when the returned func is called.
func (n *notificationsNet) setResponse(status int, errName string) func() {
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

// reset is the reference's beforeEach: default responses, no queued retries.
func (n *notificationsNet) reset(t *testing.T) {
	t.Helper()
	n.setResponse(200, "")()
	n.host.setRespond(n.defaultRespond)
	n.host.mu.Lock()
	n.host.calls = n.host.calls[:0]
	n.host.mu.Unlock()
	if err := n.pds1.s.db.Client().
		Where("1 = 1").
		Delete(&models.SpaceNotificationRetry{}).Error; err != nil {
		t.Fatal(err)
	}
}

// notifyNow sends one notification synchronously, as the reference's awaited
// notifications.notify does.
func (n *notificationsNet) notifyNow(t *testing.T, spaceURI, did string, commit *notifCommit) {
	t.Helper()
	h, err := space.LtHashFromState(commit.setHash)
	if err != nil {
		t.Fatal(err)
	}
	d := h.Digest()
	n.pds1.s.notifyAndQueue(context.Background(), notifyWriteBody{
		Space: spaceURI, Repo: did, RepoRev: commit.rev, Hash: d[:],
	})
	n.net.waitSpaceJobs()
}

// notifyBody is the notifyWrite body for a commit, built without the testing.T
// so it is safe to call from a helper goroutine.
func (n *notificationsNet) notifyBody(spaceURI, did string, commit *notifCommit) (notifyWriteBody, bool) {
	h, err := space.LtHashFromState(commit.setHash)
	if err != nil {
		return notifyWriteBody{}, false
	}
	d := h.Digest()
	return notifyWriteBody{Space: spaceURI, Repo: did, RepoRev: commit.rev, Hash: d[:]}, true
}

// retryPass runs one retry pass, as the reference's awaited retryPending does.
func (n *notificationsNet) retryPass(t *testing.T) {
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

// notifRetryRow returns the single queued retry row, failing on none or many.
func notifRetryRow(t *testing.T, n *notificationsNet) models.SpaceNotificationRetry {
	t.Helper()
	rows := notifRetryRows(t, n)
	if len(rows) != 1 {
		t.Fatalf("expected one retry row, got %d", len(rows))
	}
	return rows[0]
}

func notifRetryRows(t *testing.T, n *notificationsNet) []models.SpaceNotificationRetry {
	t.Helper()
	var rows []models.SpaceNotificationRetry
	if err := n.pds1.s.db.Client().Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// notifMakeDue sets every retry row due now, as the reference's makeDue does.
func notifMakeDue(t *testing.T, n *notificationsNet) {
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
		t.Fatalf("hash %s does not match the commit digest", base64.StdEncoding.EncodeToString(hash))
	}
}

func notifMustParseRef(t *testing.T, s string) space.Ref {
	t.Helper()
	ref, err := space.ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// notifDropConfigs makes the local notify path fail retryably, as the
// reference's actorStore.read spy does: the local path reads the space's
// governance config, and a missing table is a storage error, which is
// retryable. The returned func recreates the table with its rows.
func notifDropConfigs(t *testing.T, n *notificationsNet) func() {
	t.Helper()
	db := n.pds1.s.db
	var cfgs []models.SimplespaceConfig
	if err := db.Client().Find(&cfgs).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(context.Background(), "DROP TABLE simplespace_configs", nil).Error; err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := db.AutoMigrate(&models.SimplespaceConfig{}); err != nil {
				t.Fatal(err)
			}
			if len(cfgs) > 0 {
				if err := db.Client().Create(&cfgs).Error; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// notifHoldDelivery wraps the mock's responder so the delivery of the commit
// with rev holdRev is paused until the returned release func is called,
// letting a second notification run concurrently, as the reference's
// once-only resolver spy does. The started func returns once the held request
// has reached the mock. release is safe to call more than once. Holding by rev
// (rather than by arrival order) keeps the hold deterministic: the goroutine
// driving the older delivery and the test's newer one race to the mock.
func (n *notificationsNet) notifHoldDelivery(holdRev string) (started, release func(), restore func()) {
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

func TestSpaceNotificationRetries(t *testing.T) {
	n := newNotificationsNet(t)

	t.Run("sends immediately without queueing a successful notification", func(t *testing.T) {
		n.reset(t)
		commit := makeNotifCommit()
		n.notifyNow(t, n.spaceURI, n.writer.did, commit)
		calls := n.host.callsTo(lxmNotifyWrite)
		if len(calls) != 1 {
			t.Fatalf("expected 1 notifyWrite call, got %d", len(calls))
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
		if row := notifRetryRow(t, n); row.RepoRev != older.rev {
			t.Fatalf("repoRev %q, want %q", row.RepoRev, older.rev)
		}

		restore()
		n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
			t.Fatalf("expected 2 notifyWrite calls, got %d", len(calls))
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
			notifHashEquals(t, row.Hash, commit)

			notifMakeDue(t, n)
			n.retryPass(t)
			if row := notifRetryRow(t, n); row.Attempts != 2 {
				t.Fatalf("attempts %d, want 2", row.Attempts)
			}
			if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
				t.Fatalf("expected 2 notifyWrite calls, got %d", len(calls))
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
			if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 3 {
				t.Fatalf("expected 3 notifyWrite calls, got %d", len(calls))
			}
		})
	}

	// The reference's "retries local HTTP %s failures" (429, 503) spies the
	// local actor store to reject with an XRPCError carrying a retryable status
	// and a rejecting name. Cocoon's local notify path returns no retryable
	// HTTP status (its local failures are 400/403 XRPC errors or storage
	// errors), so the local-status aspect is N/A; the portable part — that a
	// local failure is queued and retried, with no HTTP call — is ported here
	// as a local storage failure, the same seam the reference's rejection case
	// uses for its one-off read failure.
	for _, code := range []int{429, 503} {
		t.Run(fmt.Sprintf("retries local failures (reference: local HTTP %d)", code), func(t *testing.T) {
			n.reset(t)
			restoreTable := notifDropConfigs(t, n)
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
			if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 0 {
				t.Fatalf("expected 0 notifyWrite calls, got %d", len(calls))
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
				if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 1 {
					t.Fatalf("expected 1 notifyWrite call, got %d", len(calls))
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
					if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
						t.Fatalf("expected 2 notifyWrite calls, got %d", len(calls))
					}
					if rows := notifRetryRows(t, n); len(rows) != 0 {
						t.Fatalf("queued %d retry rows", len(rows))
					}
					n.retryPass(t)
					if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
						t.Fatalf("expected 2 notifyWrite calls after another pass, got %d", len(calls))
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
				// retryable error; the dropped config table is that one-off
				// failure, restored before the retry pass so the retry reaches
				// the same definitive rejection as the first notify would.
				restoreTable := notifDropConfigs(t, n)
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
				if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 0 {
					t.Fatalf("expected 0 notifyWrite calls, got %d", len(calls))
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
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 0 {
			t.Fatalf("expected 0 notifyWrite calls, got %d", len(calls))
		}
		if row := notifRetryRow(t, n); row.RepoRev != commit.rev {
			t.Fatalf("repoRev %q, want %q", row.RepoRev, commit.rev)
		}
	})

	t.Run("surfaces an error if the failed delivery cannot be queued", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "")
		// The reference mocks the queue write to fail once and expects notify
		// to reject with the error; here the queue table is gone.
		db := n.pds1.s.db
		if err := db.Exec(context.Background(), "DROP TABLE space_notification_retries", nil).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := db.AutoMigrate(&models.SpaceNotificationRetry{}); err != nil {
				t.Fatal(err)
			}
		})
		commit := makeNotifCommit()
		h, err := space.LtHashFromState(commit.setHash)
		if err != nil {
			t.Fatal(err)
		}
		d := h.Digest()
		if err := n.pds1.s.notifyAndQueue(context.Background(), notifyWriteBody{Space: n.spaceURI, Repo: n.writer.did, RepoRev: commit.rev, Hash: d[:]}); err == nil {
			t.Fatal("a failed queue write was not surfaced")
		}
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 1 {
			t.Fatalf("expected 1 notifyWrite call, got %d", len(calls))
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
		notifHashEquals(t, row.Hash, newer)

		n.notifyNow(t, n.spaceURI, n.writer.did, older)
		n.notifyNow(t, n.spaceURI, n.writer.did, newer)
		after := notifRetryRow(t, n)
		if after.RepoRev != row.RepoRev || after.Attempts != row.Attempts || after.RetryAt != row.RetryAt ||
			after.ExpiresAt != row.ExpiresAt || string(after.Hash) != string(row.Hash) {
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
			started, release, restoreRespond := n.notifHoldDelivery(older.rev)
			defer restoreRespond()
			done := make(chan struct{})
			go func() {
				defer close(done)
				body, ok := n.notifyBody(n.spaceURI, n.writer.did, older)
				if !ok {
					return
				}
				n.pds1.s.notifyAndQueue(context.Background(), body)
				n.net.waitSpaceJobs()
			}()
			go started()

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
		// Not due yet: the pass reads nothing and delivers nothing.
		n.retryPass(t)
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 1 {
			t.Fatalf("expected 1 notifyWrite call, got %d", len(calls))
		}

		notifMakeDue(t, n)
		before := time.Now()
		n.retryPass(t)
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
			t.Fatalf("expected 2 notifyWrite calls, got %d", len(calls))
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
			started, release, restoreRespond := n.notifHoldDelivery(older.rev)
			defer restoreRespond()
			done := make(chan struct{})
			go func() {
				defer close(done)
				n.pds1.s.retrySpaceNotifications(context.Background())
				n.net.waitSpaceJobs()
			}()
			go started()

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
				after.ExpiresAt != fresh.ExpiresAt || string(after.Hash) != string(fresh.Hash) {
				t.Fatalf("row changed: %+v vs %+v", after, fresh)
			}
			if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 3 {
				t.Fatalf("expected 3 notifyWrite calls, got %d", len(calls))
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
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
			t.Fatalf("expected 2 notifyWrite calls, got %d", len(calls))
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
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
			t.Fatalf("expected 2 notifyWrite calls, got %d", len(calls))
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
	// lease expires" case is N/A for Cocoon: there is no lease and a single
	// retry worker (server/space_notify.go), so there is nothing to elect or
	// take over.

	t.Run("defers retries for inactive accounts and resumes after activation", func(t *testing.T) {
		n.reset(t)
		n.setResponse(503, "")
		n.notifyNow(t, n.spaceURI, n.writer.did, makeNotifCommit())
		notifMakeDue(t, n)
		if err := n.pds1.s.db.Exec(context.Background(),
			"UPDATE repos SET deactivated = true WHERE did = ?", nil, n.writer.did).Error; err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if err := n.pds1.s.db.Exec(context.Background(),
					"UPDATE repos SET deactivated = false WHERE did = ?", nil, n.writer.did).Error; err != nil {
					t.Fatal(err)
				}
			}()
			n.setResponse(200, "")
			n.retryPass(t)
			if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 1 {
				t.Fatalf("expected 1 notifyWrite call, got %d", len(calls))
			}
			if row := notifRetryRow(t, n); row.Attempts != 2 {
				t.Fatalf("attempts %d, want 2", row.Attempts)
			}
		}()
		notifMakeDue(t, n)
		n.retryPass(t)
		if calls := n.host.callsTo(lxmNotifyWrite); len(calls) != 2 {
			t.Fatalf("expected 2 notifyWrite calls, got %d", len(calls))
		}
	})
}
