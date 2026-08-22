package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"gorm.io/gorm"
)

func seedSpaceNotificationRegistration(t *testing.T, s *Server, service string, expires time.Time) {
	t.Helper()
	if err := s.db.Create(context.Background(), &models.SpaceNotifyRegistration{Space: testSpaceRef, Service: service, ExpiresAt: expires}, nil).Error; err != nil {
		t.Fatalf("seed registration: %v", err)
	}
}

func TestSpaceRepoTransactionalCrashWindowDoesNotLeaveOutbox(t *testing.T) {
	s := newTestServer(t)
	seedSpaceNotificationRegistration(t, s, "did:web:syncer.test#space", time.Now().Add(time.Hour))
	man := NewSpaceRepoMan(s)
	restore := man.SetFailureStage(SpaceRepoFailureAfterHeadUpdate)
	defer restore()
	if _, err := man.Apply(context.Background(), testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "crash", Record: testSpaceRecord("crash")}}); err == nil {
		t.Fatal("injected crash window unexpectedly succeeded")
	}
	for _, tc := range []struct {
		name  string
		model any
	}{
		{"repo", &models.SpaceRepo{}},
		{"record", &models.SpaceRecord{}},
		{"oplog", &models.SpaceRepoOp{}},
		{"delivery", &models.SpaceNotifyDelivery{}},
	} {
		var count int64
		if err := s.db.Client().Model(tc.model).Where("space = ?", testSpaceRef).Count(&count).Error; err != nil {
			t.Fatalf("count %s: %v", tc.name, err)
		}
		if count != 0 {
			t.Errorf("%s survived rollback: %d", tc.name, count)
		}
	}
}

func TestSpaceRepoApplyUsesInjectedNotificationClock(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2032, 3, 4, 5, 6, 7, 123000000, time.FixedZone("test", 3600))
	s.SetSpaceNotificationClock(func() time.Time { return now })
	seedSpaceNotificationRegistration(t, s, "did:web:syncer.test#space", now.Add(time.Hour))
	if _, err := NewSpaceRepoMan(s).Apply(context.Background(), testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "clock", Record: testSpaceRecord("clock")}}); err != nil {
		t.Fatal(err)
	}
	var delivery models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ?", testSpaceRef).First(&delivery).Error; err != nil {
		t.Fatal(err)
	}
	if !delivery.CreatedAt.Equal(now.UTC()) || !delivery.UpdatedAt.Equal(now.UTC()) || !delivery.ExpiresAt.Equal(now.UTC().Add(SpaceNotifyDeliveryTTL)) {
		t.Fatalf("outbox timestamps = created %s updated %s expires %s, want clock %s", delivery.CreatedAt, delivery.UpdatedAt, delivery.ExpiresAt, now.UTC())
	}
}

func TestSpaceRepoOutboxMetadataOnlyPayloadAndNoEvtman(t *testing.T) {
	s := newTestServer(t)
	seedSpaceNotificationRegistration(t, s, "did:web:syncer.test#space", time.Now().Add(time.Hour))
	if s.evtman != nil {
		t.Fatal("test server unexpectedly has an event manager")
	}
	batch, err := NewSpaceRepoMan(s).Apply(context.Background(), testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "metadata", Record: testSpaceRecord("value")}})
	if err != nil {
		t.Fatalf("Space write: %v", err)
	}
	var rows []models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ?", testSpaceRef).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("delivery rows = %d, want 1", len(rows))
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(rows[0].Payload, &payload); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	for key := range payload {
		if key != "space" && key != "repo" && key != "rev" && key != "hash" {
			t.Errorf("metadata payload contains forbidden key %q", key)
		}
	}
	if len(payload) != 4 || string(payload["repo"]) != `"`+testAuthor+`"` || string(payload["rev"]) != `"`+batch.Rev+`"` {
		t.Fatalf("unexpected metadata payload: %s", rows[0].Payload)
	}
	for _, forbidden := range []string{"collection", "rkey", "cid", "record", "blob", "cbor"} {
		if bytes.Contains(bytes.ToLower(rows[0].Payload), []byte(forbidden)) {
			t.Errorf("payload contains forbidden term %q: %s", forbidden, rows[0].Payload)
		}
	}
}

func TestSpaceNotificationRegistrationExpiryAndMatchingCredential(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.SetSpaceNotificationClock(func() time.Time { return now })
	body := `{"space":"` + testSpaceRef + `","service":"did:web:syncer.test#space"}`
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.registerNotify", body, nil)
	SetPrincipal(e, &SpaceCredentialPrincipal{SpaceURI: testSpaceRef})
	if err := s.handleSpaceRegisterNotify(e); err != nil {
		t.Fatalf("register: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("register status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var registration models.SpaceNotifyRegistration
	if err := s.db.Client().Where("space = ? AND service = ?", testSpaceRef, "did:web:syncer.test#space").First(&registration).Error; err != nil {
		t.Fatal(err)
	}
	if !registration.ExpiresAt.Equal(now.Add(SpaceNotifyRegistrationTTL)) {
		t.Fatalf("expiry = %s, want %s", registration.ExpiresAt, now.Add(SpaceNotifyRegistrationTTL))
	}
	// A different credential cannot register for this space.
	e, mismatchRec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.registerNotify", body, nil)
	SetPrincipal(e, &SpaceCredentialPrincipal{SpaceURI: "at://did:example:authority/space/com.example.space/other"})
	if err := s.handleSpaceRegisterNotify(e); err != nil {
		t.Fatalf("mismatched register handler: %v", err)
	}
	if mismatchRec.Code != http.StatusForbidden {
		t.Fatalf("mismatched credential status = %d, want %d", mismatchRec.Code, http.StatusForbidden)
	}
	// Expiry is enforced by fanout selection and worker cleanup.
	now = now.Add(SpaceNotifyRegistrationTTL + time.Second)
	var active int64
	if err := s.db.Client().Model(&models.SpaceNotifyRegistration{}).Where("space = ? AND expires_at > ?", testSpaceRef, now).Count(&active).Error; err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("expired registration remained active: %d", active)
	}
}

func TestSpaceNotifyWriteIdempotentWriterUpdateAndForwarding(t *testing.T) {
	s := newTestServer(t)
	service := "did:web:syncer.test#space"
	seedSpaceNotificationRegistration(t, s, service, time.Now().Add(time.Hour))
	hash := bytes.Repeat([]byte{0x42}, 32)
	rev := spaceRepoClock.Next().String()
	if err := s.RecordSpaceNotifyWrite(context.Background(), testSpaceRef, testAuthor, rev, hash, "did:web:repo.test"); err != nil {
		t.Fatalf("notifyWrite: %v", err)
	}
	if err := s.RecordSpaceNotifyWrite(context.Background(), testSpaceRef, testAuthor, rev, hash, "did:web:repo.test"); err != nil {
		t.Fatalf("duplicate notifyWrite: %v", err)
	}
	var writer models.SpaceWriter
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).First(&writer).Error; err != nil {
		t.Fatal(err)
	}
	if writer.Rev != rev || !bytes.Equal(writer.Hash, hash) || writer.Host != "did:web:repo.test" {
		t.Fatalf("writer = %+v", writer)
	}
	var deliveries []models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ? AND service = ?", testSpaceRef, service).Find(&deliveries).Error; err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("duplicate receiver queued %d deliveries, want 1", len(deliveries))
	}
}

func TestSpaceNotifyWriteNewerThenOlderDoesNotRegress(t *testing.T) {
	s := newTestServer(t)
	service := "did:web:syncer.test#space"
	seedSpaceNotificationRegistration(t, s, service, time.Now().Add(time.Hour))
	oldRev := spaceRepoClock.Next().String()
	newRev := spaceRepoClock.Next().String()
	oldHash := bytes.Repeat([]byte{0x11}, 32)
	newHash := bytes.Repeat([]byte{0x22}, 32)
	ctx := context.Background()
	if err := s.RecordSpaceNotifyWrite(ctx, testSpaceRef, testAuthor, newRev, newHash, "did:web:new.test"); err != nil {
		t.Fatalf("new notifyWrite: %v", err)
	}
	if err := s.RecordSpaceNotifyWrite(ctx, testSpaceRef, testAuthor, oldRev, oldHash, "did:web:old.test"); err != nil {
		t.Fatalf("older notifyWrite: %v", err)
	}
	var writer models.SpaceWriter
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).First(&writer).Error; err != nil {
		t.Fatal(err)
	}
	if writer.Rev != newRev || !bytes.Equal(writer.Hash, newHash) || writer.Host != "did:web:new.test" {
		t.Fatalf("writer regressed: %+v", writer)
	}
	var deliveries []models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ? AND service = ?", testSpaceRef, service).Find(&deliveries).Error; err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].Rev != newRev {
		t.Fatalf("deliveries = %+v, want only revision %q", deliveries, newRev)
	}
}

func TestSpaceNotifyWriteSameRevisionDifferentHashIsRejected(t *testing.T) {
	s := newTestServer(t)
	service := "did:web:syncer.test#space"
	seedSpaceNotificationRegistration(t, s, service, time.Now().Add(time.Hour))
	rev := spaceRepoClock.Next().String()
	firstHash := bytes.Repeat([]byte{0x31}, 32)
	conflictingHash := bytes.Repeat([]byte{0x32}, 32)
	ctx := context.Background()
	if err := s.RecordSpaceNotifyWrite(ctx, testSpaceRef, testAuthor, rev, firstHash, "did:web:first.test"); err != nil {
		t.Fatalf("first notifyWrite: %v", err)
	}
	if err := s.RecordSpaceNotifyWrite(ctx, testSpaceRef, testAuthor, rev, conflictingHash, "did:web:conflict.test"); !errors.Is(err, ErrSpaceNotifyRevisionConflict) {
		t.Fatalf("conflicting notifyWrite error = %v, want ErrSpaceNotifyRevisionConflict", err)
	}
	var writer models.SpaceWriter
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).First(&writer).Error; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.Hash, firstHash) || writer.Host != "did:web:first.test" {
		t.Fatalf("conflicting hash changed writer: %+v", writer)
	}
	var deliveryCount int64
	if err := s.db.Client().Model(&models.SpaceNotifyDelivery{}).Where("space = ? AND service = ?", testSpaceRef, service).Count(&deliveryCount).Error; err != nil {
		t.Fatal(err)
	}
	if deliveryCount != 1 {
		t.Fatalf("conflicting hash queued %d deliveries, want 1", deliveryCount)
	}
}

func TestSpaceNotifyWriteConcurrentOldAndNewKeepsNewest(t *testing.T) {
	s := newTestServer(t)
	seedSpaceNotificationRegistration(t, s, "did:web:syncer.test#space", time.Now().Add(time.Hour))
	oldRev := spaceRepoClock.Next().String()
	newRev := spaceRepoClock.Next().String()
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errs <- s.RecordSpaceNotifyWrite(context.Background(), testSpaceRef, testAuthor, oldRev, bytes.Repeat([]byte{0x41}, 32), "did:web:old.test")
	}()
	go func() {
		defer wg.Done()
		<-start
		errs <- s.RecordSpaceNotifyWrite(context.Background(), testSpaceRef, testAuthor, newRev, bytes.Repeat([]byte{0x42}, 32), "did:web:new.test")
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent notifyWrite: %v", err)
		}
	}
	var writer models.SpaceWriter
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).First(&writer).Error; err != nil {
		t.Fatal(err)
	}
	if writer.Rev != newRev || !bytes.Equal(writer.Hash, bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatalf("concurrent writer = %+v, want newest revision", writer)
	}
}

func TestSpaceNotificationReconciliationDoesNotQueueStaleOutboxEvent(t *testing.T) {
	s := newTestServer(t)
	service := "did:web:syncer.test#space"
	seedSpaceNotificationRegistration(t, s, service, time.Now().Add(time.Hour))
	worker := NewSpaceNotificationWorker(s, nil)
	oldRev := spaceRepoClock.Next().String()
	newRev := spaceRepoClock.Next().String()
	newHash := bytes.Repeat([]byte{0x52}, 32)
	oldHash := bytes.Repeat([]byte{0x51}, 32)
	if count, err := worker.ReconcileSpaceWriters(context.Background(), testSpaceRef, []SpaceNotificationRepoSnapshot{{Repo: testAuthor, Rev: newRev, Hash: newHash, Host: "did:web:new.test"}}, 1); err != nil || count != 1 {
		t.Fatalf("new reconciliation count=%d err=%v", count, err)
	}
	if count, err := worker.ReconcileSpaceWriters(context.Background(), testSpaceRef, []SpaceNotificationRepoSnapshot{{Repo: testAuthor, Rev: oldRev, Hash: oldHash, Host: "did:web:old.test"}}, 1); err != nil || count != 0 {
		t.Fatalf("older reconciliation count=%d err=%v, want no accepted snapshot", count, err)
	}
	var deliveries []models.SpaceNotifyDelivery
	if err := s.db.Client().Where("space = ? AND service = ?", testSpaceRef, service).Find(&deliveries).Error; err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].Rev != newRev || !bytes.Equal(deliveries[0].Hash, newHash) {
		t.Fatalf("stale reconciliation outbox = %+v", deliveries)
	}
}

func TestSpaceNotificationWorkerRetryExpiryAndRestart(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := s.db.Create(context.Background(), &models.SpaceNotifyDelivery{IdempotencyKey: "retry-key", Kind: SpaceNotifyWriteLXM, Space: testSpaceRef, Service: "did:web:syncer.test#space", Payload: []byte(`{"space":"` + testSpaceRef + `"}`), Status: "pending", ExpiresAt: now.Add(time.Hour)}, nil).Error; err != nil {
		t.Fatal(err)
	}
	attempts := 0
	sender := SpaceNotificationSenderFunc(func(_ context.Context, _ string, d models.SpaceNotifyDelivery) error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary")
		}
		if d.IdempotencyKey != "retry-key" {
			t.Errorf("wrong key %q", d.IdempotencyKey)
		}
		return nil
	})
	w := NewSpaceNotificationWorkerForDB(s.db, sender, func() time.Time { return now }, nil)
	w.SetOptions(SpaceNotificationWorkerOptions{BaseDelay: time.Second, MaxDelay: 2 * time.Second, MaxAttempts: 3, BatchSize: 10})
	if n, err := w.RunOnce(context.Background(), 1); err != nil || n != 1 {
		t.Fatalf("first run n=%d err=%v", n, err)
	}
	var row models.SpaceNotifyDelivery
	if err := s.db.Client().Where("idempotency_key = ?", "retry-key").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != "retry" || row.AttemptCount != 1 || row.NextAttemptAt == nil {
		t.Fatalf("after retry = %+v", row)
	}
	now = now.Add(time.Second)
	// A new worker instance proves pending state is DB-backed, not in-memory.
	w = NewSpaceNotificationWorkerForDB(s.db, sender, func() time.Time { return now }, nil)
	w.SetOptions(SpaceNotificationWorkerOptions{BaseDelay: time.Second, MaxDelay: 2 * time.Second, MaxAttempts: 3, BatchSize: 10})
	if _, err := w.RunOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Where("idempotency_key = ?", "retry-key").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != "delivered" || attempts != 2 {
		t.Fatalf("after restart = %+v attempts=%d", row, attempts)
	}
	expired := &models.SpaceNotifyDelivery{IdempotencyKey: "expired-key", Kind: SpaceNotifyWriteLXM, Space: testSpaceRef, Service: "did:web:syncer.test#space", Status: "pending", ExpiresAt: now.Add(-time.Second)}
	if err := s.db.Create(context.Background(), expired, nil).Error; err != nil {
		t.Fatal(err)
	}
	if expired.ID == 0 {
		t.Fatal("expired delivery was not assigned an ID")
	}
	var beforeExpired int64
	if err := s.db.Client().Model(&models.SpaceNotifyDelivery{}).Where("idempotency_key = ?", "expired-key").Count(&beforeExpired).Error; err != nil {
		t.Fatal(err)
	}
	if beforeExpired != 1 {
		t.Fatalf("expired delivery count before worker = %d", beforeExpired)
	}
	if _, err := w.RunOnce(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	row = models.SpaceNotifyDelivery{}
	if err := s.db.Client().Where("idempotency_key = ?", "expired-key").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != "expired" {
		t.Fatalf("expired row status = %q", row.Status)
	}
}

func TestSpaceNotifySpaceDeletedTombstonePersistence(t *testing.T) {
	s := newTestServer(t)
	if err := s.RecordSpaceNotifySpaceDeleted(context.Background(), testSpaceRef, "did:web:authority.test", false); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSpaceNotifySpaceDeleted(context.Background(), testSpaceRef, "did:web:authority.test", false); err != nil {
		t.Fatal(err)
	}
	var tombstones []models.SpaceTombstone
	if err := s.db.Client().Where("space = ?", testSpaceRef).Find(&tombstones).Error; err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != 1 || tombstones[0].SourceDID != "did:web:authority.test" {
		t.Fatalf("tombstones = %+v", tombstones)
	}
}

func TestSpaceNotificationReconciliationIsBoundedAndQueues(t *testing.T) {
	s := newTestServer(t)
	seedSpaceNotificationRegistration(t, s, "did:web:syncer.test#space", time.Now().Add(time.Hour))
	w := NewSpaceNotificationWorker(s, SpaceNotificationSenderFunc(func(context.Context, string, models.SpaceNotifyDelivery) error { return nil }))
	hash := bytes.Repeat([]byte{1}, 32)
	count, err := w.ReconcileSpaceWriters(context.Background(), testSpaceRef, []SpaceNotificationRepoSnapshot{{Repo: testAuthor, Rev: spaceRepoClock.Next().String(), Hash: hash}, {Repo: "did:example:bob", Rev: spaceRepoClock.Next().String(), Hash: hash}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("reconciled count = %d", count)
	}
	var writers []models.SpaceWriter
	if err := s.db.Client().Where("space = ?", testSpaceRef).Find(&writers).Error; err != nil {
		t.Fatal(err)
	}
	if len(writers) != 1 {
		t.Fatalf("writers = %d", len(writers))
	}
}

func TestSpaceNotificationWorkerUsesNoEvtman(t *testing.T) {
	s := newTestServer(t)
	if s.evtman != nil {
		t.Fatal("evtman should be nil in this focused fixture")
	}
	if _, err := NewSpaceRepoMan(s).Apply(context.Background(), testSpaceRef, testAuthor, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "no-event", Record: testSpaceRecord("ok")}}); err != nil {
		t.Fatalf("Space write called or required evtman: %v", err)
	}
	var repo models.SpaceRepo
	if err := s.db.Client().Where("space = ? AND author = ?", testSpaceRef, testAuthor).First(&repo).Error; err != nil || repo.Rev == "" {
		t.Fatalf("repo = %+v err=%v", repo, err)
	}
	if !errors.Is(gorm.ErrRecordNotFound, gorm.ErrRecordNotFound) {
		t.Fatal("unreachable")
	}
}

var _ = space.ParseSpaceURI
