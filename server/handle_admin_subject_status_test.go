package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/labstack/echo/v4"
)

// adminCall sends a request as the admin through the admin middleware.
func adminCall(t *testing.T, s *Server, method, target, body string) (int, string) {
	t.Helper()
	c, rec := newRequestContext(method, target, body, map[string]string{})
	c.Request().SetBasicAuth("admin", s.config.AdminPassword)
	h := s.handleAdminMiddleware(func(e2 echo.Context) error {
		var did string
		if method == http.MethodGet {
			did = e2.QueryParam("did")
		} else if strings.Contains(body, "recordRef") || strings.Contains(body, "blobRef") {
			// let the handler itself decide; pass through directly
		}
		if did != "" {
			return s.handleAdminGetSubjectStatus(e2)
		}
		return s.handleAdminUpdateSubjectStatus(e2)
	})
	if err := h(c); err != nil {
		t.Fatalf("admin handler error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

func TestAdminUpdateSubjectStatus(t *testing.T) {
	t.Run("repo takedown and untakedown", func(t *testing.T) {
		s := newTestServer(t)
		s.evtman = newTestEvtman(t)
		s.repoman = NewRepoMan(s)
		acct := s.createTestAccount(t, "alice.pds.test")
		s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

		code, body := adminCall(t, s, http.MethodPost, "/xrpc/com.atproto.admin.updateSubjectStatus", `{
			"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "`+acct.Did+`"},
			"takedown": {"applied": true, "ref": "spam"}
		}`)
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", code, body)
		}
		var resp map[string]any
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		if subject, _ := resp["subject"].(map[string]any); subject == nil || subject["did"] != acct.Did {
			t.Fatalf("unexpected subject echo: %v", resp["subject"])
		}
		if takedown, _ := resp["takedown"].(map[string]any); takedown == nil || takedown["applied"] != true || takedown["ref"] != "spam" {
			t.Fatalf("unexpected takedown echo: %v", resp["takedown"])
		}

		// the DB reflects it
		urepo := mustRepoActor(t, s, acct.Did)
		if urepo.Repo.TakedownRef == nil || *urepo.Repo.TakedownRef != "spam" {
			t.Fatalf("takedown_ref not applied: %v", urepo.Repo.TakedownRef)
		}

		// the account can no longer write
		c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{
			"repo": "`+acct.Did+`",
			"collection": "com.example.test",
			"record": {"$type": "com.example.test", "value": "hi"}
		}`, nil)
		c.Set("repo", urepo)
		c.Set("credentialKind", credentialLegacyAccess)
		if err := s.handleCreateRecord(c); err != nil {
			t.Fatalf("handleCreateRecord: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("taken-down account write should be refused, got %d: %s", rec.Code, rec.Body.String())
		}

		// its repo is hidden from ordinary reads
		c, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.getRepoStatus?did="+url.QueryEscape(acct.Did), "", nil)
		handler := s.handleRepoReadMiddleware(s.handleSyncGetRepoStatus)
		if err := handler(c); err != nil {
			t.Fatalf("getRepoStatus: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("taken-down repo read should be refused, got %d: %s", rec.Code, rec.Body.String())
		}

		// getSubjectStatus reports it
		code, body = adminCall(t, s, http.MethodGet, "/xrpc/com.atproto.admin.getSubjectStatus?did="+url.QueryEscape(acct.Did), "")
		if code != http.StatusOK {
			t.Fatalf("getSubjectStatus: expected 200, got %d: %s", code, body)
		}
		resp = map[string]any{}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		if takedown, _ := resp["takedown"].(map[string]any); takedown == nil || takedown["applied"] != true {
			t.Fatalf("getSubjectStatus should report takedown applied: %s", body)
		}

		// untakedown
		code, body = adminCall(t, s, http.MethodPost, "/xrpc/com.atproto.admin.updateSubjectStatus", `{
			"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "`+acct.Did+`"},
			"takedown": {"applied": false}
		}`)
		if code != http.StatusOK {
			t.Fatalf("expected 200 untakedown, got %d: %s", code, body)
		}
		urepo = mustRepoActor(t, s, acct.Did)
		if urepo.Repo.TakedownRef != nil {
			t.Fatalf("takedown_ref not cleared: %v", urepo.Repo.TakedownRef)
		}

		// writes work again
		c, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{
			"repo": "`+acct.Did+`",
			"collection": "com.example.test",
			"record": {"$type": "com.example.test", "value": "hi"}
		}`, nil)
		c.Set("repo", urepo)
		c.Set("credentialKind", credentialLegacyAccess)
		if err := s.handleCreateRecord(c); err != nil {
			t.Fatalf("handleCreateRecord: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("post-untakedown write should succeed, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("repo deactivate and reactivate", func(t *testing.T) {
		s := newTestServer(t)
		persister, err := NewDbPersister(s.db.Client(), time.Hour)
		if err != nil {
			t.Fatalf("new persister: %v", err)
		}
		s.evtman = events.NewEventManager(persister)
		acct := s.createTestAccount(t, "bob.pds.test")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		evts, _, err := s.evtman.Subscribe(ctx, "test", func(*events.XRPCStreamEvent) bool { return true }, nil)
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}

		code, body := adminCall(t, s, http.MethodPost, "/xrpc/com.atproto.admin.updateSubjectStatus", `{
			"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "`+acct.Did+`"},
			"deactivated": {"applied": true}
		}`)
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", code, body)
		}
		if urepo := mustRepoActor(t, s, acct.Did); !urepo.Repo.Deactivated {
			t.Fatal("deactivated not applied")
		}

		// the firehose carries an #account event like deactivateAccount does
		waitAccountEvent(t, evts, acct.Did, false, "deactivated")

		code, body = adminCall(t, s, http.MethodPost, "/xrpc/com.atproto.admin.updateSubjectStatus", `{
			"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "`+acct.Did+`"},
			"deactivated": {"applied": false}
		}`)
		if code != http.StatusOK {
			t.Fatalf("expected 200 reactivate, got %d: %s", code, body)
		}
		if urepo := mustRepoActor(t, s, acct.Did); urepo.Repo.Deactivated {
			t.Fatal("deactivated not cleared")
		}
		waitAccountEvent(t, evts, acct.Did, true, "")
	})

	t.Run("record and blob subjects unsupported", func(t *testing.T) {
		s := newTestServer(t)
		for _, subject := range []string{
			`{"$type": "com.atproto.admin.defs#recordRef", "uri": "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3jxyzabcdef"}`,
			`{"$type": "com.atproto.admin.defs#blobRef", "did": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "cid": "bafyreicdd"}`,
		} {
			code, body := adminCall(t, s, http.MethodPost, "/xrpc/com.atproto.admin.updateSubjectStatus", `{"subject": `+subject+`}`)
			if code != http.StatusBadRequest && code != http.StatusNotImplemented {
				t.Fatalf("subject %s: expected 400/501, got %d: %s", subject, code, body)
			}
		}
	})

	t.Run("unauthenticated admin request refused", func(t *testing.T) {
		s := newTestServer(t)
		s.createTestAccount(t, "carol.pds.test")

		c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.admin.updateSubjectStatus", `{
			"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"},
			"takedown": {"applied": true}
		}`, nil)
		h := s.handleAdminMiddleware(s.handleAdminUpdateSubjectStatus)
		if err := h(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 without admin credentials, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

// waitAccountEvent reads events until an #account event for did appears.
func waitAccountEvent(t *testing.T, evts <-chan *events.XRPCStreamEvent, did string, active bool, status string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("no #account event observed for %s (active=%t)", did, active)
		case ev := <-evts:
			if ev.RepoAccount == nil {
				continue
			}
			acct := ev.RepoAccount
			if acct.Did != did {
				continue
			}
			if acct.Active != active {
				t.Fatalf("#account event active=%t, want %t", acct.Active, active)
			}
			if status == "" && acct.Status != nil && *acct.Status != "" {
				t.Fatalf("#account event status=%q, want none", *acct.Status)
			}
			if status != "" && (acct.Status == nil || *acct.Status != status) {
				t.Fatalf("#account event status=%v, want %q", acct.Status, status)
			}
			return
		}
	}
}

var _ = atproto.SyncSubscribeRepos_Account{}
