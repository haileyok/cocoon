package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

func insertTestRecord(t *testing.T, s *Server, did, nsid, rkey string, value map[string]any) string {
	t.Helper()
	cbor, err := atdata.MarshalCBOR(value)
	if err != nil {
		t.Fatalf("marshal cbor: %v", err)
	}
	c, err := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256).Sum(cbor)
	if err != nil {
		t.Fatalf("build cid: %v", err)
	}
	rec := models.Record{
		Did:       did,
		CreatedAt: "2024-01-01T00:00:00Z",
		Nsid:      nsid,
		Rkey:      rkey,
		Cid:       c.String(),
		Value:     cbor,
	}
	if err := s.db.Create(context.Background(), &rec, nil).Error; err != nil {
		t.Fatalf("insert record: %v", err)
	}
	return c.String()
}

// TestHandleRepoGetRecordFound returns the locally stored record.
func TestHandleRepoGetRecordFound(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	const nsid = "app.bsky.feed.post"
	const rkey = "3laaaaaaaaa2x"
	cidStr := insertTestRecord(t, s, acct.Did, nsid, rkey, map[string]any{
		"$type": nsid,
		"text":  "hello world",
	})

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo="+acct.Did+"&collection="+nsid+"&rkey="+rkey, "", nil)
	if err := s.handleRepoGetRecord(e); err != nil {
		t.Fatalf("handleRepoGetRecord: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v; raw=%s", err, rec.Body.String())
	}
	if got, want := body["uri"], "at://"+acct.Did+"/"+nsid+"/"+rkey; got != want {
		t.Fatalf("uri = %v, want %s", got, want)
	}
	if got := body["cid"]; got != cidStr {
		t.Fatalf("cid = %v, want %s", got, cidStr)
	}
}

// TestHandleRepoGetRecordNotFound returns 400 RecordNotFound for a missing
// record instead of proxying upstream (which would return another record).
func TestHandleRepoGetRecordNotFound(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	const nsid = "app.bsky.feed.post"
	insertTestRecord(t, s, acct.Did, nsid, "3laaaaaaaaa2x", map[string]any{
		"$type": nsid,
		"text":  "hello world",
	})

	// s.passport / proxy collaborators are nil; if the handler fell through to
	// handleProxy it would not return a clean 400 RecordNotFound.
	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo="+acct.Did+"&collection="+nsid+"&rkey=doesnotexist", "", nil)
	if err := s.handleRepoGetRecord(e); err != nil {
		t.Fatalf("handleRepoGetRecord: %v", err)
	}
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v; raw=%s", err, rec.Body.String())
	}
	if body["error"] != "RecordNotFound" {
		t.Fatalf("error = %q, want RecordNotFound; body=%s", body["error"], rec.Body.String())
	}
}
