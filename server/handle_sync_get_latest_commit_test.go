package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// TestHandleSyncGetLatestCommitReturnsCid asserts the response body uses the
// lexicon-required "cid" key (com.atproto.sync.getLatestCommit -> {cid, rev}).
func TestHandleSyncGetLatestCommitReturnsCid(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	c, err := pref.Sum([]byte("a fake commit block"))
	if err != nil {
		t.Fatalf("build cid: %v", err)
	}
	const rev = "3laaaaaaaaa2x"

	if err := s.db.Exec(context.Background(), "UPDATE repos SET root = ?, rev = ? WHERE did = ?", nil, c.Bytes(), rev, acct.Did).Error; err != nil {
		t.Fatalf("update repo: %v", err)
	}

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.getLatestCommit?did="+acct.Did, "", nil)

	if err := s.handleSyncGetLatestCommit(e); err != nil {
		t.Fatalf("handleSyncGetLatestCommit: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v; raw=%s", err, rec.Body.String())
	}
	if _, ok := body["cid"]; !ok {
		t.Fatalf("response missing \"cid\" key; body=%s", rec.Body.String())
	}
	if got := body["cid"]; got != c.String() {
		t.Fatalf("cid = %v, want %s", got, c.String())
	}
	if got := body["rev"]; got != rev {
		t.Fatalf("rev = %v, want %s", got, rev)
	}
	if _, ok := body["string"]; ok {
		t.Fatalf("response should not contain legacy \"string\" key; body=%s", rec.Body.String())
	}
}
