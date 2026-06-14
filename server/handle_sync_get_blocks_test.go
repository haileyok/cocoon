package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestHandleGetBlocksBadCid returns 400 InvalidRequest when a requested cid is
// not a parseable CID, rather than a 500.
func TestHandleGetBlocksBadCid(t *testing.T) {
	s := newTestServer(t)

	e, rec := newRequestContext(http.MethodGet, "/xrpc/com.atproto.sync.getBlocks?did=did:web:pds.test&cids=undefined", "", nil)
	if err := s.handleGetBlocks(e); err != nil {
		t.Fatalf("handleGetBlocks: %v", err)
	}
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v; raw=%s", err, rec.Body.String())
	}
	if body["error"] != "InvalidRequest" {
		t.Fatalf("error = %q, want InvalidRequest; body=%s", body["error"], rec.Body.String())
	}
}
