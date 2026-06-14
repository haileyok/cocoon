package server

import (
	"net/http"
	"testing"
)

// TestHandleGetBlocksReturnsCar requests a block by its string CID (as the
// lexicon specifies) and expects a CAR response, not a 400.
func TestHandleGetBlocksReturnsCar(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	root, _ := s.seedGenesisRepo(t, acct.Did, acct.SigningKey)

	target := "/xrpc/com.atproto.sync.getBlocks?did=" + acct.Did + "&cids=" + root.String()
	e, rec := newRequestContext(http.MethodGet, target, "", nil)
	if err := s.handleGetBlocks(e); err != nil {
		t.Fatalf("handleGetBlocks: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("content-type"); ct != "application/vnd.ipld.car" {
		t.Fatalf("content-type = %q, want application/vnd.ipld.car", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("empty CAR body")
	}
}
