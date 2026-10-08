package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Space requests go to endpoints DID documents name, so by default they must
// not reach loopback or private addresses.
func TestSpaceClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	s := newTestServer(t)
	resp, err := s.spaceClient().Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("space client reached a loopback address")
	}
}
