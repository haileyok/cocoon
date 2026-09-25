package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
	"github.com/ipfs/go-cid"
)

func checkAccountStatus(t *testing.T, s *Server, account *testAccount) ComAtprotoServerCheckAccountStatusResponse {
	t.Helper()
	repo, err := s.getRepoActorByDid(context.Background(), account.Did)
	if err != nil {
		t.Fatal(err)
	}
	c, w := newRequestContext("GET", "/xrpc/com.atproto.server.checkAccountStatus", "", nil)
	c.Set("repo", repo)
	if err := s.handleServerCheckAccountStatus(c); err != nil || w.Code != 200 {
		t.Fatalf("checkAccountStatus: %d %s %v", w.Code, w.Body.String(), err)
	}
	var status ComAtprotoServerCheckAccountStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestCheckAccountStatusActivated(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "status.pds.test")
	attachStatusDID(t, s, account, account.Did, "valid")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	for _, deactivated := range []bool{false, true, false} {
		if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Update("deactivated", deactivated).Error; err != nil {
			t.Fatal(err)
		}
		if status := checkAccountStatus(t, s, account); status.Activated == deactivated {
			t.Fatalf("activated = %t when deactivated = %t", status.Activated, deactivated)
		}
	}
}

func TestCheckAccountStatusBlobCounts(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "blob-status.pds.test")
	attachStatusDID(t, s, account, account.Did, "valid")
	other := s.createTestAccount(t, "other-status.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	assertCounts := func(expected, imported, records int64) {
		t.Helper()
		status := checkAccountStatus(t, s, account)
		if status.ExpectedBlobs != expected || status.ImportedBlobs != imported || status.IndexedRecords != records {
			t.Fatalf("got expected=%d imported=%d records=%d; want %d/%d/%d", status.ExpectedBlobs, status.ImportedBlobs, status.IndexedRecords, expected, imported, records)
		}
	}
	assertCounts(0, 0, 0)
	uploadTestBlob(t, s, account, "unreferenced")
	uploadTestBlob(t, s, other, "second")
	_, foreign := blobRecord(t, "foreign-only")
	otherRoot, otherBlocks, _ := importFixture(t, other.Did, []string{"app.bsky.feed.post/foreign"}, foreign)
	if code, msg := callImportRepo(t, s, other, bytes.NewReader(importCAR(t, []cid.Cid{otherRoot}, otherBlocks))); code != 200 {
		t.Fatalf("other account import: %d %s", code, msg)
	}
	_, first := blobRecord(t, "first")
	_, second := blobRecord(t, "second")
	assertCounts(0, 1, 0)
	root, all, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/one", "app.bsky.feed.post/two", "app.bsky.feed.post/three"}, first, first, second)
	if code, msg := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, all))); code != 200 {
		t.Fatalf("import: %d %s", code, msg)
	}
	assertCounts(2, 1, 3)
	uploadTestBlob(t, s, account, "first")
	uploadTestBlob(t, s, account, "first")
	for _, incomplete := range []models.Blob{{Did: account.Did}, {Did: account.Did, Cid: []byte{}}} {
		if err := s.db.Client().Create(&incomplete).Error; err != nil {
			t.Fatal(err)
		}
	}
	assertCounts(2, 2, 3)
	uploadTestBlob(t, s, account, "second")
	assertCounts(2, 3, 3)
}

func attachStatusDID(t *testing.T, s *Server, account *testAccount, did, scenario string) {
	t.Helper()
	rk, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := atcrypto.ParsePrivateBytesK256(account.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := sk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	data := identity.DidData{
		Did:                 did,
		VerificationMethods: map[string]string{"atproto": signing.DIDKey()},
		RotationKeys:        []string{"did:key:extra-recovery-key", pub.DIDKey()},
		Services:            map[string]identity.OperationService{"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.test"}},
	}
	switch scenario {
	case "endpoint":
		data.Services["atproto_pds"] = identity.OperationService{Type: "AtprotoPersonalDataServer", Endpoint: "https://old-pds.test"}
	case "type":
		data.Services["atproto_pds"] = identity.OperationService{Type: "OtherService", Endpoint: "https://pds.test"}
	case "signing":
		data.VerificationMethods["atproto"] = pub.DIDKey()
	case "rotation":
		data.RotationKeys = data.RotationKeys[:1]
	case "missing":
		data.Services = nil
		data.VerificationMethods = nil
	case "wrong-did":
		data.Did = "did:web:other.test"
	}
	prefix := ""
	if scenario == "full-ids" {
		prefix = did
	}
	doc := identity.DidDoc{Id: data.Did,
		Service:             []identity.DidDocService{{Id: prefix + "#atproto_pds", Type: data.Services["atproto_pds"].Type, ServiceEndpoint: data.Services["atproto_pds"].Endpoint}},
		VerificationMethods: []identity.DidDocVerificationMethod{{Id: prefix + "#atproto", PublicKeyMultibase: strings.TrimPrefix(data.VerificationMethods["atproto"], "did:key:")}},
	}
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scenario == "unavailable" {
			w.WriteHeader(503)
			return
		}
		if scenario == "malformed" {
			_, _ = w.Write([]byte("{"))
			return
		}
		if strings.HasPrefix(did, "did:plc:") {
			if r.URL.Path != "/"+did+"/data" {
				t.Errorf("unexpected PLC path: %s", r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(data)
		} else {
			_ = json.NewEncoder(w).Encode(doc)
		}
	}))
	t.Cleanup(remote.Close)
	s.plcClient, err = plc.NewClient(&plc.ClientArgs{H: remote.Client(), Service: remote.URL, PdsHostname: testHostname, RotationKey: rk.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	transport := remote.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, remote.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	cache := identity.NewMemCache(10)
	_ = cache.PutDoc(did, &identity.DidDoc{Id: "stale"})
	s.passport = identity.NewPassport(&http.Client{Transport: transport}, cache)
}

func TestCheckAccountStatusValidDID(t *testing.T) {
	for _, method := range []string{"plc", "web"} {
		for _, scenario := range []string{"valid", "full-ids", "endpoint", "type", "signing", "rotation", "missing", "wrong-did", "unavailable", "malformed"} {
			t.Run(method+"/"+scenario, func(t *testing.T) {
				s := newTestServer(t)
				account := s.createTestAccount(t, "did-status.pds.test")
				s.seedGenesisRepo(t, account.Did, account.SigningKey)
				repo := mustRepoActor(t, s, account.Did)
				if method == "web" {
					repo.Repo.Did = "did:web:identity.test"
				}
				attachStatusDID(t, s, account, repo.Repo.Did, scenario)
				c, w := newRequestContext("GET", "/xrpc/com.atproto.server.checkAccountStatus", "", nil)
				c.Set("repo", repo)
				if err := s.handleServerCheckAccountStatus(c); err != nil || w.Code != 200 {
					t.Fatalf("status: %d %s %v", w.Code, w.Body.String(), err)
				}
				var status ComAtprotoServerCheckAccountStatusResponse
				if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
					t.Fatal(err)
				}
				want := scenario == "valid" || scenario == "full-ids" || (method == "web" && scenario == "rotation")
				if status.ValidDid != want {
					t.Fatalf("validDid = %t, want %t", status.ValidDid, want)
				}
			})
		}
	}
}
