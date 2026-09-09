package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
)

// These tests pin cocoon to the REFERENCE PDS behavior for PLC operations
// (packages/pds/src/api/com/atproto/identity/{submitPlcOperation,signPlcOperation}.ts
// and packages/pds/tests/plc-operations.test.ts in bluesky-social/atproto):
//
//   - submitPlcOperation rejects an op that REMOVES the server's rotation key
//     but ACCEPTS an op that ADDS a user-supplied key alongside it (the
//     supported migration-prep path; the reference test 'submits a valid
//     operation' pins exactly this).
//   - submitPlcOperation pins service type/endpoint, atproto verification
//     method, and aka[0] to the current account handle. An empty alsoKnownAs
//     is a 400 (the reference's .at(0) returns undefined), not a panic.
//   - signPlcOperation requires a valid emailed token, rejects tombstoned
//     DIDs ('Did is tombstoned'), signs user-supplied rotation keys with the
//     PDS rotation key, and deletes the token on success (single-use).
//   - PLC sendOperation must FAIL on a non-2xx PLC response (the did-plc lib
//     throws PlcClientError); a PLC rejection must not be reported as success.

// --- scaffolding -----------------------------------------------------------

// plcTestServer stands in for plc.directory: it records submitted ops,
// serves a configurable audit log, and returns a configurable status for
// op submissions.
type plcTestServer struct {
	srv    *httptest.Server
	status int
	log    identity.DidAuditLog
	ops    []plc.Operation
}

func newPlcTestServer(t *testing.T) *plcTestServer {
	t.Helper()
	p := &plcTestServer{status: http.StatusOK}
	mux := http.NewServeMux()
	// GetLastOp builds: {service}/{url-escaped did}/log/audit
	mux.HandleFunc("/log/audit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(p.log)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if len(path) > 10 && path[len(path)-10:] == "/log/audit" {
			w.Header().Set("content-type", "application/json")
			json.NewEncoder(w).Encode(p.log)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var op plc.Operation
		if err := json.NewDecoder(r.Body).Decode(&op); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		p.ops = append(p.ops, op)
		w.WriteHeader(p.status)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// attachPlcClient wires s.plcClient to the test PLC server with a generated
// PDS rotation key, mirroring production construction. It also wires the
// event manager and a cache-backed passport, since the submit/sign handlers
// bust the DID doc cache and emit identity events.
func (s *Server) attachPlcClient(t *testing.T, p *plcTestServer) *plc.Client {
	t.Helper()
	rk, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate rotation key: %v", err)
	}
	c, err := plc.NewClient(&plc.ClientArgs{
		H:           p.srv.Client(),
		Service:     p.srv.URL,
		PdsHostname: testHostname,
		RotationKey: rk.Bytes(),
	})
	if err != nil {
		t.Fatalf("new plc client: %v", err)
	}
	s.plcClient = c

	persister, err := NewDbPersister(s.db.Client(), time.Hour)
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}
	s.evtman = events.NewEventManager(persister)
	s.passport = identity.NewPassport(nil, identity.NewMemCache(10))
	return c
}

func (s *Server) setPlcOperationCode(t *testing.T, did, code string) {
	t.Helper()
	eat := time.Now().Add(10 * time.Minute).UTC()
	if err := s.db.Exec(context.Background(), "UPDATE repos SET plc_operation_code = ?, plc_operation_code_expires_at = ? WHERE did = ?", nil, code, eat, did).Error; err != nil {
		t.Fatalf("set plc_operation_code: %v", err)
	}
}

func mustRepoActor(t *testing.T, s *Server, did string) *models.RepoActor {
	t.Helper()
	repo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	return repo
}

// requiredCreds builds the credentials the submit handler derives itself.
func (s *Server) requiredCreds(t *testing.T, acct *testAccount) *plc.DidCredentials {
	t.Helper()
	k, err := atcrypto.ParsePrivateBytesK256(acct.SigningKey)
	if err != nil {
		t.Fatalf("parse signing key: %v", err)
	}
	required, err := s.plcClient.CreateDidCredentials(k, "", acct.Handle)
	if err != nil {
		t.Fatalf("create did credentials: %v", err)
	}
	return required
}

func callSubmitPlcOp(t *testing.T, s *Server, acct *testAccount, op plc.Operation) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"operation": op})
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.identity.submitPlcOperation", string(body), nil)
	c.Set("repo", mustRepoActor(t, s, acct.Did))
	if err := s.handleSubmitPlcOperation(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

// --- submit tests ----------------------------------------------------------

const sampleUserKey = "did:key:zQ3shtCGgFrAtUwdiHRYzKQqNUNiLNGoXjSaMfZxNhbRvbbRS"

// Reference parity: adding a user-supplied rotation key alongside the
// server's key is ACCEPTED ('submits a valid operation' in the reference suite).
func TestSubmitPlcOpAcceptsAddedRotationKey(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	required := s.requiredCreds(t, acct)

	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: required.VerificationMethods,
		RotationKeys:        append([]string{required.RotationKeys[0]}, sampleUserKey),
		AlsoKnownAs:         required.AlsoKnownAs,
		Services:            required.Services,
		Sig:                 "test-sig",
	}

	code, _ := callSubmitPlcOp(t, s, acct, op)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for rotation-key ADD (reference parity), got %d", code)
	}
	if len(p.ops) != 1 {
		t.Fatalf("expected exactly one PLC submission, got %d", len(p.ops))
	}
	if got := p.ops[0].RotationKeys; len(got) != 2 || got[1] != sampleUserKey {
		t.Fatalf("submitted rotation keys = %v, want [serverKey, %s]", got, sampleUserKey)
	}
}

// Reference parity: removing the server's rotation key is REJECTED
// ("Rotation keys do not include server's rotation key").
func TestSubmitPlcOpRejectsRemovedServerKey(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	required := s.requiredCreds(t, acct)

	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: required.VerificationMethods,
		RotationKeys:        []string{sampleUserKey},
		AlsoKnownAs:         required.AlsoKnownAs,
		Services:            required.Services,
		Sig:                 "test-sig",
	}

	code, _ := callSubmitPlcOp(t, s, acct, op)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for rotation-key REMOVAL, got %d", code)
	}
	if len(p.ops) != 0 {
		t.Fatalf("op must not reach PLC on rejection, got %d submissions", len(p.ops))
	}
}

// A PLC-side rejection (non-2xx) must not be reported as success — pins the
// did-plc lib's PlcClientError behavior that cocoon's client was missing.
func TestSubmitPlcOpRejectsPlcError(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	p.status = http.StatusUnauthorized // PLC rejects the op
	s.attachPlcClient(t, p)
	required := s.requiredCreds(t, acct)

	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: required.VerificationMethods,
		RotationKeys:        required.RotationKeys,
		AlsoKnownAs:         required.AlsoKnownAs,
		Services:            required.Services,
		Sig:                 "test-sig",
	}

	code, body := callSubmitPlcOp(t, s, acct, op)
	if code == http.StatusOK {
		t.Fatal("PLC rejection (401) must not be reported as success")
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on PLC rejection, got %d (%s)", code, body)
	}
	if len(p.ops) != 1 {
		t.Fatalf("op should have been attempted at PLC exactly once, got %d", len(p.ops))
	}
}

// Empty alsoKnownAs must be a 400 (reference .at(0) semantics), not a panic.
func TestSubmitPlcOpEmptyAkaDoesNotPanic(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	required := s.requiredCreds(t, acct)

	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: required.VerificationMethods,
		RotationKeys:        required.RotationKeys,
		AlsoKnownAs:         []string{},
		Services:            required.Services,
		Sig:                 "test-sig",
	}

	code, _ := callSubmitPlcOp(t, s, acct, op)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty alsoKnownAs, got %d", code)
	}
}

// --- sign tests ------------------------------------------------------------

func auditEntry(acct *testAccount, opType string) identity.DidAuditEntry {
	return identity.DidAuditEntry{
		Did: acct.Did,
		Operation: identity.DidLogEntry{
			Type: opType,
			VerificationMethods: map[string]string{
				"atproto": "did:key:zQ3shtCGgexistingAtprotoKey",
			},
			RotationKeys: []string{"did:key:zQ3shtCGgexistingRotation"},
			AlsoKnownAs:  []string{"at://" + acct.Handle},
			Services: map[string]identity.OperationService{
				"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: "https://" + testHostname},
			},
			Prev: nil,
			Sig:  "sig",
		},
		Cid:       "bafytestcid",
		CreatedAt: time.Now().Format(time.RFC3339),
	}
}

func callSignPlcOp(t *testing.T, s *Server, acct *testAccount, body string) (int, string) {
	t.Helper()
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.identity.signPlcOperation", body, nil)
	c.Set("repo", mustRepoActor(t, s, acct.Did))
	if err := s.handleSignPlcOperation(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

// Reference parity: a tombstoned DID is refused ('Did is tombstoned').
func TestSignPlcOpRejectsTombstone(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	s.setPlcOperationCode(t, acct.Did, "ABCDE-FGHIJ")
	p.log = identity.DidAuditLog{auditEntry(acct, "plc_tombstone")}

	body, _ := json.Marshal(map[string]any{
		"token":        "ABCDE-FGHIJ",
		"rotationKeys": []string{sampleUserKey},
	})
	code, _ := callSignPlcOp(t, s, acct, string(body))
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tombstoned DID, got %d", code)
	}
}

// Reference parity: valid token -> PDS-signed op carrying the user-supplied
// rotation keys, token consumed (single-use).
func TestSignPlcOpValidTokenSignsUserRotationKeys(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	s.setPlcOperationCode(t, acct.Did, "ABCDE-FGHIJ")
	p.log = identity.DidAuditLog{auditEntry(acct, "plc_operation")}

	body, _ := json.Marshal(map[string]any{
		"token":        "ABCDE-FGHIJ",
		"rotationKeys": []string{sampleUserKey, "did:key:zQ3shtCGgexistingRotation"},
	})
	code, respBody := callSignPlcOp(t, s, acct, string(body))
	if code != http.StatusOK {
		t.Fatalf("expected 200 for valid-token sign, got %d: %s", code, respBody)
	}

	var resp struct {
		Operation plc.Operation `json:"operation"`
	}
	if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{sampleUserKey, "did:key:zQ3shtCGgexistingRotation"}
	if len(resp.Operation.RotationKeys) != 2 || resp.Operation.RotationKeys[0] != want[0] || resp.Operation.RotationKeys[1] != want[1] {
		t.Fatalf("rotation keys = %v, want %v", resp.Operation.RotationKeys, want)
	}
	if resp.Operation.Sig == "" {
		t.Fatal("returned op must be signed by the PDS rotation key")
	}

	repo, _ := s.getRepoActorByDid(context.Background(), acct.Did)
	if repo.PlcOperationCode != nil {
		t.Fatal("plc_operation_code must be cleared after successful sign (single-use)")
	}
}

// Bad token: no signed op ('Token is invalid' in the reference).
func TestSignPlcOpBadTokenRejected(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	s.setPlcOperationCode(t, acct.Did, "ABCDE-FGHIJ")
	p.log = identity.DidAuditLog{auditEntry(acct, "plc_operation")}

	body, _ := json.Marshal(map[string]any{
		"token":        "123456",
		"rotationKeys": []string{sampleUserKey},
	})
	code, _ := callSignPlcOp(t, s, acct, string(body))
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad token, got %d", code)
	}
}

// Empty audit log must not panic (guard on log[len-1]).
func TestSignPlcOpEmptyLogDoesNotPanic(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	p := newPlcTestServer(t)
	s.attachPlcClient(t, p)
	s.setPlcOperationCode(t, acct.Did, "ABCDE-FGHIJ")
	p.log = identity.DidAuditLog{} // empty

	body, _ := json.Marshal(map[string]any{
		"token":        "ABCDE-FGHIJ",
		"rotationKeys": []string{sampleUserKey},
	})
	code, _ := callSignPlcOp(t, s, acct, string(body))
	if code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for empty audit log, got %d", code)
	}
}
