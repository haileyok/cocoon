package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// plcClientOwnsRotationKey reports whether a did:key equals the PDS rotation
// key this test server's plc client was constructed with.
func (s *Server) plcClientOwnsRotationKey(t *testing.T, didKey string) bool {
	t.Helper()
	// CreateDidCredentials returns the client's own rotation key as the only
	// entry when no recovery key is supplied.
	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	creds, err := s.plcClient.CreateDidCredentials(k, "", "check.pds.test")
	if err != nil {
		t.Fatalf("create did credentials: %v", err)
	}
	return len(creds.RotationKeys) > 0 && creds.RotationKeys[0] == didKey
}

// createAccountWithRecoveryKey drives the createAccount handler and returns
// the recorder and parsed response.
func createAccountWithRecoveryKey(t *testing.T, s *Server, body map[string]any) (*testAccount, int, string) {
	t.Helper()

	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createAccount", string(b), nil)
	if err := s.handleCreateAccount(c); err != nil {
		t.Fatalf("handleCreateAccount: %v", err)
	}
	if rec.Code != http.StatusOK {
		return nil, rec.Code, rec.Body.String()
	}
	var resp ComAtprotoServerCreateAccountResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	acct := &testAccount{Did: resp.Did, Handle: resp.Handle, Password: "correct-horse-battery-staple"}
	return acct, rec.Code, rec.Body.String()
}

// The optional recoveryKey is a did:key that lands FIRST in the genesis
// operation's rotationKeys, before the PDS's own rotation key, so the key
// holder outranks the PDS for identity recovery.
func TestCreateAccountRecoveryKey(t *testing.T) {
	recovery, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	recoveryPub, err := recovery.PublicKey()
	if err != nil {
		t.Fatalf("derive recovery public key: %v", err)
	}
	recoveryDidKey := recoveryPub.DIDKey()

	t.Run("recovery key first in genesis rotationKeys", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		_, code, body := createAccountWithRecoveryKey(t, s, map[string]any{
			"handle":      "alice.pds.test",
			"email":       "alice@test.invalid",
			"password":    "correct-horse-battery-staple",
			"recoveryKey": recoveryDidKey,
		})
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", code, body)
		}
		if len(p.ops) != 1 {
			t.Fatalf("expected one genesis PLC op, got %d", len(p.ops))
		}
		keys := p.ops[0].RotationKeys
		if len(keys) != 2 {
			t.Fatalf("expected 2 rotation keys (recovery + pds), got %d: %v", len(keys), keys)
		}
		if keys[0] != recoveryDidKey {
			t.Errorf("recovery key must be FIRST in rotationKeys, got %q (want %q) in %v", keys[0], recoveryDidKey, keys)
		}
		if !s.plcClientOwnsRotationKey(t, keys[1]) {
			t.Errorf("second rotation key %q is not the PDS's own key", keys[1])
		}
	})

	t.Run("no recovery key keeps pds key alone", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		_, code, body := createAccountWithRecoveryKey(t, s, map[string]any{
			"handle":   "bob.pds.test",
			"email":    "bob@test.invalid",
			"password": "correct-horse-battery-staple",
		})
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", code, body)
		}
		keys := p.ops[0].RotationKeys
		if len(keys) != 1 || !s.plcClientOwnsRotationKey(t, keys[0]) {
			t.Fatalf("expected only the PDS rotation key, got %v", keys)
		}
	})

	t.Run("invalid recovery key is rejected", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		for _, bad := range []string{"not-a-did-key", "did:key:zzzz", "did:web:example.com", "did:key:zQ3shtCGgFrAtUwdiHRYzKQqNUNiLNGoXjSaMfZxNhbRvbbRX-trailing"} {
			_, code, body := createAccountWithRecoveryKey(t, s, map[string]any{
				"handle":      "carol.pds.test",
				"email":       "carol@test.invalid",
				"password":    "correct-horse-battery-staple",
				"recoveryKey": bad,
			})
			if code != http.StatusBadRequest {
				t.Errorf("recoveryKey %q: expected 400, got %d: %s", bad, code, body)
			}
			if len(p.ops) != 0 {
				t.Fatalf("invalid recoveryKey must not submit a PLC op, got %d", len(p.ops))
			}
		}
	})
}
