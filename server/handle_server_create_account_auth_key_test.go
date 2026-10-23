package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
)

// httptestRecorder aliases the recorder so the helper reads like the rest of
// the suite.
type httptestRecorder = httptest.ResponseRecorder

// createAccountJson drives the createAccount handler with a JSON body and
// returns the recorder and parsed response.
func createAccountJson(t *testing.T, s *Server, body map[string]any) (*httptestRecorder, ComAtprotoServerCreateAccountResponse) {
	t.Helper()

	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createAccount", string(b), nil)
	if err := s.handleCreateAccount(c); err != nil {
		c.Error(err)
	}
	var resp ComAtprotoServerCreateAccountResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
}

// authKeysFor returns the account's stored sign-in key rows.
func authKeysFor(t *testing.T, s *Server, did string) []models.AuthKey {
	t.Helper()
	var keys []models.AuthKey
	if err := s.db.Raw(context.Background(), "SELECT * FROM auth_keys WHERE did = ?", nil, did).Scan(&keys).Error; err != nil {
		t.Fatalf("query auth keys: %v", err)
	}
	return keys
}

// createSessionAttempt drives com.atproto.server.createSession and returns the
// status code.
func createSessionAttempt(t *testing.T, s *Server, identifier, password string) int {
	t.Helper()
	body := map[string]any{"identifier": identifier, "password": password}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createSession", string(b), nil)
	if err := s.handleCreateSession(c); err != nil {
		c.Error(err)
	}
	return rec.Code
}

// The optional authKey is a did:key (K-256 or P-256) that becomes the
// account's sign-in key. With it set, the password is optional: the account
// signs in through the jwt-bearer OAuth grant instead, and no legacy session
// is minted.
func TestCreateAccountAuthKey(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate sign-in key: %v", err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("derive public sign-in key: %v", err)
	}
	authKey := pub.DIDKey()

	recovery, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	recoveryPub, err := recovery.PublicKey()
	if err != nil {
		t.Fatalf("derive recovery public key: %v", err)
	}
	recoveryDidKey := recoveryPub.DIDKey()

	t.Run("auth key with no password", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		rec, resp := createAccountJson(t, s, map[string]any{
			"handle":      "alice.pds.test",
			"email":       "alice@test.invalid",
			"authKey":     authKey,
			"recoveryKey": recoveryDidKey,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		// No legacy session: empty jwts.
		if resp.AccessJwt != "" || resp.RefreshJwt != "" {
			t.Errorf("expected empty jwts for an auth-key account, got access %d / refresh %d chars", len(resp.AccessJwt), len(resp.RefreshJwt))
		}
		if resp.Did == "" {
			t.Fatal("expected a did in the response")
		}

		// The key is stored as an active sign-in key.
		keys := authKeysFor(t, s, resp.Did)
		if len(keys) != 1 {
			t.Fatalf("expected 1 stored auth key, got %d", len(keys))
		}
		if keys[0].DidKey != authKey {
			t.Errorf("stored key %q does not match authKey %q", keys[0].DidKey, authKey)
		}
		if keys[0].RevokedAt != nil {
			t.Errorf("stored key must be active, revoked_at set")
		}

		// The recovery key is still FIRST in the genesis op's rotationKeys.
		if len(p.ops) != 1 {
			t.Fatalf("expected one genesis PLC op, got %d", len(p.ops))
		}
		rk := p.ops[0].RotationKeys
		if len(rk) != 2 || rk[0] != recoveryDidKey {
			t.Fatalf("expected recovery key first in rotationKeys, got %v", rk)
		}

		// No usable password hash: password sign-in is refused.
		var repo models.Repo
		if err := s.db.Raw(context.Background(), "SELECT * FROM repos WHERE did = ?", nil, resp.Did).Scan(&repo).Error; err != nil {
			t.Fatalf("query repo: %v", err)
		}
		if repo.Password != "" {
			t.Errorf("expected no stored password hash, got %d chars", len(repo.Password))
		}
		if code := createSessionAttempt(t, s, "alice.pds.test", ""); code == http.StatusOK {
			t.Error("createSession must fail for an account with no password")
		}
		if code := createSessionAttempt(t, s, "alice.pds.test", "some-guess"); code == http.StatusOK {
			t.Error("createSession must fail for an account with no password")
		}

		// No legacy session rows either.
		var n int64
		if err := s.db.Raw(context.Background(), "SELECT COUNT(*) FROM tokens", nil).Scan(&n).Error; err != nil || n != 0 {
			t.Errorf("expected no legacy token rows, got %d (err %v)", n, err)
		}
	})

	t.Run("invalid auth key rejected before plc op", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		for _, bad := range []string{"not-a-did-key", "did:key:zzzz", "did:web:example.com", "did:key:zQ3shtCGgFrAtUwdiHRYzKQqNUNiLNGoXjSaMfZxNhbRvbbRX-trailing"} {
			rec, _ := createAccountJson(t, s, map[string]any{
				"handle":  "bob.pds.test",
				"email":   "bob@test.invalid",
				"authKey": bad,
			})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("authKey %q: expected 400, got %d: %s", bad, rec.Code, rec.Body.String())
			}
			if len(p.ops) != 0 {
				t.Fatalf("invalid authKey must not submit a PLC op, got %d", len(p.ops))
			}
		}
	})

	t.Run("p256 auth key accepted", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		pkey, err := atcrypto.GeneratePrivateKeyP256()
		if err != nil {
			t.Fatalf("generate p256 key: %v", err)
		}
		ppub, err := pkey.PublicKey()
		if err != nil {
			t.Fatalf("derive p256 public key: %v", err)
		}

		rec, resp := createAccountJson(t, s, map[string]any{
			"handle":   "carol.pds.test",
			"email":    "carol@test.invalid",
			"password": "correct-horse-battery-staple",
			"authKey":  ppub.DIDKey(),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		// Both a password and a sign-in key: the response keeps the legacy
		// session (password given), and the key is stored.
		if resp.AccessJwt == "" {
			t.Error("expected a legacy session when a password is supplied")
		}
		if keys := authKeysFor(t, s, resp.Did); len(keys) != 1 {
			t.Fatalf("expected 1 stored auth key, got %d", len(keys))
		}
	})

	t.Run("password still required without auth key", func(t *testing.T) {
		s := newTestServer(t)
		p := newPlcTestServer(t)
		s.attachPlcClient(t, p)

		rec, _ := createAccountJson(t, s, map[string]any{
			"handle": "dave.pds.test",
			"email":  "dave@test.invalid",
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 without password or authKey, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
