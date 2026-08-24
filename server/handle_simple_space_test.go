package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
	oauthclient "github.com/haileyok/cocoon/oauth/client"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/haileyok/cocoon/space"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	testSimpleSpaceType = "com.example.forum"
	testSimpleSpaceKey  = "main"
)

func simpleSpaceManagementScopes() []string {
	return []string{"space:" + testSimpleSpaceType + "?authority=self&manage=create&manage=update&manage=delete"}
}

func simpleSpaceReadScope() []string {
	return []string{"space:" + testSimpleSpaceType + "?authority=*&skey=" + testSimpleSpaceKey + "&action=read"}
}

func decodeSimpleSpaceBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	return body
}

func TestSimpleSpaceLifecyclePoliciesAndDeletionRetention(t *testing.T) {
	s := newTestServer(t)
	owner := s.createTestAccount(t, "space-owner.pds.test")
	member := s.createTestAccount(t, "space-member.pds.test")
	ownerPrincipal := &OAuthPrincipal{Subject: owner.Did, Scopes: simpleSpaceManagementScopes()}

	createBody := `{"type":"` + testSimpleSpaceType + `","skey":"` + testSimpleSpaceKey + `","policy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.createSpace", createBody, nil)
	SetPrincipal(e, ownerPrincipal)
	if err := s.handleSimpleSpaceCreateSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d; body=%s", rec.Code, rec.Body.String())
	}
	spaceURI := "at://" + owner.Did + "/space/" + testSimpleSpaceType + "/" + testSimpleSpaceKey

	updateBody := `{"space":"` + spaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"}}`
	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.updateSpace", updateBody, nil)
	SetPrincipal(e, ownerPrincipal)
	if err := s.handleSimpleSpaceUpdateSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d; body=%s", rec.Code, rec.Body.String())
	}

	addBody := `{"space":"` + spaceURI + `","did":"` + member.Did + `"}`
	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.addMember", addBody, nil)
	SetPrincipal(e, ownerPrincipal)
	if err := s.handleSimpleSpaceAddMember(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("add member status = %d; body=%s", rec.Code, rec.Body.String())
	}

	memberPrincipal := &OAuthPrincipal{Subject: member.Did}
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.simplespace.getSpace?space="+spaceURI, "", nil)
	SetPrincipal(e, memberPrincipal)
	if err := s.handleSimpleSpaceGetSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member get status = %d; want 403; body=%s", rec.Code, rec.Body.String())
	}

	readPrincipal := &OAuthPrincipal{Subject: member.Did, Scopes: simpleSpaceReadScope()}
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.simplespace.listMembers?space="+spaceURI+"&limit=1", "", nil)
	SetPrincipal(e, readPrincipal)
	if err := s.handleSimpleSpaceListMembers(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member list members status = %d; want 403; body=%s", rec.Code, rec.Body.String())
	}

	ownerReadPrincipal := &OAuthPrincipal{
		Subject: owner.Did,
		Scopes:  append(simpleSpaceManagementScopes(), "space:"+testSimpleSpaceType+"?authority=self&skey="+testSimpleSpaceKey+"&action=read_self"),
	}
	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.simplespace.getSpace?space="+spaceURI, "", nil)
	SetPrincipal(e, ownerReadPrincipal)
	if err := s.handleSimpleSpaceGetSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("owner get status = %d; body=%s", rec.Code, rec.Body.String())
	}

	e, rec = newRequestContext(http.MethodGet, "/xrpc/com.atproto.simplespace.listMembers?space="+spaceURI+"&limit=1", "", nil)
	SetPrincipal(e, ownerReadPrincipal)
	if err := s.handleSimpleSpaceListMembers(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("owner list members status = %d; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSimpleSpaceBody(t, rec)
	members, ok := body["members"].([]any)
	if !ok || len(members) != 1 || members[0].(map[string]any)["did"] != member.Did {
		t.Fatalf("members = %#v", body["members"])
	}

	initial, err := space.NewLtHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(context.Background(), &models.SpaceRepo{Space: spaceURI, Author: owner.Did, LtHash: initial.State()}, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(context.Background(), &models.SpaceRepo{Space: spaceURI, Author: member.Did, LtHash: initial.State()}, nil).Error; err != nil {
		t.Fatal(err)
	}

	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.deleteSpace", `{"space":"`+spaceURI+`"}`, nil)
	SetPrincipal(e, ownerPrincipal)
	if err := s.handleSimpleSpaceDeleteSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var tombstone models.SpaceTombstone
	if err := s.db.First(context.Background(), &tombstone, "space = ?", spaceURI).Error; err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	var ownRepo models.SpaceRepo
	if err := s.db.First(context.Background(), &ownRepo, "space = ? AND author = ?", spaceURI, owner.Did).Error; err == nil {
		t.Fatal("authority repo should be deleted")
	}
	var memberRepo models.SpaceRepo
	if err := s.db.First(context.Background(), &memberRepo, "space = ? AND author = ?", spaceURI, member.Did).Error; err != nil {
		t.Fatalf("member repo should be retained: %v", err)
	}
	if memberRepo.Deleted || memberRepo.DeletedAt != nil {
		t.Fatalf("remote member repo must be retained unchanged: %#v", memberRepo)
	}

	// The tombstoned URI cannot be recreated.
	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.createSpace", createBody, nil)
	SetPrincipal(e, ownerPrincipal)
	if err := s.handleSimpleSpaceCreateSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "SpaceAlreadyExists") {
		t.Fatalf("recreate tombstoned space = %d %s", rec.Code, rec.Body.String())
	}

	// Repeating delete is idempotent for the owner.
	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.deleteSpace", `{"space":"`+spaceURI+`"}`, nil)
	SetPrincipal(e, ownerPrincipal)
	if err := s.handleSimpleSpaceDeleteSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("repeat delete status = %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSimpleSpaceRejectsUnknownUnionsAndWrongPrincipal(t *testing.T) {
	s := newTestServer(t)
	owner := s.createTestAccount(t, "union-owner.pds.test")
	p := &OAuthPrincipal{Subject: owner.Did, Scopes: simpleSpaceManagementScopes()}
	body := `{"type":"` + testSimpleSpaceType + `","skey":"union","policy":{"$type":"com.example.unknownPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.createSpace", body, nil)
	SetPrincipal(e, p)
	if err := s.handleSimpleSpaceCreateSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "UnsupportedPolicy") {
		t.Fatalf("unknown policy response = %d %s", rec.Code, rec.Body.String())
	}

	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.simplespace.createSpace", body, nil)
	SetPrincipal(e, &SpaceCredentialPrincipal{})
	if err := s.handleSimpleSpaceCreateSpace(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("credential management status = %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSimpleSpaceCredentialExchangeUsesDelegationAndAuthorityKey(t *testing.T) {
	s := newTestServer(t)
	owner := s.createTestAccount(t, "credential-owner.pds.test")
	spaceURI := "at://" + owner.Did + "/space/" + testSimpleSpaceType + "/credential"
	if err := s.db.Create(context.Background(), &models.SimpleSpace{
		URI: spaceURI, OwnerDID: owner.Did, Type: testSimpleSpaceType, SKey: "credential",
		Policy: simpleSpacePolicyMemberList, AppAccess: simpleSpaceAppAccessOpen,
	}, nil).Error; err != nil {
		t.Fatal(err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	ref, err := space.ParseSpaceURI(spaceURI)
	if err != nil {
		t.Fatal(err)
	}
	audience := string(ref.AuthorityDID) + space.SpaceHostAudienceSuffix
	principal := &DelegationPrincipal{
		SpaceURI: spaceURI, AuthorityDID: owner.Did, DPoPJKT: jkt,
		DPoPJTI: "credential-exchange-dpop", DPoPIssuedAt: time.Now(),
		Claims: space.SpaceTokenClaims{Iss: owner.Did, Sub: spaceURI, Aud: &audience, JTI: "credential-exchange-delegation", Exp: time.Now().Add(time.Minute).Unix()},
	}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.getSpaceCredential", `{"space":"`+spaceURI+`"}`, nil)
	SetPrincipal(e, principal)
	if err := s.handleSimpleSpaceGetSpaceCredential(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("credential status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var output ComAtprotoSpaceGetSpaceCredentialOutput
	if err := json.Unmarshal(rec.Body.Bytes(), &output); err != nil || output.Credential == "" {
		t.Fatalf("credential output = %s; err=%v", rec.Body.String(), err)
	}
	key, err := atcrypto.ParsePrivateBytesK256(owner.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := space.NewAtprotoVerifier(public)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := space.VerifyCredential(context.Background(), output.Credential, space.VerifySpaceTokenOptions{Verifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Claims.Sub != spaceURI || verified.Claims.Iss != owner.Did || verified.Claims.Cnf == nil || verified.Claims.Cnf.JKT != jkt {
		t.Fatalf("credential claims = %#v", verified.Claims)
	}

	// A deleted authority is discovered by the exchange itself, even without
	// going through the route middleware's availability check.
	deletedAt := time.Now().UTC()
	if err := s.db.Save(context.Background(), &models.SimpleSpace{URI: spaceURI, OwnerDID: owner.Did, Type: testSimpleSpaceType, SKey: "credential", Policy: simpleSpacePolicyMemberList, AppAccess: simpleSpaceAppAccessOpen, Deleted: true, DeletedAt: &deletedAt}, nil).Error; err != nil {
		t.Fatal(err)
	}
	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.getSpaceCredential", `{"space":"`+spaceURI+`"}`, nil)
	SetPrincipal(e, principal)
	if err := s.handleSimpleSpaceGetSpaceCredential(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "SpaceDeleted") {
		t.Fatalf("deleted credential response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestSimpleSpaceCredentialRejectsInactiveDelegationIssuerWithoutReplayConsume(t *testing.T) {
	statuses := []struct {
		name string
		set  func(*models.Repo)
		want string
	}{
		{"deactivated", func(r *models.Repo) { r.Deactivated = true }, "RepoDeactivated"},
		{"suspended", func(r *models.Repo) { r.Suspended = true }, "RepoSuspended"},
		{"takendown", func(r *models.Repo) { r.Takendown = true }, "RepoTakendown"},
	}
	for _, test := range statuses {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t)
			owner := s.createTestAccount(t, "inactive-"+test.name+".pds.test")
			var repo models.Repo
			if err := s.db.First(context.Background(), &repo, "did = ?", owner.Did).Error; err != nil {
				t.Fatal(err)
			}
			test.set(&repo)
			if err := s.db.Save(context.Background(), &repo, nil).Error; err != nil {
				t.Fatal(err)
			}
			spaceURI := "at://" + owner.Did + "/space/" + testSimpleSpaceType + "/inactive"
			if err := s.db.Create(context.Background(), &models.SimpleSpace{URI: spaceURI, OwnerDID: owner.Did, Type: testSimpleSpaceType, SKey: "inactive", Policy: simpleSpacePolicyPublic, AppAccess: simpleSpaceAppAccessOpen}, nil).Error; err != nil {
				t.Fatal(err)
			}
			ref, err := space.ParseSpaceURI(spaceURI)
			if err != nil {
				t.Fatal(err)
			}
			audience := string(ref.AuthorityDID) + space.SpaceHostAudienceSuffix
			principal := &DelegationPrincipal{SpaceURI: spaceURI, AuthorityDID: owner.Did, DPoPJKT: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), DPoPJTI: "inactive-dpop-" + test.name, DPoPIssuedAt: time.Now(), Claims: space.SpaceTokenClaims{Iss: owner.Did, Sub: spaceURI, Aud: &audience, JTI: "inactive-delegation-" + test.name, Exp: time.Now().Add(time.Minute).Unix()}}
			e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.getSpaceCredential", `{"space":"`+spaceURI+`"}`, nil)
			SetPrincipal(e, principal)
			if err := s.handleSimpleSpaceGetSpaceCredential(e); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), test.want) {
				t.Fatalf("inactive issuer response = %d %s", rec.Code, rec.Body.String())
			}
			if err := s.spaceReplayStore().Consume(context.Background(), principal.Claims.JTI, string(space.TokenDelegation), time.Now().Add(time.Minute)); err != nil {
				t.Fatalf("inactive issuer burned delegation replay: %v", err)
			}
		})
	}
}

type nonBatchReplayStore struct{ consumes int }

func (s *nonBatchReplayStore) Consume(context.Context, string, string, time.Time) error {
	s.consumes++
	return nil
}

func TestSimpleSpaceCredentialFailsClosedWithoutAtomicReplayStore(t *testing.T) {
	s := newTestServer(t)
	store := &nonBatchReplayStore{}
	s.SetSpaceReplayStore(store)
	principal := &DelegationPrincipal{
		DPoPJTI: "nonbatch-dpop", DPoPIssuedAt: time.Now(),
		Claims: space.SpaceTokenClaims{JTI: "nonbatch-delegation", Exp: time.Now().Add(time.Minute).Unix()},
	}
	if err := s.consumeSimpleSpaceExchange(context.Background(), principal, nil); !errors.Is(err, space.ErrBatchReplayUnavailable) {
		t.Fatalf("non-batch replay store error = %v, want ErrBatchReplayUnavailable", err)
	}
	if store.consumes != 0 {
		t.Fatalf("non-batch replay store was used sequentially %d times", store.consumes)
	}
}

func TestSimpleSpaceCredentialExchangeConcurrentIdenticalBatchesOneSuccess(t *testing.T) {
	s := newTestServer(t)
	s.SetSpaceReplayStore(space.NewMemoryReplayStore())
	principal := &DelegationPrincipal{
		DPoPJTI: "exchange-concurrent-dpop", DPoPIssuedAt: time.Now(),
		Claims: space.SpaceTokenClaims{JTI: "exchange-concurrent-delegation", Exp: time.Now().Add(time.Minute).Unix()},
	}
	const attempts = 32
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- s.consumeSimpleSpaceExchange(context.Background(), principal, nil)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, space.ErrReplay):
			replays++
		default:
			t.Fatalf("unexpected exchange batch error: %v", err)
		}
	}
	if successes != 1 || replays != attempts-1 {
		t.Fatalf("concurrent exchange batches successes=%d replays=%d, want 1/%d", successes, replays, attempts-1)
	}
}

func TestSimpleSpaceCredentialPolicyFailureDoesNotConsumeReplayArtifacts(t *testing.T) {
	s := newTestServer(t)
	owner := s.createTestAccount(t, "retry-owner.pds.test")
	member := s.createTestAccount(t, "retry-member.pds.test")
	spaceURI := "at://" + owner.Did + "/space/" + testSimpleSpaceType + "/retry"
	if err := s.db.Create(context.Background(), &models.SimpleSpace{
		URI: spaceURI, OwnerDID: owner.Did, Type: testSimpleSpaceType, SKey: "retry",
		Policy: simpleSpacePolicyMemberList, AppAccess: simpleSpaceAppAccessOpen,
	}, nil).Error; err != nil {
		t.Fatal(err)
	}
	ref, err := space.ParseSpaceURI(spaceURI)
	if err != nil {
		t.Fatal(err)
	}
	audience := string(ref.AuthorityDID) + space.SpaceHostAudienceSuffix
	principal := &DelegationPrincipal{
		SpaceURI: spaceURI, AuthorityDID: owner.Did, DPoPJKT: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		DPoPJTI: "retry-dpop", DPoPIssuedAt: time.Now(),
		Claims: space.SpaceTokenClaims{Iss: member.Did, Sub: spaceURI, Aud: &audience, JTI: "retry-delegation", Exp: time.Now().Add(time.Minute).Unix()},
	}
	first, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.getSpaceCredential", `{"space":"`+spaceURI+`"}`, nil)
	SetPrincipal(first, principal)
	if err := s.handleSimpleSpaceGetSpaceCredential(first); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "UserNotAuthorized") {
		t.Fatalf("policy failure = %d %s", rec.Code, rec.Body.String())
	}

	if err := s.db.Create(context.Background(), &models.SimpleSpaceMember{Space: spaceURI, DID: member.Did}, nil).Error; err != nil {
		t.Fatal(err)
	}
	second, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.getSpaceCredential", `{"space":"`+spaceURI+`"}`, nil)
	SetPrincipal(second, principal)
	if err := s.handleSimpleSpaceGetSpaceCredential(second); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("successful retry = %d %s", rec.Code, rec.Body.String())
	}
	if err := s.spaceReplayStore().Consume(context.Background(), principal.Claims.JTI, string(space.TokenDelegation), time.Now().Add(time.Minute)); !errors.Is(err, space.ErrReplay) {
		t.Fatalf("delegation replay was not consumed after successful mint: %v", err)
	}
}

func TestSimpleSpaceCredentialRefreshesRotatedInlineClientKey(t *testing.T) {
	oldPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPublic, err := jwk.FromRaw(&oldPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, err := jwk.FromRaw(&newPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "client-key"
	if err := oldPublic.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if err := newPublic.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}

	var mu sync.RWMutex
	metadataKey := oldPublic
	var metadataRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		metadataRequests++
		key := metadataKey
		mu.Unlock()
		keyBytes, marshalErr := json.Marshal(key)
		if marshalErr != nil {
			t.Errorf("marshal client key: %v", marshalErr)
			return
		}
		var keyObject map[string]any
		if unmarshalErr := json.Unmarshal(keyBytes, &keyObject); unmarshalErr != nil {
			t.Errorf("unmarshal client key: %v", unmarshalErr)
			return
		}
		metadata := map[string]any{
			"client_id":                       "http://" + r.Host + r.URL.Path,
			"client_uri":                      "https://client.example.com",
			"redirect_uris":                   []string{"https://client.example.com/callback"},
			"grant_types":                     []string{"authorization_code"},
			"response_types":                  []string{"code"},
			"application_type":                "web",
			"dpop_bound_access_tokens":        true,
			"scope":                           "atproto",
			"token_endpoint_auth_method":      "private_key_jwt",
			"token_endpoint_auth_signing_alg": "ES256",
			"jwks":                            map[string]any{"keys": []any{keyObject}},
		}
		w.Header().Set("Content-Type", "application/json")
		if writeErr := json.NewEncoder(w).Encode(metadata); writeErr != nil {
			t.Errorf("write client metadata: %v", writeErr)
		}
	}))
	defer server.Close()

	s := newTestServer(t)
	s.oauthProvider = provider.NewProvider(provider.Args{
		ClientManagerArgs: oauthclient.ManagerArgs{Cli: server.Client()},
		DpopManagerArgs:   dpop.ManagerArgs{NonceSecret: []byte("test-nonce-secret")},
	})
	clientID := server.URL + "/client"
	if _, err := s.oauthProvider.ClientManager.GetClientJWKS(context.Background(), clientID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	metadataKey = newPublic
	mu.Unlock()

	spaceURI := "at://did:web:pds.test/space/com.example.forum/refresh"
	ref, err := space.ParseSpaceURI(spaceURI)
	if err != nil {
		t.Fatal(err)
	}
	audience := string(ref.AuthorityDID) + space.SpaceHostAudienceSuffix
	signer, err := space.NewECDSASigner(newPrivate, "ES256", nil)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := space.CreateClientAttestation(space.CreateSpaceTokenOptions{
		Iss:       clientID,
		Sub:       clientID,
		Aud:       audience,
		Kid:       kid,
		ExpiresIn: time.Minute,
		JTI:       "rotated-client-attestation",
	}, signer)
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.simpleSpaceCredentialClient(context.Background(), ref, attestation, simpleSpaceAppAccessOpen)
	if err != nil {
		t.Fatal(err)
	}
	if result.ClientID != clientID {
		t.Fatalf("client id = %q, want %q", result.ClientID, clientID)
	}
	mu.RLock()
	if metadataRequests != 2 {
		t.Fatalf("metadata requests = %d, want initial lookup plus forced refresh", metadataRequests)
	}
	mu.RUnlock()
}
