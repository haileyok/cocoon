package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/space"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Credential, OAuth and mock-party helpers for the Spaces test network, the
// rest of the reference's tests/_space.ts.

// spaceCredential is a credential and the P-256 key it is bound to.
type spaceCredential struct {
	credential string
	key        *atcrypto.PrivateKeyP256
}

// headers signs a request with the credential for an audience DID.
func (c *spaceCredential) headers(t *testing.T, audience string) map[string]string {
	t.Helper()
	h, err := space.CreateSpaceSigHeaders(c.key, "Atproto-Space "+c.credential, audience)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// get reads from a PDS with the credential, addressed to the repo param or
// else the space's authority, as the reference's SpaceCredential.fetch does.
func (c *spaceCredential) get(t *testing.T, p *spacePDS, nsid string, params map[string]string) xres {
	t.Helper()
	aud := params["repo"]
	if aud == "" {
		ref, err := space.ParseRef(params["space"])
		if err != nil {
			t.Fatal(err)
		}
		aud = ref.Authority
	}
	return p.get(nsid, params, c.headers(t, aud))
}

func (c *spaceCredential) post(t *testing.T, p *spacePDS, nsid string, body map[string]any) xres {
	t.Helper()
	aud, _ := body["repo"].(string)
	if aud == "" {
		ref, err := space.ParseRef(body["space"].(string))
		if err != nil {
			t.Fatal(err)
		}
		aud = ref.Authority
	}
	return p.post(nsid, body, c.headers(t, aud))
}

func newP256Key(t *testing.T) *atcrypto.PrivateKeyP256 {
	t.Helper()
	k, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func delegationTokenFor(t *testing.T, a *actor, spaceURI string) string {
	t.Helper()
	return mustOK(t, a.get("com.atproto.space.getDelegationToken", map[string]string{"space": spaceURI})).str("token")
}

// exchange posts getSpaceCredential to the authority's PDS, signing the
// exchange with key.
func exchange(t *testing.T, authority *spacePDS, spaceURI, token string, key *atcrypto.PrivateKeyP256, attestation string) xres {
	t.Helper()
	h, err := space.CreateSpaceSigHeaders(key, "Bearer "+token, "")
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"space": spaceURI}
	if attestation != "" {
		body["clientAttestation"] = attestation
	}
	return authority.post("com.atproto.space.getSpaceCredential", body, h)
}

// credentialFor mints a delegation token on a's PDS and exchanges it with the
// authority for a credential bound to a fresh key.
func credentialFor(t *testing.T, a *actor, authority *spacePDS, spaceURI string) *spaceCredential {
	t.Helper()
	key := newP256Key(t)
	res := mustOK(t, exchange(t, authority, spaceURI, delegationTokenFor(t, a, spaceURI), key, ""))
	return &spaceCredential{credential: res.str("credential"), key: key}
}

// waitSpaceJobs waits for background space work on every PDS.
func (n *spaceNet) waitSpaceJobs() {
	for _, p := range n.pdses {
		p.s.spaceJobs.Wait()
	}
}

// awaitCond polls until cond holds, for best-effort notifications.
func awaitCond(t *testing.T, cond func() bool) bool {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return true
		}
		time.Sleep(30 * time.Millisecond)
	}
	return cond()
}

// takedown marks an account taken down, as an admin takedown does.
func takedown(t *testing.T, a *actor, on bool) {
	t.Helper()
	var ref any
	if on {
		ref = "test-takedown"
	}
	if err := a.pds.s.db.Exec(context.Background(), "UPDATE repos SET takedown_ref = ? WHERE did = ?", nil, ref, a.did).Error; err != nil {
		t.Fatal(err)
	}
}

// OAuth sessions --------------------------------------------------------

type dpopSession struct {
	key   *ecdsa.PrivateKey
	jwk   map[string]any
	token string
	mu    sync.Mutex
	nonce string
}

// createOAuthActor makes an account whose requests use an OAuth session with
// the given scope, as an app the user granted it to would.
func (p *spacePDS) createOAuthActor(name, scope string) *actor {
	t := p.net.t
	t.Helper()
	a := p.createActor(name)
	a.oauth = p.newOAuthSession(a, scope)
	return a
}

// newOAuthSession inserts a DPoP-bound OAuth token for a, as the token
// endpoint would after the user approved scope.
func (p *spacePDS) newOAuthSession(a *actor, scope string) *dpopSession {
	t := p.net.t
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jk, err := jwk.FromRaw(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := jk.Thumbprint(cryptoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	jb, _ := json.Marshal(jk)
	var jm map[string]any
	_ = json.Unmarshal(jb, &jm)
	repo, err := p.s.getRepoActorByDid(context.Background(), a.did)
	if err != nil {
		t.Fatal(err)
	}
	tok := "oauth-" + uuid.NewString()
	row := provider.OauthToken{
		ClientId:       "http://localhost",
		Parameters:     provider.ParRequest{Scope: p.s.expandScopes(context.Background(), scope, a.did), DpopJkt: &jkt},
		ExpiresAt:      time.Now().Add(time.Hour),
		Sub:            a.did,
		SessionVersion: repo.Repo.SessionVersion,
		Token:          tok,
		RefreshToken:   "refresh-" + tok,
	}
	if err := p.s.db.Create(context.Background(), &row, nil).Error; err != nil {
		t.Fatal(err)
	}
	if p.s.oauthProvider == nil {
		t.Fatal("pds has no oauth provider")
	}
	return &dpopSession{key: key, jwk: jm, token: tok}
}

func (d *dpopSession) proof(t *testing.T, method, htu string) string {
	t.Helper()
	ath := sha256.Sum256([]byte(d.token))
	claims := jwt.MapClaims{
		"jti": uuid.NewString(), "htm": method, "htu": htu, "iat": time.Now().Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
	}
	d.mu.Lock()
	if d.nonce != "" {
		claims["nonce"] = d.nonce
	}
	d.mu.Unlock()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = d.jwk
	s, err := tok.SignedString(d.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// doOAuth sends a request with the DPoP session, retrying once with the
// server's nonce.
func (a *actor) doOAuth(method, nsid string, params map[string]string, body any) xres {
	t := a.pds.net.t
	t.Helper()
	v := url.Values{}
	for k, x := range params {
		v.Set(k, x)
	}
	path := "/xrpc/" + nsid
	htu := "https://" + a.pds.s.config.Hostname + path
	var res xres
	for i := 0; i < 2; i++ {
		h := map[string]string{"Authorization": "DPoP " + a.oauth.token, "DPoP": a.oauth.proof(t, method, htu)}
		res = a.pds.net.do(method, a.pds.url, nsid, v, body, h)
		if n := res.header.Get("DPoP-Nonce"); n != "" {
			a.oauth.mu.Lock()
			a.oauth.nonce = n
			a.oauth.mu.Unlock()
		}
		if res.status != 401 || res.errName() != "use_dpop_nonce" {
			break
		}
	}
	return res
}

// Mock parties ------------------------------------------------------------

type mockCall struct {
	lxm  string
	body map[string]any
	auth string
}

// mockService is a local HTTP service with a DID in the directory, which
// records every request it receives: a managing app, a syncer, a remote
// space host.
type mockService struct {
	t         *testing.T
	srv       *httptest.Server
	url       string
	did       string
	serviceID string
	key       *atcrypto.PrivateKeyK256
	mu        sync.Mutex
	calls     []mockCall
	respond   func(r *http.Request, call mockCall) (int, any)
}

func (n *spaceNet) newMockService(serviceID string, respond func(*http.Request, mockCall) (int, any)) *mockService {
	t := n.t
	t.Helper()
	m := &mockService{t: t, serviceID: serviceID, respond: respond}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		call := mockCall{lxm: strings.TrimPrefix(r.URL.Path, "/xrpc/"), auth: r.Header.Get("Authorization")}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &call.body)
		} else {
			call.body = map[string]any{}
			for k := range r.URL.Query() {
				call.body[k] = r.URL.Query().Get(k)
			}
		}
		m.mu.Lock()
		m.calls = append(m.calls, call)
		resp := m.respond
		m.mu.Unlock()
		status, body := 200, any(map[string]any{})
		if resp != nil {
			status, body = resp(r, call)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(m.srv.Close)
	m.url = m.srv.URL
	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	m.key = k
	m.did = "did:plc:" + strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))[:24]
	doc := didDocFor(m.did, k, "")
	doc.Service = []identity.DidDocService{{Id: "#" + serviceID, Type: "AtprotoSpaceService", ServiceEndpoint: m.url}}
	n.dir.put(doc)
	return m
}

func (m *mockService) serviceRef() string { return m.did + "#" + m.serviceID }

func (m *mockService) setRespond(fn func(*http.Request, mockCall) (int, any)) {
	m.mu.Lock()
	m.respond = fn
	m.mu.Unlock()
}

func (m *mockService) callsTo(lxm string) []mockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []mockCall
	for _, c := range m.calls {
		if c.lxm == lxm {
			out = append(out, c)
		}
	}
	return out
}

// serviceAuth mints service auth from the mock's own DID.
func (m *mockService) serviceAuth(aud, lxm string) map[string]string {
	tok, err := mintServiceAuth(m.key, m.did, aud, lxm, time.Minute)
	if err != nil {
		m.t.Fatal(err)
	}
	return map[string]string{"Authorization": "Bearer " + tok}
}

// mockClientApp publishes client metadata and a JWKS over HTTP, so a client
// attestation is checked against a key actually fetched.
type mockClientApp struct {
	srv      *httptest.Server
	clientID string
	jwksURI  string
	key      jwk.Key
	priv     *ecdsa.PrivateKey
}

type clientAppOpts struct {
	kid         string
	publishKeys *bool
	inlineJwks  bool
}

func (n *spaceNet) newMockClientApp(o clientAppOpts) *mockClientApp {
	t := n.t
	t.Helper()
	if o.kid == "" {
		o.kid = "key-1"
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, o.kid)
	_ = key.Set(jwk.AlgorithmKey, jwa.ES256)
	pub, _ := key.PublicKey()
	m := &mockClientApp{key: key, priv: priv}
	var base string
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		send := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		switch r.URL.Path {
		case "/client-metadata.json":
			md := map[string]any{
				"client_id": base + "/client-metadata.json", "client_name": "Mock Space App",
				"redirect_uris": []string{base + "/cb"}, "response_types": []string{"code"},
				"grant_types": []string{"authorization_code"}, "scope": "atproto", "application_type": "web",
				"token_endpoint_auth_method": "private_key_jwt", "dpop_bound_access_tokens": true,
			}
			if o.publishKeys == nil || *o.publishKeys {
				if o.inlineJwks {
					md["jwks"] = map[string]any{"keys": []any{pub}}
				} else {
					md["jwks_uri"] = base + "/jwks.json"
				}
			}
			send(md)
		case "/jwks.json":
			send(map[string]any{"keys": []any{pub}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	base = strings.Replace(m.srv.URL, "localhost", "127.0.0.1", 1)
	m.clientID = base + "/client-metadata.json"
	m.jwksURI = base + "/jwks.json"
	return m
}

// installOn lets a PDS fetch from this app (the default fetch is SSRF-guarded).
func (m *mockClientApp) installOn(p *spacePDS) {
	p.s.spaceFetchHTTP = &http.Client{Timeout: 5 * time.Second}
}

type attestOpts struct {
	signWith  jwk.Key
	iss       string
	expiresIn int64
	jti       string
	noJti     bool
}

// attest signs an attestation addressed to spaceHost.
func (m *mockClientApp) attest(t *testing.T, spaceHost string, o attestOpts) string {
	t.Helper()
	now := time.Now().Unix()
	iss := o.iss
	if iss == "" {
		iss = m.clientID
	}
	exp := o.expiresIn
	if exp == 0 {
		exp = 60
	}
	payload := map[string]any{"iss": iss, "sub": iss, "aud": spaceHost, "iat": now, "exp": now + exp}
	if !o.noJti {
		payload["jti"] = o.jti
		if o.jti == "" {
			payload["jti"] = "nonce-" + uuid.NewString()
		}
	}
	signer := o.signWith
	if signer == nil {
		signer = m.key
	}
	pb, _ := json.Marshal(payload)
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.TypeKey, "atproto-client-attestation+jwt")
	_ = hdrs.Set(jws.KeyIDKey, signer.KeyID())
	out, err := jws.Sign(pb, jws.WithKey(jwa.ES256, signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

const cryptoSHA256 = crypto.SHA256
