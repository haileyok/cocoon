package server

// A multi-PDS test network for Spaces, the Go counterpart of the reference's
// packages/pds/tests/_space.ts (bluesky-social/atproto 5b95b2f2): several PDSes
// sharing one in-memory DID directory, accounts with password sessions, and
// helpers for the space write and credential flows.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/space"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
)

const (
	testCollection    = "com.example.spaceRecord"
	testCollectionAlt = "com.example.spaceNote"
	testSpaceType     = "com.example.group"
)

// didDirectory serves DID documents for did:plc (by path) and did:web (by
// rewriting https://{host}/.well-known/did.json) from memory.
type didDirectory struct {
	mu   sync.Mutex
	docs map[string]*identity.DidDoc
	srv  *httptest.Server
	down atomic.Bool
}

func newDidDirectory(t *testing.T) *didDirectory {
	d := &didDirectory{docs: map[string]*identity.DidDoc{}}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		did := strings.TrimPrefix(r.URL.Path, "/")
		d.mu.Lock()
		doc := d.docs[did]
		d.mu.Unlock()
		if doc == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *didDirectory) put(doc *identity.DidDoc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.docs[doc.Id] = doc
}

func (d *didDirectory) get(did string) *identity.DidDoc {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.docs[did]
}

// RoundTrip sends did:web document requests to the directory, and everything
// else out over the default transport.
func (d *didDirectory) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme == "https" && r.URL.Path == "/.well-known/did.json" {
		u, _ := url.Parse(d.srv.URL + "/did:web:" + r.URL.Host)
		r2 := r.Clone(r.Context())
		r2.URL = u
		r2.Host = u.Host
		return http.DefaultTransport.RoundTrip(r2)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// noCache is a passport cache that holds nothing, so key rotations and
// endpoint changes in the directory are seen at once.
type noCache struct{}

func (noCache) GetDoc(string) (*identity.DidDoc, bool) { return nil, false }
func (noCache) PutDoc(string, *identity.DidDoc) error  { return nil }
func (noCache) BustDoc(string) error                   { return nil }
func (noCache) GetDid(string) (string, bool)           { return "", false }
func (noCache) PutDid(string, string) error            { return nil }
func (noCache) BustDid(string) error                   { return nil }

type spaceNet struct {
	t     *testing.T
	dir   *didDirectory
	http  *http.Client
	pdses []*spacePDS
}

func newSpaceNet(t *testing.T) *spaceNet {
	t.Helper()
	n := &spaceNet{t: t, dir: newDidDirectory(t)}
	n.http = &http.Client{Transport: n.dir, Timeout: 10 * time.Second}
	return n
}

type spacePDS struct {
	net *spaceNet
	s   *Server
	srv *httptest.Server
	url string
}

func (n *spaceNet) newPDS() *spacePDS {
	t := n.t
	t.Helper()
	s := newTestServer(t)
	p := &spacePDS{net: n, s: s}
	p.srv = httptest.NewUnstartedServer(nil)
	p.url = "http://" + p.srv.Listener.Addr().String()
	host := p.srv.Listener.Addr().String()
	s.config.Hostname = host
	s.config.Did = "did:web:" + strings.ReplaceAll(host, ":", "%3A")
	s.http = n.http
	s.passport = identity.NewPassport(n.http, noCache{}, identity.WithPlcURL(n.dir.srv.URL))
	s.oauthProvider = provider.NewProvider(provider.Args{
		Hostname:        host,
		DpopManagerArgs: dpop.ManagerArgs{Hostname: host, NonceSecret: []byte("0123456789abcdef0123456789abcdef"), Logger: s.logger},
	})
	s.echo = echo.New()
	s.echo.Validator = newTestValidator()
	s.addRoutes()
	p.srv.Config.Handler = s.echo
	p.srv.Start()
	t.Cleanup(p.srv.Close)
	t.Cleanup(s.stopSpaceWorkers)
	n.pdses = append(n.pdses, p)
	return p
}

// actor is an account with everything needed to act as it.
type actor struct {
	name   string
	did    string
	pds    *spacePDS
	key    *atcrypto.PrivateKeyK256
	access string
	// oauth, when set, makes the actor's requests over a DPoP OAuth session.
	oauth *dpopSession
}

func (a *actor) auth() map[string]string {
	return map[string]string{"Authorization": "Bearer " + a.access}
}

func didDocFor(did string, key atcrypto.PrivateKey, endpoint string) *identity.DidDoc {
	pub, _ := key.PublicKey()
	doc := &identity.DidDoc{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		Id:      did,
		VerificationMethods: []identity.DidDocVerificationMethod{{
			Id: did + "#atproto", Type: "Multikey", Controller: did, PublicKeyMultibase: pub.Multibase(),
		}},
	}
	if endpoint != "" {
		doc.Service = []identity.DidDocService{{Id: "#atproto_pds", Type: "AtprotoPersonalDataServer", ServiceEndpoint: endpoint}}
	}
	return doc
}

func (p *spacePDS) createActor(name string) *actor {
	t := p.net.t
	t.Helper()
	acct := p.s.createTestAccount(t, name+".test")
	key, err := atcrypto.ParsePrivateBytesK256(acct.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	p.net.dir.put(didDocFor(acct.Did, key, p.url))
	repo, err := p.s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := p.s.createSession(context.Background(), &repo.Repo)
	if err != nil {
		t.Fatal(err)
	}
	return &actor{name: name, did: acct.Did, pds: p, key: key, access: sess.AccessToken}
}

// xres is an XRPC response.
type xres struct {
	status int
	body   map[string]any
	raw    []byte
	header http.Header
}

func (r xres) errName() string { s, _ := r.body["error"].(string); return s }
func (r xres) message() string { s, _ := r.body["message"].(string); return s }
func (r xres) str(k string) string {
	s, _ := r.body[k].(string)
	return s
}
func (r xres) list(k string) []map[string]any {
	arr, _ := r.body[k].([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, x := range arr {
		m, _ := x.(map[string]any)
		out = append(out, m)
	}
	return out
}

func (n *spaceNet) do(method, base, nsid string, params url.Values, body any, headers map[string]string) xres {
	n.t.Helper()
	u := base + "/xrpc/" + nsid
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	var rdr io.Reader
	if body != nil {
		switch b := body.(type) {
		case []byte:
			rdr = bytes.NewReader(b)
		default:
			jb, err := json.Marshal(body)
			if err != nil {
				n.t.Fatal(err)
			}
			rdr = bytes.NewReader(jb)
		}
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		n.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := xres{status: resp.StatusCode, raw: raw, header: resp.Header}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

func (a *actor) get(nsid string, params map[string]string) xres {
	if a.oauth != nil {
		return a.doOAuth(http.MethodGet, nsid, params, nil)
	}
	return a.pds.get(nsid, params, a.auth())
}

func (a *actor) post(nsid string, body any) xres {
	if a.oauth != nil {
		return a.doOAuth(http.MethodPost, nsid, nil, body)
	}
	return a.pds.post(nsid, body, a.auth())
}

func (p *spacePDS) get(nsid string, params map[string]string, headers map[string]string) xres {
	v := url.Values{}
	for k, x := range params {
		v.Set(k, x)
	}
	return p.net.do(http.MethodGet, p.url, nsid, v, nil, headers)
}

func (p *spacePDS) post(nsid string, body any, headers map[string]string) xres {
	return p.net.do(http.MethodPost, p.url, nsid, nil, body, headers)
}

func mustOK(t *testing.T, r xres) xres {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("status %d: %s", r.status, r.raw)
	}
	return r
}

func expectErr(t *testing.T, r xres, status int, name string) {
	t.Helper()
	if r.status != status || (name != "" && r.errName() != name) {
		t.Fatalf("want %d %s, got %d: %s", status, name, r.status, r.raw)
	}
}

var nonSkey = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// testSkey is a record-key-safe slug of the running test's name.
func testSkey(t *testing.T) string {
	s := strings.Trim(nonSkey.ReplaceAllString(t.Name(), "-"), "-")
	if len(s) > 120 {
		s = s[:120]
	}
	if s == "" {
		return "space"
	}
	return s
}

type spaceOpts struct {
	skey        string
	spaceType   string
	members     []*actor
	readPolicy  map[string]any
	writePolicy map[string]any
	appAccess   map[string]any
	ungoverned  bool
}

func memberListPolicy() map[string]any {
	return map[string]any{"$type": "com.atproto.simplespace.defs#memberListPolicy"}
}
func publicPolicy() map[string]any {
	return map[string]any{"$type": "com.atproto.simplespace.defs#publicPolicy"}
}
func managingAppPolicy(app string) map[string]any {
	return map[string]any{"$type": "com.atproto.simplespace.defs#managingAppPolicy", "managingApp": app}
}
func openAccess() map[string]any { return map[string]any{"$type": "com.atproto.simplespace.defs#open"} }
func allowList(ids ...string) map[string]any {
	return map[string]any{"$type": "com.atproto.simplespace.defs#allowList", "allowed": ids}
}

// createSpace creates a space governed by owner, adding members.
func createSpace(t *testing.T, owner *actor, o spaceOpts) string {
	t.Helper()
	if o.skey == "" {
		o.skey = testSkey(t)
	}
	if o.spaceType == "" {
		o.spaceType = testSpaceType
	}
	uri := space.Ref{Authority: owner.did, Type: o.spaceType, Skey: o.skey}.String()
	if !o.ungoverned {
		body := map[string]any{"spaceType": o.spaceType, "skey": o.skey}
		body["readPolicy"] = memberListPolicy()
		if o.readPolicy != nil {
			body["readPolicy"] = o.readPolicy
		}
		body["writePolicy"] = memberListPolicy()
		if o.writePolicy != nil {
			body["writePolicy"] = o.writePolicy
		}
		body["appAccess"] = openAccess()
		if o.appAccess != nil {
			body["appAccess"] = o.appAccess
		}
		r := mustOK(t, owner.post("com.atproto.simplespace.createSpace", body))
		if r.str("uri") != uri {
			t.Fatalf("expected space %s, got %s", uri, r.str("uri"))
		}
	}
	for _, m := range o.members {
		putMember(t, owner, uri, m, true, true)
	}
	return uri
}

func putMember(t *testing.T, owner *actor, spaceURI string, m *actor, read, write bool) {
	t.Helper()
	mustOK(t, owner.post("com.atproto.simplespace.putMember", map[string]any{"space": spaceURI, "did": m.did, "read": read, "write": write}))
}

func testRecord(collection, text string) map[string]any {
	if text == "" {
		text = "hello"
	}
	return map[string]any{"$type": collection, "text": text, "createdAt": time.Now().UTC().Format(time.RFC3339Nano)}
}

type writeOpts struct {
	collection string
	rkey       string
	text       string
	record     map[string]any
	validate   *bool
	headers    map[string]string
}

func (w writeOpts) body(a *actor, spaceURI string, defaultRkey string) map[string]any {
	if w.collection == "" {
		w.collection = testCollection
	}
	if w.record == nil {
		w.record = testRecord(w.collection, w.text)
	}
	b := map[string]any{"space": spaceURI, "repo": a.did, "collection": w.collection, "record": w.record}
	rkey := w.rkey
	if rkey == "" {
		rkey = defaultRkey
	}
	if rkey != "" {
		b["rkey"] = rkey
	}
	if w.validate != nil {
		b["validate"] = *w.validate
	}
	return b
}

func (w writeOpts) auth(a *actor) map[string]string {
	if w.headers != nil {
		return w.headers
	}
	return a.auth()
}

// doWrite creates one record in a's own repo in the space.
func doWrite(a *actor, spaceURI string, w writeOpts) xres {
	if w.headers == nil {
		return a.post("com.atproto.space.createRecord", w.body(a, spaceURI, ""))
	}
	return a.pds.post("com.atproto.space.createRecord", w.body(a, spaceURI, ""), w.headers)
}

func doPut(a *actor, spaceURI string, w writeOpts) xres {
	if w.headers == nil {
		return a.post("com.atproto.space.putRecord", w.body(a, spaceURI, "self"))
	}
	return a.pds.post("com.atproto.space.putRecord", w.body(a, spaceURI, "self"), w.headers)
}

func doDel(a *actor, spaceURI, collection, rkey string) xres {
	if collection == "" {
		collection = testCollection
	}
	return a.post("com.atproto.space.deleteRecord", map[string]any{"space": spaceURI, "repo": a.did, "collection": collection, "rkey": rkey})
}

// repoState reads a's stored repo state in a space directly, as the reference's
// helper does. Nil when the repo has never been written to.
func repoState(t *testing.T, a *actor, spaceURI string) *models.SpaceRepo {
	t.Helper()
	var rows []models.SpaceRepo
	if err := a.pds.s.db.Raw(context.Background(), "SELECT * FROM space_repos WHERE did = ? AND space = ?", nil, a.did, spaceURI).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || rows[0].SetHash == nil {
		return nil
	}
	return &rows[0]
}

// expectSetHashMatchesStore asserts a's stored set hash equals one recomputed
// from its stored records.
func expectSetHashMatchesStore(t *testing.T, a *actor, spaceURI string) {
	t.Helper()
	var recs []models.SpaceRecord
	if err := a.pds.s.db.Raw(context.Background(), "SELECT * FROM space_records WHERE did = ? AND space = ?", nil, a.did, spaceURI).Scan(&recs).Error; err != nil {
		t.Fatal(err)
	}
	var refs []space.RecordRef
	for _, r := range recs {
		refs = append(refs, space.RecordRef{Collection: r.Collection, Rkey: r.Rkey, Cid: mustCid(t, r.Cid)})
	}
	var state []byte
	if st := repoState(t, a, spaceURI); st != nil {
		state = st.SetHash
	}
	stored, err := space.RepoCommitFromState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !space.RepoCommitFromRecords(refs).SetHash.Equal(stored.SetHash) {
		t.Fatal("stored set hash diverged from the stored records")
	}
}

func lastSegment(uri string) string { return uri[strings.LastIndex(uri, "/")+1:] }

func boolp(b bool) *bool { return &b }

var _ = fmt.Sprintf
