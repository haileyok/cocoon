package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
)

const oauthSpaceAuthority = "did:plc:z72i7hdynmk6r22z27h6tvur"

func newOAuthSpaceHandlerFixture(t *testing.T) (*Server, *testAccount, space.SpaceURI) {
	t.Helper()
	s := newTestServer(t)
	s.spaceRepoMan = NewSpaceRepoMan(s)
	account := s.createTestAccount(t, "oauth-space.pds.test")
	ref, err := space.NewSpaceURI(oauthSpaceAuthority, "com.example.space", "alpha")
	if err != nil {
		t.Fatal(err)
	}
	return s, account, ref
}

func oauthSpaceScope(ref space.SpaceURI, action string, collections ...string) string {
	parts := []string{"space:" + string(ref.SpaceType), "authority=" + string(ref.AuthorityDID), "action=" + action}
	for _, collection := range collections {
		parts = append(parts, "collection="+collection)
	}
	return parts[0] + "?" + strings.Join(parts[1:], "&")
}

func installOAuthSpacePrincipal(e echo.Context, account *testAccount, scopes ...string) {
	SetPrincipal(e, &OAuthPrincipal{Subject: account.Did, Scopes: scopes})
}

func invokeSpaceJSON(t *testing.T, account *testAccount, method, target string, body any, scopes []string, handler echo.HandlerFunc) (int, map[string]any) {
	t.Helper()
	bodyText := ""
	if body != nil {
		bodyText = mustJSON(t, body)
	}
	e, rec := newRequestContext(method, target, bodyText, nil)
	installOAuthSpacePrincipal(e, account, scopes...)
	if err := handler(e); err != nil {
		t.Fatal(err)
	}
	output := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &output); err != nil {
			t.Fatalf("decode response %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, output
}

func TestOAuthSpaceHandlersFailClosedAndRequireSubjectRepo(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	body := map[string]any{"space": ref.String(), "repo": account.Did, "collection": "com.example.post", "rkey": "first", "record": map[string]any{"$type": "com.example.post", "text": "one"}}
	e, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.putRecord", mustJSON(t, body), nil)
	SetPrincipal(e, &SpaceCredentialPrincipal{SpaceURI: ref.String()})
	if err := s.handleSpacePutRecord(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-OAuth principal status = %d, want 401", rec.Code)
	}
	body["repo"] = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	e, rec = newRequestContext(http.MethodPost, "/xrpc/com.atproto.space.putRecord", mustJSON(t, body), nil)
	installOAuthSpacePrincipal(e, account, oauthSpaceScope(ref, "create", "com.example.post"))
	if err := s.handleSpacePutRecord(e); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "InvalidRequest") {
		t.Fatalf("mismatched repo = %d/%s", rec.Code, rec.Body.String())
	}
}

func TestOAuthSpaceCRUDStrictCreateUpsertAndIdempotentDelete(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	createScope := oauthSpaceScope(ref, "create", "com.example.post")
	updateScope := oauthSpaceScope(ref, "update", "com.example.post")
	deleteScope := oauthSpaceScope(ref, "delete", "com.example.post")
	body := map[string]any{"space": ref.String(), "repo": account.Did, "collection": "com.example.post", "rkey": "first", "record": map[string]any{"$type": "com.example.post", "text": "one"}}
	status, created := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.createRecord", body, []string{createScope}, s.handleSpaceCreateRecord)
	if status != http.StatusOK || created["uri"] == nil || created["cid"] == nil {
		t.Fatalf("create = %d/%v", status, created)
	}
	status, duplicate := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.createRecord", body, []string{createScope}, s.handleSpaceCreateRecord)
	if status != http.StatusBadRequest || duplicate["error"] != "RecordAlreadyExists" {
		t.Fatalf("duplicate create = %d/%v", status, duplicate)
	}
	body["record"] = map[string]any{"$type": "com.example.post", "text": "two"}
	status, updated := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.putRecord", body, []string{updateScope}, s.handleSpacePutRecord)
	if status != http.StatusOK || updated["cid"] == created["cid"] {
		t.Fatalf("put update = %d/%v", status, updated)
	}
	deleteBody := map[string]any{"space": ref.String(), "repo": account.Did, "collection": "com.example.post", "rkey": "first"}
	status, deleted := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.deleteRecord", deleteBody, []string{deleteScope}, s.handleSpaceDeleteRecord)
	if status != http.StatusOK || len(deleted) != 0 {
		t.Fatalf("delete = %d/%v", status, deleted)
	}
	status, deleted = invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.deleteRecord", deleteBody, []string{deleteScope}, s.handleSpaceDeleteRecord)
	if status != http.StatusOK || len(deleted) != 0 {
		t.Fatalf("idempotent delete = %d/%v", status, deleted)
	}
}

func TestOAuthSpacePutUsesResolvedActionScope(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	body := map[string]any{"space": ref.String(), "repo": account.Did, "collection": "com.example.post", "rkey": "raced", "record": map[string]any{"$type": "com.example.post", "text": "one"}}
	status, output := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.putRecord", body, []string{oauthSpaceScope(ref, "update", "com.example.post")}, s.handleSpacePutRecord)
	if status != http.StatusForbidden || output["error"] != "insufficient_scope" {
		t.Fatalf("create with update scope = %d/%v", status, output)
	}
	if _, err := s.spaceRepoManager().GetRecord(context.Background(), ref.String(), account.Did, "com.example.post", "raced"); err == nil {
		t.Fatal("insufficient create scope wrote a record")
	}

	body["record"] = map[string]any{"$type": "com.example.post", "text": "original"}
	if _, err := s.spaceRepoManager().Apply(context.Background(), ref.String(), account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "existing", Record: body["record"]}}); err != nil {
		t.Fatal(err)
	}
	body["rkey"] = "existing"
	body["record"] = map[string]any{"$type": "com.example.post", "text": "unauthorized-update"}
	status, output = invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.putRecord", body, []string{oauthSpaceScope(ref, "create", "com.example.post")}, s.handleSpacePutRecord)
	if status != http.StatusForbidden || output["error"] != "insufficient_scope" {
		t.Fatalf("update with create scope = %d/%v", status, output)
	}
	row, err := s.spaceRepoManager().GetRecord(context.Background(), ref.String(), account.Did, "com.example.post", "existing")
	if err != nil {
		t.Fatal(err)
	}
	if string(row.CanonicalCBOR) == string(mustRecordCBOR(t, body["record"].(map[string]any))) {
		t.Fatal("insufficient update scope changed a record")
	}
}

func TestOAuthSpaceCreateGeneratesRkey(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	body := map[string]any{"space": ref.String(), "repo": account.Did, "collection": "com.example.post", "record": map[string]any{"$type": "com.example.post", "text": "generated"}}
	status, output := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.createRecord", body, []string{oauthSpaceScope(ref, "create", "com.example.post")}, s.handleSpaceCreateRecord)
	if status != http.StatusOK {
		t.Fatalf("generated create = %d/%v", status, output)
	}
	recordURI, err := space.ParseRecordURI(output["uri"].(string))
	if err != nil || recordURI.RKey.String() == "" {
		t.Fatalf("generated URI = %v/%v", output["uri"], err)
	}
}

func TestOAuthSpaceApplyWritesClosedUnionAndAtomicStrictness(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	ctx := context.Background()
	manager := s.spaceRepoManager()
	if _, err := manager.Apply(ctx, ref.String(), account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "existing", Record: map[string]any{"$type": "com.example.post", "text": "old"}}}); err != nil {
		t.Fatal(err)
	}
	writeScopes := []string{oauthSpaceScope(ref, "create", "com.example.post"), oauthSpaceScope(ref, "update", "com.example.post"), oauthSpaceScope(ref, "delete", "com.example.post")}
	body := map[string]any{"space": ref.String(), "repo": account.Did, "writes": []any{
		map[string]any{"$type": spaceCreateType, "collection": "com.example.post", "rkey": "new", "value": map[string]any{"$type": "com.example.post", "text": "new"}},
		map[string]any{"$type": spaceUpdateType, "collection": "com.example.post", "rkey": "existing", "value": map[string]any{"$type": "com.example.post", "text": "updated"}},
	}}
	status, output := invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.applyWrites", body, writeScopes, s.handleSpaceApplyWrites)
	results, ok := output["results"].([]any)
	if status != http.StatusOK || !ok || len(results) != 2 || results[0].(map[string]any)["$type"] != spaceCreateResultType || results[1].(map[string]any)["$type"] != spaceUpdateResultType {
		t.Fatalf("apply = %d/%v", status, output)
	}
	before, err := manager.GetRecord(ctx, ref.String(), account.Did, "com.example.post", "existing")
	if err != nil {
		t.Fatal(err)
	}
	body["writes"] = []any{
		map[string]any{"$type": spaceUpdateType, "collection": "com.example.post", "rkey": "existing", "value": map[string]any{"$type": "com.example.post", "text": "rollback"}},
		map[string]any{"$type": spaceDeleteType, "collection": "com.example.post", "rkey": "missing"},
	}
	status, output = invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.applyWrites", body, writeScopes, s.handleSpaceApplyWrites)
	if status != http.StatusBadRequest || output["error"] != "RecordNotFound" {
		t.Fatalf("atomic missing delete = %d/%v", status, output)
	}
	after, err := manager.GetRecord(ctx, ref.String(), account.Did, "com.example.post", "existing")
	if err != nil || !bytes.Equal(after.CanonicalCBOR, before.CanonicalCBOR) {
		t.Fatalf("atomic rollback changed record: err=%v", err)
	}
	body["writes"] = []any{map[string]any{"$type": "com.atproto.space.applyWrites#unknown", "collection": "com.example.post", "value": map[string]any{"$type": "com.example.post"}}}
	status, output = invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.applyWrites", body, writeScopes, s.handleSpaceApplyWrites)
	if status != http.StatusBadRequest || output["error"] != "InvalidRequest" {
		t.Fatalf("closed union = %d/%v", status, output)
	}
	body["writes"] = []any{map[string]any{"$type": spaceCreateType, "collection": "com.example.post", "rkey": "bad/key", "value": map[string]any{"$type": "com.example.post", "text": "bad"}}}
	status, output = invokeSpaceJSON(t, account, http.MethodPost, "/xrpc/com.atproto.space.applyWrites", body, writeScopes, s.handleSpaceApplyWrites)
	if status != http.StatusBadRequest || output["error"] != "InvalidRequest" {
		t.Fatalf("invalid create rkey = %d/%v", status, output)
	}
}

func TestOAuthSpaceListSpacesFiltersAndPaginates(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	other, err := space.NewSpaceURI(oauthSpaceAuthority, "com.example.other", "beta")
	if err != nil {
		t.Fatal(err)
	}
	third, err := space.NewSpaceURI("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "com.example.space", "gamma")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, target := range []space.SpaceURI{ref, other, third} {
		if _, err := s.spaceRepoManager().Apply(ctx, target.String(), account.Did, []SpaceRepoOperation{{Type: SpaceRepoOpCreate, Collection: "com.example.post", Rkey: "one", Record: map[string]any{"$type": "com.example.post"}}}); err != nil {
			t.Fatal(err)
		}
	}
	scope := "space:*?authority=*&action=read"
	status, output := invokeSpaceJSON(t, account, http.MethodGet, "/xrpc/com.atproto.space.listSpaces?limit=1", nil, []string{scope}, s.handleSpaceListSpaces)
	spaces, ok := output["spaces"].([]any)
	if status != http.StatusOK || !ok || len(spaces) != 1 || output["cursor"] == nil {
		t.Fatalf("first list page = %d/%v", status, output)
	}
	status, output = invokeSpaceJSON(t, account, http.MethodGet, "/xrpc/com.atproto.space.listSpaces?limit=1&cursor="+output["cursor"].(string), nil, []string{scope}, s.handleSpaceListSpaces)
	if status != http.StatusOK || len(output["spaces"].([]any)) != 1 {
		t.Fatalf("second list page = %d/%v", status, output)
	}
	status, output = invokeSpaceJSON(t, account, http.MethodGet, "/xrpc/com.atproto.space.listSpaces?type=com.example.other&did="+oauthSpaceAuthority, nil, []string{scope}, s.handleSpaceListSpaces)
	spaces = output["spaces"].([]any)
	if status != http.StatusOK || len(spaces) != 1 || spaces[0].(map[string]any)["uri"] != other.String() {
		t.Fatalf("filtered list = %d/%v", status, output)
	}
}

func TestOAuthSpaceDelegationClaimsAndReadSelfRejection(t *testing.T) {
	s, account, ref := newOAuthSpaceHandlerFixture(t)
	target := "/xrpc/com.atproto.space.getDelegationToken?space=" + ref.String()
	status, output := invokeSpaceJSON(t, account, http.MethodGet, target, nil, []string{oauthSpaceScope(ref, "read")}, s.handleSpaceGetDelegationToken)
	if status != http.StatusOK || output["token"] == nil {
		t.Fatalf("delegation = %d/%v", status, output)
	}
	parsed, err := space.ParseSpaceToken(space.TokenDelegation, output["token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Claims.Iss != account.Did || parsed.Claims.Sub != ref.String() || parsed.Claims.Aud == nil || *parsed.Claims.Aud != oauthSpaceAuthority+space.SpaceHostAudienceSuffix || parsed.Claims.Exp-parsed.Claims.IAT != 60 || parsed.Claims.JTI == "" || parsed.Header.Kid != space.DelegationSigningKeyID {
		t.Fatalf("delegation claims/header = %#v/%#v", parsed.Claims, parsed.Header)
	}
	status, output = invokeSpaceJSON(t, account, http.MethodGet, target, nil, []string{oauthSpaceScope(ref, "read_self")}, s.handleSpaceGetDelegationToken)
	if status != http.StatusForbidden || output["error"] != "insufficient_scope" {
		t.Fatalf("read_self delegation = %d/%v", status, output)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
