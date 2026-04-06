package testpds_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/haileyok/cocoon/testpds"
)

func TestStart(t *testing.T) {
	pds := testpds.Start(t, nil)

	resp, err := http.Get(pds.URL + "/xrpc/_health")
	if err != nil {
		t.Fatalf("health check request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestStartWithOptions(t *testing.T) {
	pds := testpds.Start(t, &testpds.Options{
		AdminPassword: "custom-password",
		RequireInvite: true,
	})

	resp, err := http.Get(pds.URL + "/xrpc/_health")
	if err != nil {
		t.Fatalf("health check request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	if pds.AdminPassword != "custom-password" {
		t.Fatalf("expected admin password 'custom-password', got '%s'", pds.AdminPassword)
	}
}

func TestCreateAccount(t *testing.T) {
	pds := testpds.Start(t, nil)
	ctx := context.Background()

	client := pds.Client()
	email := "alice@test.com"
	password := "hunter2"
	out, err := atproto.ServerCreateAccount(ctx, client, &atproto.ServerCreateAccount_Input{
		Handle:   "alice.test",
		Email:    &email,
		Password: &password,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	if out.Handle != "alice.test" {
		t.Errorf("expected handle 'alice.test', got '%s'", out.Handle)
	}
	if out.Did == "" {
		t.Error("expected non-empty DID")
	}
	if out.AccessJwt == "" {
		t.Error("expected non-empty access JWT")
	}

	// Verify FakePLC recorded the operation
	if pds.FakePLC == nil {
		t.Fatal("expected FakePLC to be set")
	}
	op := pds.FakePLC.GetOperation(out.Did)
	if op == nil {
		t.Fatal("expected FakePLC to have recorded an operation for the DID")
	}
}

func TestMustCreateAccount(t *testing.T) {
	pds := testpds.Start(t, nil)

	alice := pds.MustCreateAccount(t, "alice.test", "alice@test.com", "password")

	if alice.Auth.Did == "" {
		t.Fatal("expected non-empty DID")
	}
	if alice.Auth.Handle != "alice.test" {
		t.Errorf("expected handle 'alice.test', got '%s'", alice.Auth.Handle)
	}
}

func TestRecordCRUD(t *testing.T) {
	pds := testpds.Start(t, nil)
	ctx := context.Background()

	// Create an authenticated client
	alice := pds.MustCreateAccount(t, "alice.test", "alice@test.com", "password123")

	// Create a record
	created, err := atproto.RepoCreateRecord(ctx, alice, &atproto.RepoCreateRecord_Input{
		Repo:       alice.Auth.Did,
		Collection: "app.bsky.feed.post",
		Record: &lexutil.LexiconTypeDecoder{Val: &bsky.FeedPost{
			Text:      "hello from testpds",
			CreatedAt: time.Now().Format(time.RFC3339),
		}},
	})
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	if created.Uri == "" {
		t.Fatal("expected non-empty record URI")
	}
	t.Logf("created: %s", created.Uri)

	// List records
	listed, err := atproto.RepoListRecords(ctx, pds.Client(), "app.bsky.feed.post", "", 50, alice.Auth.Did, false)
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	if len(listed.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(listed.Records))
	}
	if listed.Records[0].Uri != created.Uri {
		t.Errorf("URI mismatch: %s != %s", listed.Records[0].Uri, created.Uri)
	}
	t.Logf("listed: %s", listed.Records[0].Uri)

	// Delete the record
	// Extract rkey from URI: at://did/collection/rkey
	rkey := created.Uri[len(created.Uri)-13:] // TID is 13 chars
	_, err = atproto.RepoDeleteRecord(ctx, alice, &atproto.RepoDeleteRecord_Input{
		Repo:       alice.Auth.Did,
		Collection: "app.bsky.feed.post",
		Rkey:       rkey,
	})
	if err != nil {
		t.Fatalf("delete record: %v", err)
	}

	// Verify deletion
	listed, err = atproto.RepoListRecords(ctx, pds.Client(), "app.bsky.feed.post", "", 50, alice.Auth.Did, false)
	if err != nil {
		t.Fatalf("list records after delete: %v", err)
	}
	if len(listed.Records) != 0 {
		t.Fatalf("expected 0 records after delete, got %d", len(listed.Records))
	}
}
