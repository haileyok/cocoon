package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
)

func TestInactiveRepoReads(t *testing.T) {
	s, account := endpointTestServer(t)
	s.repoman = NewRepoMan(s)
	blob, record := blobRecord(t, "staged media")
	root, blocks, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/one"}, record)
	if code, msg := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, blocks))); code != 200 {
		t.Fatalf("import: %d %s", code, msg)
	}
	uploadTestBlob(t, s, account, "staged media")
	cache := identity.NewMemCache(10)
	if err := cache.PutDoc(account.Did, &identity.DidDoc{Id: account.Did}); err != nil {
		t.Fatal(err)
	}
	s.passport = identity.NewPassport(nil, cache)
	owner, err := s.createSession(context.Background(), &mustRepoActor(t, s, account.Did).Repo)
	if err != nil {
		t.Fatal(err)
	}
	other := s.createTestAccount(t, "other.pds.test")
	stranger, err := s.createSession(context.Background(), &mustRepoActor(t, s, other.Did).Repo)
	if err != nil {
		t.Fatal(err)
	}
	s.config.AdminPassword = "test-admin-password"
	for _, inactive := range []bool{false, true} {
		if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Update("deactivated", inactive).Error; err != nil {
			t.Fatal(err)
		}
		for _, endpoint := range []string{
			"sync.getRepo?did=" + account.Did,
			"sync.getRecord?did=" + account.Did + "&collection=app.bsky.feed.post&rkey=one",
			"sync.getBlocks?did=" + account.Did + "&cids=" + root.String(),
			"sync.getLatestCommit?did=" + account.Did,
			"sync.listBlobs?did=" + account.Did,
			"sync.getBlob?did=" + account.Did + "&cid=" + blob.String(),
			"repo.getRecord?repo=" + account.Did + "&collection=app.bsky.feed.post&rkey=one",
			"repo.listRecords?repo=" + account.Did + "&collection=app.bsky.feed.post",
			"repo.listRecords?repo=" + account.Handle + "&collection=app.bsky.feed.post",
			"repo.listRecords?repo=" + account.Handle + "&collection=app.bsky.feed.post&did=" + other.Did,
			"repo.describeRepo?repo=" + account.Did,
		} {
			for _, auth := range []string{"anonymous", "owner", "other", "refresh", "invalid", "admin"} {
				t.Run(endpoint+"/"+auth+map[bool]string{true: "/inactive", false: "/active"}[inactive], func(t *testing.T) {
					r := httptest.NewRequest("GET", "/xrpc/com.atproto."+endpoint, nil)
					switch auth {
					case "owner":
						r.Header.Set("Authorization", "Bearer "+owner.AccessToken)
					case "other":
						r.Header.Set("Authorization", "Bearer "+stranger.AccessToken)
					case "refresh":
						r.Header.Set("Authorization", "Bearer "+owner.RefreshToken)
					case "invalid":
						r.Header.Set("Authorization", "Bearer invalid")
					case "admin":
						r.SetBasicAuth("admin", s.config.AdminPassword)
					}
					w := httptest.NewRecorder()
					s.echo.ServeHTTP(w, r)
					allowed := !inactive || (strings.HasPrefix(endpoint, "sync.") && (auth == "owner" || auth == "admin"))
					if allowed {
						if w.Code != 200 || w.Body.Len() == 0 {
							t.Fatalf("read: %d %s", w.Code, w.Body.String())
						}
						if strings.HasPrefix(endpoint, "sync.getBlob?") && w.Body.String() != "staged media" {
							t.Fatal("wrong blob payload")
						}
						switch {
						case strings.HasPrefix(endpoint, "repo.getRecord?"):
							var got ComAtprotoRepoGetRecordResponse
							if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
								t.Fatal(err)
							}
							if got.Uri != "at://"+account.Did+"/app.bsky.feed.post/one" || got.Value["embed"] == nil {
								t.Fatalf("wrong record: %s", w.Body.String())
							}
						case strings.HasPrefix(endpoint, "repo.listRecords?"):
							var got ComAtprotoRepoListRecordsResponse
							if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
								t.Fatal(err)
							}
							if len(got.Records) != 1 || got.Records[0].Uri != "at://"+account.Did+"/app.bsky.feed.post/one" {
								t.Fatalf("wrong records: %s", w.Body.String())
							}
						case strings.HasPrefix(endpoint, "repo.describeRepo?"):
							var got ComAtprotoRepoDescribeRepoResponse
							if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
								t.Fatal(err)
							}
							if got.Did != account.Did || len(got.Collections) != 1 || got.Collections[0] != "app.bsky.feed.post" {
								t.Fatalf("wrong description: %s", w.Body.String())
							}
						}
					} else if w.Code < 400 || w.Code >= 500 {
						t.Fatalf("rejection: %d %s", w.Code, w.Body.String())
					} else if auth == "anonymous" || auth == "other" || strings.HasPrefix(endpoint, "repo.") {
						var body map[string]string
						if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
							t.Fatal(err)
						}
						if body["error"] != "RepoDeactivated" {
							t.Fatalf("wrong error: %s", w.Body.String())
						}
					}
				})
			}
		}
	}
}

func TestInactiveSyncCredentials(t *testing.T) {
	for _, auth := range []string{"oauth-owner", "oauth-other", "oauth-no-proof", "revoked", "service", "bad-admin", "empty-admin"} {
		t.Run(auth, func(t *testing.T) {
			s, account := endpointTestServer(t)
			root, rev := s.seedGenesisRepo(t, account.Did, account.SigningKey)
			if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Update("deactivated", true).Error; err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/xrpc/com.atproto.sync.getLatestCommit?did="+account.Did, nil)
			switch auth {
			case "oauth-owner", "oauth-other", "oauth-no-proof":
				did := account.Did
				if auth == "oauth-other" {
					did = s.createTestAccount(t, "other.pds.test").Did
				}
				setProxyTestOAuth(t, s, r, did, "atproto")
				if auth == "oauth-no-proof" {
					r.Header.Del("DPoP")
				}
			case "revoked":
				session, err := s.createSession(context.Background(), &mustRepoActor(t, s, account.Did).Repo)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.db.Client().Where("token = ?", session.AccessToken).Delete(&models.Token{}).Error; err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			case "service":
				token := mintServiceAuthToken(t, account.SigningKey, account.Did, s.config.Did, "com.atproto.sync.getLatestCommit", time.Now().Add(time.Minute))
				r.Header.Set("Authorization", "Bearer "+token)
			case "bad-admin":
				s.config.AdminPassword = "correct"
				r.SetBasicAuth("admin", "wrong")
			case "empty-admin":
				s.config.AdminPassword = ""
				r.SetBasicAuth("admin", "")
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if auth == "oauth-owner" {
				var got ComAtprotoSyncGetLatestCommitResponse
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || got.Cid != root.String() || got.Rev != rev {
					t.Fatalf("owner read: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code < 400 || w.Code >= 500 {
				t.Fatalf("rejection: %d %s", w.Code, w.Body.String())
			}

			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, httptest.NewRequest("GET", "/xrpc/com.atproto.sync.getRepoStatus?did="+account.Did, nil))
			var status ComAtprotoSyncGetRepoStatusResponse
			if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || status.Active || status.Status == nil || *status.Status != "deactivated" {
				t.Fatalf("public status: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
