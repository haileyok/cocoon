package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
)

func repoSwapRequest(t *testing.T, did, token, endpoint string, body map[string]any) *http.Request {
	t.Helper()
	body["repo"] = did
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/xrpc/com.atproto.repo."+endpoint, bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestRepoSwapPreconditions(t *testing.T) {
	for _, endpoint := range []string{"createRecord", "putRecord", "deleteRecord", "applyWrites"} {
		for _, field := range []string{"swapCommit", "swapRecord"} {
			if field == "swapRecord" && endpoint == "applyWrites" {
				continue
			}
			for _, mode := range []string{"omitted", "matching", "other-encoding", "stale", "null", "empty", "malformed", "wrong-type", "missing-matching", "missing-null", "unchanged-stale"} {
				if field == "swapCommit" && (mode == "missing-matching" || mode == "missing-null" || mode == "unchanged-stale") {
					continue
				}
				t.Run(endpoint+"/"+field+"/"+mode, func(t *testing.T) {
					s, account := endpointTestServer(t)
					s.repoman = NewRepoMan(s)
					_, record := blobRecord(t, "original media")
					root, blocks, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/existing"}, record)
					if code, msg := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, blocks))); code != 200 {
						t.Fatalf("import: %d %s", code, msg)
					}
					uploadTestBlob(t, s, account, "original media")
					manager, persister := newTestEvtmanPersister(t)
					s.evtman = manager
					session, err := s.createSession(context.Background(), &mustRepoActor(t, s, account.Did).Repo)
					if err != nil {
						t.Fatal(err)
					}
					head := currentRoot(t, s, account.Did)
					recordCID := walkMstLeaves(t, s, account.Did)["app.bsky.feed.post/existing"]
					matching, stale := head, recordCID
					if field == "swapRecord" {
						matching, stale = recordCID, head
					}
					key := "existing"
					if mode == "missing-matching" || mode == "missing-null" {
						key = "new"
					}
					body := map[string]any{"collection": "app.bsky.feed.post", "rkey": key, "record": postRecord("replacement")}
					if mode == "unchanged-stale" {
						body["record"] = record
					}
					if endpoint == "applyWrites" {
						body = map[string]any{"writes": []any{
							map[string]any{"$type": OpTypeCreate, "collection": "app.bsky.feed.post", "rkey": "new", "value": postRecord("new")},
							map[string]any{"$type": OpTypeDelete, "collection": "app.bsky.feed.post", "rkey": "existing"},
						}}
					}
					if endpoint != "applyWrites" {
						if field == "swapRecord" {
							body["swapCommit"] = head.String()
						} else {
							body["swapRecord"] = recordCID.String()
						}
					}
					wantError := ""
					switch mode {
					case "matching", "missing-matching":
						body[field] = matching.String()
						if mode == "missing-matching" {
							wantError = "InvalidSwap"
						}
					case "other-encoding":
						encoded, err := matching.StringOfBase(multibase.Base58BTC)
						if err != nil {
							t.Fatal(err)
						}
						body[field] = encoded
					case "stale", "unchanged-stale":
						body[field], wantError = stale.String(), "InvalidSwap"
					case "null", "missing-null":
						body[field], wantError = nil, "InvalidRequest"
						if endpoint == "putRecord" && field == "swapRecord" {
							wantError = "InvalidSwap"
							if mode == "missing-null" {
								wantError = ""
							}
						}
					case "empty":
						body[field], wantError = "", "InvalidRequest"
					case "malformed":
						body[field], wantError = "not-a-cid", "InvalidRequest"
					case "wrong-type":
						body[field], wantError = 7, "InvalidRequest"
					}
					before := importState(t, s, account.Did)
					w := httptest.NewRecorder()
					s.echo.ServeHTTP(w, repoSwapRequest(t, account.Did, session.AccessToken, endpoint, body))
					if wantError != "" {
						var got struct{ Error string }
						if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
							t.Fatal(err)
						}
						if w.Code != 400 || got.Error != wantError {
							t.Fatalf("got %d %s, want 400 %s", w.Code, w.Body.String(), wantError)
						}
						if !reflect.DeepEqual(before, importState(t, s, account.Did)) {
							t.Fatal("rejected swap changed repository or blob state")
						}
						if _, _, ok, err := persister.EventSeqRange(context.Background()); err != nil || ok {
							t.Fatalf("rejected swap published an event: %v", err)
						}
						return
					}
					if w.Code != 200 {
						t.Fatalf("write: %d %s", w.Code, w.Body.String())
					}
					leaves := walkMstLeaves(t, s, account.Did)
					if endpoint == "deleteRecord" || endpoint == "applyWrites" {
						if _, exists := leaves["app.bsky.feed.post/existing"]; exists {
							t.Fatal("record was not deleted")
						}
					} else if got := leaves["app.bsky.feed.post/"+key]; !got.Defined() || got.Equals(recordCID) {
						t.Fatal("record was not written")
					}
					if endpoint == "applyWrites" && !leaves["app.bsky.feed.post/new"].Defined() {
						t.Fatal("batch did not create the new record")
					}
				})
			}
		}
	}
}

func TestRepoSwapConcurrentWrites(t *testing.T) {
	for _, field := range []string{"swapCommit", "swapRecord"} {
		t.Run(field, func(t *testing.T) {
			s, account := endpointTestServer(t)
			s.repoman = NewRepoMan(s)
			s.evtman = newTestEvtman(t)
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			mustApply(t, s, account.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("existing"), Record: rmPostRecord("original")})
			expected := currentRoot(t, s, account.Did)
			if field == "swapRecord" {
				expected = walkMstLeaves(t, s, account.Did)["app.bsky.feed.post/existing"]
			}
			session, err := s.createSession(context.Background(), &mustRepoActor(t, s, account.Did).Repo)
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			type response struct {
				w         *httptest.ResponseRecorder
				key, text string
			}
			responses := make(chan response, 2)
			for _, text := range []string{"first", "second"} {
				key := "existing"
				if field == "swapCommit" {
					key = text
				}
				r := repoSwapRequest(t, account.Did, session.AccessToken, "putRecord", map[string]any{
					"collection": "app.bsky.feed.post", "rkey": key, "record": postRecord(text), field: expected.String(),
				})
				go func() {
					<-start
					w := httptest.NewRecorder()
					s.echo.ServeHTTP(w, r)
					responses <- response{w, key, text}
				}()
			}
			close(start)
			a, b := <-responses, <-responses
			if a.w.Code != 200 {
				a, b = b, a
			}
			var rejected struct{ Error string }
			if err := json.Unmarshal(b.w.Body.Bytes(), &rejected); err != nil {
				t.Fatal(err)
			}
			if a.w.Code != 200 || b.w.Code != 400 || rejected.Error != "InvalidSwap" {
				t.Fatalf("expected one successful write and one InvalidSwap: %d %s; %d %s", a.w.Code, a.w.Body.String(), b.w.Code, b.w.Body.String())
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, httptest.NewRequest("GET", "/xrpc/com.atproto.repo.getRecord?repo="+account.Did+"&collection=app.bsky.feed.post&rkey="+a.key, nil))
			var got ComAtprotoRepoGetRecordResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || got.Value["text"] != a.text {
				t.Fatalf("winning write was not retained: %d %s", w.Code, w.Body.String())
			}
			if field == "swapCommit" && walkMstLeaves(t, s, account.Did)["app.bsky.feed.post/"+b.key].Defined() {
				t.Fatal("losing write was stored")
			}
		})
	}
}
