package server

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
)

func TestListMissingBlobsPagination(t *testing.T) {
	for _, limit := range []string{"1", "2", "500", ""} {
		t.Run("limit="+limit, func(t *testing.T) {
			s := newTestServer(t)
			account := s.createTestAccount(t, "missing.pds.test")
			other := s.createTestAccount(t, "other.pds.test")
			count := 5
			if limit == "500" || limit == "" {
				count = 503
			}
			values := make(map[string][]byte)
			var all []string
			for i := range count {
				c, record := blobRecord(t, fmt.Sprintf("payload-%d", i))
				value, err := atdata.MarshalCBOR(map[string]any(record))
				if err != nil {
					t.Fatal(err)
				}
				all = append(all, c.String())
				values[c.String()] = value
			}
			sort.Strings(all)
			uris := make(map[string]map[string]bool)
			var records []models.Record
			for i := count - 1; i >= 0; i-- {
				for duplicate := range 2 {
					rkey := fmt.Sprintf("%04d-%d", count-i, duplicate)
					records = append(records, models.Record{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: rkey, Value: values[all[i]]})
					if uris[all[i]] == nil {
						uris[all[i]] = make(map[string]bool)
					}
					uris[all[i]]["at://"+account.Did+"/app.bsky.feed.post/"+rkey] = true
				}
			}
			if err := s.db.Client().CreateInBatches(records, 100).Error; err != nil {
				t.Fatal(err)
			}
			present, err := cid.Decode(all[1])
			if err != nil {
				t.Fatal(err)
			}
			foreign, err := cid.Decode(all[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Create(&[]models.Blob{{Did: account.Did, Cid: present.Bytes()}, {Did: other.Did, Cid: foreign.Bytes()}}).Error; err != nil {
				t.Fatal(err)
			}
			want := append([]string{all[0]}, all[2:]...)
			var got []string
			cursor := ""
			for page := 0; ; page++ {
				if page > count {
					t.Fatal("pagination did not terminate")
				}
				c, w := newRequestContext("GET", "/xrpc/com.atproto.repo.listMissingBlobs?limit="+limit+"&cursor="+url.QueryEscape(cursor), "", nil)
				c.Set("repo", mustRepoActor(t, s, account.Did))
				if err := s.handleListMissingBlobs(c); err != nil || w.Code != 200 {
					t.Fatalf("list: %d %s %v", w.Code, w.Body.String(), err)
				}
				var response ComAtprotoRepoListMissingBlobsResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				pageSize := map[string]int{"1": 1, "2": 2, "500": 500, "": 500}[limit]
				if len(response.Blobs) > pageSize {
					t.Fatalf("page exceeds limit: %d > %d", len(response.Blobs), pageSize)
				}
				for _, blob := range response.Blobs {
					got = append(got, blob.Cid)
					if !uris[blob.Cid][blob.RecordUri] {
						t.Fatalf("incorrect record URI: %+v", blob)
					}
				}
				if response.Cursor == nil {
					break
				}
				if *response.Cursor <= cursor {
					t.Fatal("cursor did not advance")
				}
				cursor = *response.Cursor
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("missing CIDs: got %v; want %v", got, want)
			}
		})
	}
}

func TestListMissingBlobsLookupError(t *testing.T) {
	s := newTestServer(t)
	account := s.createTestAccount(t, "missing.pds.test")
	_, record := blobRecord(t, "missing")
	insertTestRecord(t, s, account.Did, "app.bsky.feed.post", "one", map[string]any(record))
	if err := s.db.Client().Migrator().DropTable(&models.Blob{}); err != nil {
		t.Fatal(err)
	}
	c, w := newRequestContext("GET", "/xrpc/com.atproto.repo.listMissingBlobs", "", nil)
	c.Set("repo", mustRepoActor(t, s, account.Did))
	if err := s.handleListMissingBlobs(c); err != nil {
		t.Fatal(err)
	}
	if w.Code != 500 {
		t.Fatalf("lookup failure: %d %s", w.Code, w.Body.String())
	}
}
