package server

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// fakeS3 is a minimal path-style S3 endpoint serving GetObject and
// ListObjectsV2 over an in-memory bucket.
func fakeS3(t *testing.T, bucket string, objects map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == bucket {
			prefix := r.URL.Query().Get("prefix")
			var keys []string
			for k := range objects {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			type content struct {
				Key  string
				Size int
			}
			type result struct {
				XMLName  xml.Name `xml:"ListBucketResult"`
				Name     string
				Prefix   string
				KeyCount int
				MaxKeys  int
				Contents []content
			}
			res := result{Name: bucket, Prefix: prefix, KeyCount: len(keys), MaxKeys: 1000}
			for _, k := range keys {
				res.Contents = append(res.Contents, content{Key: k, Size: len(objects[k])})
			}
			w.Header().Set("Content-Type", "application/xml")
			_ = xml.NewEncoder(w).Encode(res)
			return
		}
		key, ok := strings.CutPrefix(path, bucket+"/")
		body, found := objects[key]
		if !ok || !found {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetS3BlobKeyLayouts(t *testing.T) {
	t.Parallel()

	const (
		did  = "did:plc:oisofpd7lj26yvgiivf3lxsi"
		cstr = "bafkreifq2pczayel2ljghsigxe4bbf7vkwucrtcqtjpmr532o7t65ev2wa"
	)
	c := mustCid(t, cstr)

	tests := []struct {
		name    string
		objects map[string]string
		want    string
		wantErr bool
	}{
		{
			name:    "flat key",
			objects: map[string]string{"blobs/" + did + "/" + cstr: "flat"},
			want:    "flat",
		},
		{
			name:    "key nested under a cid directory",
			objects: map[string]string{"blobs/" + did + "/" + cstr + "/8c8119e0dcc22e219c27ca3082fa3e59": "nested"},
			want:    "nested",
		},
		{
			name: "flat key preferred over nested",
			objects: map[string]string{
				"blobs/" + did + "/" + cstr:                                       "flat",
				"blobs/" + did + "/" + cstr + "/8c8119e0dcc22e219c27ca3082fa3e59": "nested",
			},
			want: "flat",
		},
		{
			name:    "other blobs do not match",
			objects: map[string]string{"blobs/" + did + "/" + cstr + "x/abc": "other", "blobs/did:plc:other/" + cstr + "/abc": "other"},
			wantErr: true,
		},
		{
			name:    "missing",
			objects: map[string]string{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := fakeS3(t, "bucket", tc.objects)
			s := newTestServer(t)
			s.s3Config = &S3Config{
				BlobstoreEnabled: true,
				Endpoint:         srv.URL,
				Region:           "us-east-1",
				Bucket:           "bucket",
				AccessKey:        "k",
				SecretKey:        "s",
			}

			body, err := s.getS3Blob(context.Background(), did, c)
			if tc.wantErr {
				if err == nil {
					body.Close()
					t.Fatal("expected error")
				}
				if !isS3NoSuchKey(err) {
					t.Fatalf("expected NoSuchKey error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("getS3Blob: %v", err)
			}
			defer body.Close()
			got, _ := io.ReadAll(body)
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
