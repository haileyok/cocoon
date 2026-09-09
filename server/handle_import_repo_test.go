package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

// importRepo reads the request body with io.ReadAll. Without a size cap, an
// authenticated user can stream an arbitrarily large body and balloon the
// process heap. The uploadBlob endpoint caps uploads at 100 MB; importRepo
// must enforce the same cap and reject oversized bodies without buffering
// them.

// importRepoMaxBodyBytes is defined in handle_import_repo.go (100 MB).

func callImportRepo(t *testing.T, s *Server, acct *testAccount, body io.Reader) (int, string) {
	t.Helper()
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.importRepo", "", map[string]string{"content-type": "application/octet-stream"})
	c.Request().Body = io.NopCloser(body)
	repo, err := s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	c.Set("repo", repo)
	if err := s.handleRepoImportRepo(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

// TestImportRepoRejectsOversizedBody: a body exceeding the import cap must be
// rejected with 413. The body is larger than the cap (cap + 1 MiB of 'A's), so
// a handler that reads it unboundedly would buffer past the limit; the cap
// must cut it off first.
func TestImportRepoRejectsOversizedBody(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	oversized := io.LimitReader(newInfiniteReader(), importRepoMaxBodyBytes+(1<<20))
	code, _ := callImportRepo(t, s, acct, oversized)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized import body, got %d", code)
	}
}

// TestImportRepoAcceptsSmallBody: a tiny (invalid CAR but size-in-bounds) body
// must not trip the size cap — it should fail for CAR reasons, not 413.
func TestImportRepoAcceptsSmallBody(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")

	code, _ := callImportRepo(t, s, acct, strings.NewReader("not a car"))
	if code == http.StatusRequestEntityTooLarge {
		t.Fatalf("small body unexpectedly rejected with 413, got %d", code)
	}
}

// infiniteReader produces an endless stream of bytes without holding them in
// memory, so an unbounded handler would never finish reading.
type infiniteReader struct{}

func newInfiniteReader() *infiniteReader { return &infiniteReader{} }

func (i *infiniteReader) Read(p []byte) (int, error) {
	for j := range p {
		p[j] = 0x41
	}
	return len(p), nil
}

var (
	_ = bytes.MinRead
	_ = errors.Is
	_ = helpers.InputError
	_ = models.TwoFactorTypeNone
	_ = echo.MIMEOctetStream
)
