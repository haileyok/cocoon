# AGENTS.md

Guidance for working on cocoon, focused on how tests work here.

## Running tests

```bash
make test          # go clean -testcache && go test -v ./...
go test ./...      # quick, uses the test cache
go test -race ./...# what CI runs
```

Tests **require CGO and a C compiler.** The SQLite driver (`gorm.io/driver/sqlite`,
backed by `mattn/go-sqlite3`) is a cgo package, so anything that opens a database
will fail to build with `CGO_ENABLED=0`. CI sets `CGO_ENABLED=1` explicitly; locally
it just needs `gcc`/`cc` on PATH (the Go default).

Other useful targets:

```bash
make check         # go build ./...   (compile only)
make lint          # go vet ./... + gofmt check
make fmt           # go fmt ./...
```

Keep `gofmt` and `go vet ./...` clean before pushing.

## How tests are organized

- Tests live next to the code they cover as `*_test.go`.
- Server tests are **white-box** (`package server`): `Server` and its `config` have
  unexported fields, so tests must be in-package to construct and drive them.

## The test harness

`server/testutil_test.go` provides the shared building blocks. Use these instead of
standing up your own database or echo context:

- `newTestServer(t)` — a `*Server` backed by a fresh temp SQLite DB (`t.TempDir()`),
  the production `AutoMigrate` list, a generated ES256 key, and a minimal `config`.
  Network collaborators (`plcClient`, `passport`, `oauthProvider`, `mail`) are left
  **nil**; set them in your test if the path under test needs one.
- `newRequestContext(method, target, body, headers)` — an `echo.Context` wired with
  the same custom validator as `New()`, so handlers that call `e.Validate` behave as
  in production. Body defaults to JSON content-type; override via `headers`.
- `createTestAccount(t, handle)` — inserts a `Repo`+`Actor` with a known password and
  a fresh k256 signing key, returning a descriptor for token/auth tests.

### Patterns

- **One DB per test** comes for free via `newTestServer` (`t.TempDir()`); no manual
  cleanup needed.
- **Exercising a handler:** build a context with `newRequestContext`, call the handler
  method directly, then assert on the `*httptest.ResponseRecorder` and/or the DB. For
  middleware, wrap a trivial `next` that records whether it ran.
- **Code paths that need a collaborator:** set the field on the test server. For
  example, OAuth token tests construct a `provider.NewProvider(...)` and assign it to
  `s.oauthProvider`; a `http://localhost` client gets virtual metadata with no network.
- **Concurrency tests:** SQLite serializes writes, so to test logic (not lock
  contention) pin the pool to one connection:
  `sqlDB, _ := s.db.Client().DB(); sqlDB.SetMaxOpenConns(1)`.

## Conventions

- **Write the test first.** Add a failing test, confirm it's red for the expected
  reason, then implement until it's green. Reproduce panics/races in a test before
  fixing them where feasible.
- Prefer extracting small, pure helpers (e.g. claim/verify functions) when a fix lives
  deep inside a large handler — they're far easier to test than the whole request path.
- New security-sensitive randomness uses `crypto/rand` (see `internal/helpers`), never
  `math/rand`.

## CI

`.github/workflows/go-test.yml` runs `go vet ./...` and `go test -race ./...` (CGO on)
on every pull request and on pushes to `main`. Keep it green.
