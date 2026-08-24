---
name: run-atproto-tests
description: Validate Cocoon's experimental Atproto Spaces implementation against the pinned atproto reference and test suites.
---

# Run the atproto reference tests

Use this skill when validating Cocoon's `com.atproto.space` or
`com.atproto.simplespace` implementation.

## Reference selection

Cocoon's Spaces alpha is pinned to atproto PR #5187:

- Repository: `https://github.com/bluesky-social/atproto`
- Commit: `89deb9faca20e56fa2a262fe9746ed52bc1095ba`
- Cocoon fixture manifest: `testdata/spaces-alpha/SHA256SUMS`

Do not use current atproto `main` as the protocol comparison target without
checking first. The current `main` may not contain the Spaces implementation.
Use current `main` for drift awareness, and the pinned commit for compatibility.

## Worktrees and setup

Keep the Cocoon PR worktree read-only while comparing it. Prepare the atproto
reference in a separate worktree:

```bash
mkdir -p ~/worktrees/atproto
GIT_CONFIG_GLOBAL=/dev/null git -C ~/bluesky/atproto fetch \
  https://github.com/bluesky-social/atproto.git \
  89deb9faca20e56fa2a262fe9746ed52bc1095ba:refs/remotes/origin/private-spaces-reference \
  --no-tags
git -C ~/bluesky/atproto worktree add --detach \
  ~/worktrees/atproto/private-spaces-reference \
  89deb9faca20e56fa2a262fe9746ed52bc1095ba
cd ~/worktrees/atproto/private-spaces-reference
pnpm install --frozen-lockfile
```

Build the relevant dependency closures before running tests:

```bash
pnpm --filter @atproto/space... build
pnpm --filter @atproto/pds... build
pnpm --filter @atproto/dev-env... build
```

## Fixture integrity

The copied Lexicons and selected helper files must match the pinned commit.
The manifest paths are relative to Cocoon's fixture directory; strip
`testdata/spaces-alpha/` before looking up Lexicons, and strip `reference/`
when looking up selected helper source files. A mismatch means the wire
contract has changed and must be reviewed before changing implementation code.

At minimum run:

```bash
cd ~/worktrees/cocoon/private-spaces
go test ./space -run 'TestSpaces(ReadmeContract|FixtureManifestMatchesProtocolTypes|AlphaReferenceCommitPinned)$'
```

## Cocoon checks

Run from the Cocoon Spaces worktree with CGO enabled:

```bash
CGO_ENABLED=1 go test -count=1 ./...
CGO_ENABLED=1 go vet ./...
CGO_ENABLED=1 go build ./...
CGO_ENABLED=1 go test -count=1 -race ./...
```

Also check formatting and patch whitespace:

```bash
go_files=$( { git diff --name-only --diff-filter=ACM -- '*.go'; git ls-files --others --exclude-standard -- '*.go'; } | sort -u )
if [ -n "$go_files" ]; then
  printf '%s\n' "$go_files" | xargs -r gofmt -l
fi
git diff --check
```

The optional PostgreSQL tests require a reachable DSN:

```bash
COCOON_TEST_POSTGRES_DSN='postgres://...' \
  go test ./server -run 'TestPostgresSpaceRepo'
```

## Direct reference-client checks against Cocoon

The upstream `TestNetworkNoAppView` harness always creates in-process TypeScript
PDS instances; it does not accept an external PDS URL. Cocoon therefore has a
separate generated-client interop runner that starts Cocoon, seeds disposable
accounts, obtains real Cocoon session JWTs, and uses the pinned atproto
`@atproto/lex` client plus generated Space Lexicons over HTTP:

```bash
cd ~/worktrees/cocoon/private-spaces
ATPROTO_ROOT=~/worktrees/atproto/private-spaces-reference \
  ./interop/atproto/run.sh
```

This is the required Cocoon-backed check for the reference wire contract. It
covers Space creation, membership, owner metadata access, record create/read,
listRecords, getLatestCommit, listRepoOps including nullable fields and cursor
format, deletion, listSpaces, and non-owner authorization. The runner files are
`interop/atproto/reference-client.mjs`, `interop/atproto/run.sh`, and the
throwaway account seeder under `interop/atproto/seed/`. GitHub Actions runs the
same check in `.github/workflows/atproto-interop.yml`.

## atproto Spaces checks

Run the pure cross-language primitive tests:

```bash
cd ~/worktrees/atproto/private-spaces-reference
pnpm --filter @atproto/space test
```

Run the focused PDS Spaces suite with the repository's PostgreSQL/Redis
harness:

```bash
./packages/dev-infra/with-test-redis-and-db.sh \
  pnpm --filter @atproto/pds test:sqlite -- \
  tests/space tests/space-scope.test.ts --runInBand
```

Run all non-browser PDS tests:

```bash
NODE_OPTIONS=--experimental-vm-modules \
  ./packages/dev-infra/with-test-redis-and-db.sh \
  pnpm --filter @atproto/pds exec jest --runInBand \
  --testPathIgnorePatterns='(oauth|account-manager)\\.test\\.ts'
```

The full PDS suite is useful, but its OAuth and account-manager browser tests
need Chromium sandbox support. A host may report `No usable sandbox` even when
all application tests pass.

## Browser tests on restricted Linux hosts

If Chromium cannot use the host user namespace sandbox, create a temporary
wrapper outside the repository or in an ignored temporary path. The wrapper
must execute the Puppeteer-managed Chrome binary with `--no-sandbox`:

```sh
#!/bin/sh
exec /path/to/puppeteer/chrome --no-sandbox "$@"
```

Find the managed binary with:

```bash
find ~/.cache/puppeteer/chrome -type f -name chrome -perm -u+x -print
```

Then run only the browser suites with the wrapper selected explicitly:

```bash
PUPPETEER_EXECUTABLE_PATH=/path/to/chrome-no-sandbox \
  NODE_OPTIONS=--experimental-vm-modules \
  ./packages/dev-infra/with-test-redis-and-db.sh \
  pnpm --filter @atproto/pds exec jest --runInBand \
  tests/oauth.test.ts tests/account-manager.test.ts
```

Remove the wrapper afterward. Do not commit it.

## Interpreting failures

- A failure in `@atproto/space` or `packages/pds/tests/space/**` is relevant to
  Spaces compatibility.
- A missing generated `dist` module in a fresh worktree means the dependency
  closure was not built yet.
- A Chromium `No usable sandbox` error is an environment failure; rerun with
  the temporary wrapper before classifying browser behavior.
- The historical pinned commit may have unrelated stale monorepo tests or
  generated-output failures. Record those separately from the focused Spaces
  and PDS results.
- Prefer tests that decode raw JSON with the pinned Lexicon shape instead of
  only unmarshalling Cocoon's own response structs.
