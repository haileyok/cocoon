# Atproto Spaces alpha compatibility fixture

Cocoon's experimental Spaces implementation targets the following immutable upstream snapshot:

- Proposal: `bluesky-social/proposals/0016-permissioned-data` as reviewed on 2026-08-21
- Reference repository: `bluesky-social/atproto`
- Reference commit: `89deb9faca20e56fa2a262fe9746ed52bc1095ba`
- Reference PR: https://github.com/bluesky-social/atproto/pull/5187

The `lexicons/` directory is copied byte-for-byte from that commit. The selected files under `reference/` are retained solely as interoperability references for tests and review. The current `SHA256SUMS` has one `SHA-256-digest  repository-relative-path` entry for each of the 35 copied upstream Lexicons/reference files. It deliberately excludes `SHA256SUMS` itself and this explanatory document. `space/compatibility_test.go` recomputes every listed digest, so a changed fixture fails deterministically instead of silently changing the wire contract.

Spaces provide access control, not encryption or confidentiality. These fixtures and the resulting implementation are unsuitable for sensitive or production data. The fixture pin is not a claim of complete external interoperability.

## Compatibility update checklist

This target is alpha software. Updating it is an intentional compatibility change:

1. Select one new immutable upstream atproto commit; do not mix files from multiple proposal revisions.
2. Replace the copied `lexicons/` and selected `reference/` files from that commit only.
3. Regenerate `SHA256SUMS` with SHA-256 paths relative to the repository root, and confirm the manifest excludes itself and this document.
4. Update the reference SHA, compatibility version, this document, and the detailed Spaces guide together.
5. Regenerate and review cross-language vectors for token, DPoP, LtHash, signed commit, CAR, and sync behavior.
6. Review all changed Lexicons for route names, auth requirements, closed unions, notification payloads, and blob visibility semantics before changing Cocoon code.
7. Run the manifest/reference tests, the documentation contract test, `go test ./...`, and the repository diff/ownership check.

Known compatibility hazards:

- The proposal specifies HKDF-Expand-only for commit MAC keys; verify the pinned TypeScript helper's exact semantics with cross-language vectors before implementing signed commits.
- Dedicated `#atproto_space` key behavior and comments in the pinned branch are not fully aligned.
- The pinned notification registration Lexicon accepts `{space, service}` and has no repo parameter; Cocoon follows the pinned Lexicon.
- There is no complete Space import API; `getRepo` is an authenticated current-state CAR recovery/export path, not a general migration importer.

## Minimal local checks

The fixture and README checks do not need a running database:

```bash
go test ./space -run 'TestSpaces(ReadmeContract|FixtureManifestMatchesProtocolTypes|AlphaReferenceCommitPinned)$'
go test ./...
```

The opt-in PostgreSQL Space tests use an isolated schema. Supply a reachable PostgreSQL DSN as `COCOON_TEST_POSTGRES_DSN`:

```bash
COCOON_TEST_POSTGRES_DSN='postgres://cocoon:password@localhost:5432/cocoon?sslmode=disable' \
  go test ./server -run 'TestPostgresSpaceRepo'
```
