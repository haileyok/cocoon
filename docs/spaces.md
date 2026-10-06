# Spaces (permissioned data)

Cocoon implements the ATProto Spaces alpha: permissioned data that never
reaches the firehose. It tracks the reference implementation in
[bluesky-social/atproto PR #5187](https://github.com/bluesky-social/atproto/pull/5187)
at `5b95b2f2`. The lexicons are vendored unmodified in `lexicons/com/atproto/space`
and `lexicons/com/atproto/simplespace` (see `lexicons/SOURCE`). The alpha
changes often and has no backwards compatibility, so a format change upstream
replaces the old one here.

## What a space is

A space is a group's private data, addressed as
`at://{authority}/space/{spaceType}/{skey}`. Its authority (a DID) decides who
may read and write. Each member who writes keeps a space repo for it on their
own PDS, and the space is the union of those repos. A record in a space is
addressed as `at://{authority}/space/{spaceType}/{skey}/{author}/{collection}/{rkey}`.

A space repo is a flat set of records rather than an MST. Its commit signs an
LtHash set hash, with a fresh key per reader so a leaked commit proves nothing
to a third party. Syncers pull a repo's changes with `listRepoOps` and its full
state with `getRepo` (a two-root CAR: the commit, then the index).

## Roles Cocoon plays

- **Repo host**: an account's own space repos. The account writes with
  `com.atproto.space.createRecord`, `putRecord`, `deleteRecord` and
  `applyWrites`, and reads its own repo with `getRecord`, `listRecords`,
  `listRepoOps`, `getLatestCommit`, `getRepo`, `getBlob` and `listBlobs`.
  Reading another member's repo takes a space credential.
- **Simplespace host**: spaces an account governs, anchored on its own DID.
  This covers `com.atproto.simplespace.createSpace`, `getSpace`, `updateSpace`,
  `deleteSpace`, `putMember`, `removeMember` and `listMembers`. Read and write
  policies can be public, member-list or managing-app, and app access can be
  open or an allow-list checked against client attestations.
- **Credentials**: `getDelegationToken` mints a 60-second token on the
  member's own PDS. The authority exchanges it at `getSpaceCredential` for a
  10-minute credential bound to the P-256 key that signed the exchange. Reads
  then present the credential with an HTTP message signature naming the
  audience repo. `notifyCredentialRevoked` lets an authority revoke
  credentials at repo hosts.
- **Sync**: after each commit, a writer's PDS sends `notifyWrite` to the
  authority. The authority records the writer with a `spaceRev`, serves the
  writer set from `listRepos`, and forwards notifications to services
  registered with `registerNotify`. A notification that fails retryably is
  queued and resent with backoff for up to a day.

## OAuth

Apps reach space data through `space:` scopes, for example
`space:com.example.group?authority=self&collection=*`. An omitted authority
means the user's own spaces. A grant with no collection permits no writes,
and `read` covers whole-space reads while `read_self` covers only the user's
own repo. When a token is issued, a bare `space:<type>` grant gains the
collections the type's lexicon declaration lists. The consent page describes
space grants in plain language.

Password sessions can also write and read the account's own space repos, as in
the reference.

## Where Cocoon differs from the reference

- **No app passwords.** Cocoon has none, so the reference's app-password
  cases don't apply.
- **Record validation.** The reference validates space records against its
  bundled schemas. Cocoon has no lexicon catalog, so a validated space write
  always reports `unknown`, and `validate: true` refuses it. Every space
  collection in the reference's tests behaves the same way.
- **Public blob sync.** With Spaces, the reference serves a blob over
  `com.atproto.sync.getBlob` only if a public record references it. Cocoon
  refuses only blobs that space records alone reference, so an upload is still
  served before any record names it.
- **Takedowns.** Cocoon has a takedown flag on accounts (`takedown_ref`) but
  no admin API to set it yet. A taken-down account's space repos aren't served
  and it can't write or mint delegation tokens, as in the reference.
- **One retry worker.** The reference elects a notification retry worker with
  a lease. Cocoon runs a single worker in process.
- **Unresolvable space type.** The reference refuses to issue a token when a
  bare `space:<type>` grant's declaration can't be resolved. Cocoon issues the
  grant unchanged, which permits no writes.

## Tests

The reference's Spaces test suites are ported case by case. Each Go test names
the reference case it ports.

| Reference suite | Go tests |
|---|---|
| `packages/space` unit tests (set hash, commits, tokens, HTTP signatures, repo CAR) | `internal/space/*_test.go`, plus reference-generated vectors and an export CAR in `internal/space/testdata` |
| `oauth-scopes` `space-permission.test.ts` | `oauth/scopes/space_test.go` |
| `pds/tests/space/records.test.ts` | `server/space_records_test.go`, `server/space_blobs_test.go` |
| `pds/tests/space/auth.test.ts` | `server/space_auth_test.go` |
| `pds/tests/space/simplespace.test.ts` | `server/space_simplespace_test.go` |
| `pds/tests/space/sync.test.ts` | `server/space_sync_test.go` |
| `pds/tests/space/notifications.test.ts` | `server/space_notifications_test.go` |
| `pds/tests/space-scope.test.ts` | `server/space_scope_test.go` |
| `pds/tests/client-attestation.test.ts` | `server/space_attestation_test.go` |

The server tests run on a network of in-process PDSes sharing one in-memory DID
directory (`server/space_net_test.go`, `server/space_net_creds_test.go`), the
counterpart of the reference's `tests/_space.ts`.

Cases that don't apply, each noted in its test file: the two app-password
cases, the revocation cases that mock the clock or a background queue, the
writer-state migration, the retry-worker lease, and the upstream `it.todo` for
oplog pruning.
