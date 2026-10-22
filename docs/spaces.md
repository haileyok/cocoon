# Spaces (permissioned data)

Cocoon implements the ATProto Spaces alpha: permissioned data that never
reaches the firehose. It tracks the reference implementation's October 22,
2026 alpha (`permissioned-data-alpha` at `ac0c9f15`, published as
`0.0.0-spaces-alpha-20261022141228`). The lexicons are vendored unmodified in `lexicons/com/atproto/space`
and `lexicons/com/atproto/simplespace` (see `lexicons/SOURCE`). The alpha
changes often and has no backwards compatibility, so a format change upstream
replaces the old one here.

## What a space is

A space is a group's private data, addressed as
`at://{authority}/space/{spaceType}/{skey}`. Its authority (a DID) decides who
may read and write. Each member who writes keeps a space repo for it on their
own PDS, and the space is the union of those repos. A record in a space is
addressed as `at://{authority}/space/{spaceType}/{skey}/{author}/{collection}/{rkey}`.

A space repo is a flat set of records rather than an MST. Its commit names the
repo, space and rev and carries the digest of an LtHash set hash (`data`), but
no signature. Instead the repo host authenticates each commit or record it
serves with an HMAC keyed by a per-request shared secret, so a leaked response
proves nothing to a third party. Syncers pull a repo's changes with
`listRepoOps` and its full state with `getRepo` (a STAR archive: the commit as
metadata, then each record in path order).

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
  member's own PDS. A caller asks the authority's `getSpaceCredential` for a
  10-minute credential bound to a P-256 key it names (`credentialKid`),
  sending the delegation token and a client attestation in the request body
  when the space requires them. A space with a public read policy issues one
  without a delegation token. Reads then present the credential
  (`Authorization: Atproto-Space-Credential ...`) with an HTTP message
  signature naming the audience repo. `notifyCredentialRevoked` lets an
  authority revoke credentials at repo hosts.
- **MACs**: each account has a dedicated P-256 `#atproto_kem` key, published
  in its genesis PLC operation. A syncer reading with a credential sends an
  ephemeral key share in `Atproto-Space-Want-Mac`. `getLatestCommit`,
  `getRepo`, `listRepoOps` and `getRecord` answer with an HMAC of the commit or
  record in `Atproto-Space-Mac`, keyed by the DHKEM(P-256, HKDF-SHA256) shared
  secret. Accounts created before KEM keys existed get one from a background
  backfill at startup, which publishes it to PLC when this PDS holds a rotation
  key for the account and is its current PDS. Otherwise the account must
  publish the key itself, from `getRecommendedDidCredentials`.
- **Sync**: after each commit, a writer's PDS sends `notifyWrite` to the
  authority. The authority records the writer with a `spaceRev`, serves the
  writer set from `listRepos`, and forwards notifications to services
  registered with `registerNotify`. A notification that fails retryably is
  queued and resent with backoff for up to a day. Deleting a space sends
  `notifySpaceDeleted` to every registered service, retrying until delivery
  succeeds or the registration expires.

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
- **One retry worker.** The reference elects a notification retry worker and a
  KEM key backfill worker with leases. Cocoon runs each once in process.
- **Stored field names.** The protocol renamed a commit's `hash` to `data`.
  Cocoon's `space_writers.hash` and `space_notification_retries.hash` columns
  keep their names, so no data migration was needed.
- **Outbound requests.** Managing-app checks and notifications go to
  endpoints that DID documents name. Cocoon sends them with its SSRF-guarded
  client, which refuses private and loopback addresses. The reference uses a
  plain fetch.
- **One process per database.** Like Cocoon's public repo writes, space writes
  and blob cleanup are serialized per account within one process. Running
  several Cocoon instances on one Postgres database could let blob cleanup race
  a space write that references the same blob.
- **Unresolvable space type.** The reference refuses to issue a token when a
  bare `space:<type>` grant's declaration can't be resolved. Cocoon issues the
  grant unchanged, which permits no writes.

## Tests

The reference's Spaces test suites are ported case by case. Each Go test names
the reference case it ports.

| Reference suite | Go tests |
|---|---|
| `packages/space` unit tests (set hash, commits, MACs, KEM, tokens, HTTP signatures, STAR) | `space/*_test.go`, plus reference-generated vectors and an exported repo in `space/testdata` |
| `oauth-scopes` `space-permission.test.ts` | `oauth/scopes/space_test.go` |
| `pds/tests/space/records.test.ts` | `server/space_records_test.go`, `server/space_blobs_test.go` |
| `pds/tests/space/auth.test.ts` | `server/space_auth_test.go` |
| `pds/tests/space/simplespace.test.ts` | `server/space_simplespace_test.go` |
| `pds/tests/space/sync.test.ts` | `server/space_sync_test.go` |
| `pds/tests/space/notifications.test.ts` | `server/space_notifications_test.go` |
| `pds/tests/space-scope.test.ts` | `server/space_scope_test.go` |
| `pds/tests/client-attestation.test.ts` | `server/space_attestation_test.go` |
| `pds/tests/space/kem-key-backfill.test.ts`, `plc-operations.test.ts` (KEM keys) | `server/kem_key_test.go` |

The server tests run on a network of in-process PDSes sharing one in-memory DID
directory (`server/space_net_test.go`, `server/space_net_creds_test.go`), the
counterpart of the reference's `tests/_space.ts`.

Cases that don't apply, each noted in its test file: the two app-password
cases, the revocation cases that mock the clock or a background queue, the
writer-state migration, the retry-worker and backfill leases, the in-flight
deletion-retry race (it spies on a delivery), and the upstream `it.todo` for
oplog pruning.
