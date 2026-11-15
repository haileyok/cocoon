# Spaces (permissioned data)

Cocoon implements the ATProto Spaces alpha: permissioned data that never
reaches the firehose. It tracks the reference implementation's November 12,
2026 alpha (`permissioned-data-alpha` at `d4def6e9`, published as
`0.0.0-spaces-alpha-20261112204144`). The lexicons are vendored unmodified in
`lexicons/com/atproto/{space,memberspace,managedspace,personalspace}` (see
`lexicons/SOURCE`). The alpha changes often and has no backwards
compatibility, so a format change upstream replaces the old one here.

## What a space is

A space is a group's private data, addressed as
`at://{authority}/space/{spaceType}/{skey}`. Its authority (a DID) decides who
may read and write. Each member who writes keeps a space repo for it on their
own PDS, and the space is the union of those repos. A record in a space is
addressed as `at://{authority}/space/{spaceType}/{skey}/{author}/{collection}/{rkey}`.

A space repo is a flat set of records rather than an MST. Its commit names the
repo, space and rev and carries the digest of an LtHash set hash (`data`), but
no signature. Instead the repo host authenticates each commit or record it
serves with a MAC (an HTTP message signature keyed by a per-request HPKE
secret), so a leaked response proves nothing to a third party. Syncers pull a
repo's changes with `listRepoOps` and its full state with `getRepo` (a STAR
archive: the commit as metadata, then each record in path order).

## Roles Cocoon plays

- **Repo host**: an account's own space repos. The account writes with
  `com.atproto.space.createRecord`, `putRecord`, `deleteRecord`, `applyWrites`
  and `clearRecords`, and reads its own repo with `getRecord`, `listRecords`,
  `listRepoOps`, `getLatestCommit`, `getRepo`, `getBlob` and `listBlobs`.
  Reading another member's repo takes a space credential. After each commit
  the PDS sends `notifyRepoUpdate` to the space authority.
- **Space host**: spaces an account governs, anchored on its own DID. The
  lifecycle methods are `com.atproto.space.createSpace`, `getSpace`,
  `updateSpace`, `deleteSpace` and `removeWriter`. A space is governed by one
  policy, an open union discriminated by `$type`. Cocoon supports the three
  baseline policies:
  - `com.atproto.personalspace.policy`: only the authority's own account may
    read, and no other writers are tracked.
  - `com.atproto.memberspace.policy`: a member list (`putMembers`,
    `removeMembers`, `listMembers`), with `publicRead`, `publicWrite`, an
    `allowedApps` allow-list judged against client attestations, and
    `publishPolicy` / `publishMembers`, which publish the configuration as
    `com.atproto.space.policy` and `com.atproto.memberspace.member` records in
    the authority's own repo in the space (refused as direct writes).
  - `com.atproto.managedspace.policy`: every account decision is deferred to a
    managing app (`did#serviceId`) through `com.atproto.managedspace.checkAccess`.
    An app that does not answer fails the request with `UpstreamFailure`
    rather than denying access.

  Removing a writer (`removeWriter`, `removeMembers`, or `putMembers` revoking
  write access) advances the space revision, is announced to registered
  syncers, and is listed by `listWriters` as a `repoRemoved` entry until the
  repo writes again.
- **Credentials**: `getDelegationToken` mints a 60-second token on the
  member's own PDS. A caller asks the authority's `authorizeSpaceSync` for a
  10-minute credential bound to a P-256 key it names (`credentialKey`),
  sending the delegation token and a client attestation in the request body
  when the space requires them. The response carries the space's current
  `spaceRev`. A `memberspace` with `publicRead` issues a credential without a
  delegation token. Reads then present the credential
  (`Authorization: Atproto-Space-Credential ...`) with an HTTP message
  signature (tag `atproto-space-credential`, found under any label) naming the
  audience repo. `notifyCredentialsRevoked` lets an authority revoke
  credentials at repo hosts.
- **Notifications**: a syncer registers an endpoint by including
  `notify: {endpoint, token}` in `authorizeSpaceSync`. Before creating a
  registration the host calls `confirmRegistration` on the endpoint and
  requires its challenge back. A registration stays active while the credential
  from its latest authorization is valid, so a syncer keeps reauthorizing.
  The host sends `notifySpaceUpdate` with a `repoWrite`, `repoRemoved`,
  `spaceDeleted` or `registrationExpired` update, authenticated by the token in
  the body. Writes and removals are best effort. Deletion and expiry notices
  are retried with backoff from 1 minute to 12 hours for at least 72 hours, and
  a syncer that rejects its expiry notice, or can't be reached in that time, is
  unregistered. Cocoon does not act as a syncer: it does not serve
  `confirmRegistration` or `notifySpaceUpdate`.
- **MACs**: each account has a dedicated P-256 `#atproto_kem` key, published
  in its genesis PLC operation. A syncer reading with a credential sends
  `Accept-Signature: mac=("atproto-space-commit";sf);keyid="<ephemeral did:key>";tag="atproto-space-commit"`
  (the record profile for `getRecord`). `getLatestCommit`, `getRepo`,
  `listRepoOps` and `getRecord` answer with an `Atproto-Space-Commit` or
  `Atproto-Space-Record` header and an `hmac-sha256` signature over it, keyed by
  the HPKE secret export (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, export-only
  AEAD, info `atproto-mac`). Accounts created before KEM keys existed get one
  from a background backfill at startup, which publishes it to PLC when this
  PDS holds a rotation key for the account and is its current PDS. Otherwise
  the account must publish the key itself, from `getRecommendedDidCredentials`.
- **Migration**: `exportSpaceMeta` and `importSpaceMeta` carry a space's
  policy, member list and writer set between hosts as a STAR archive
  (`atproto-space-meta`), and `getRepo` / `importRepo` carry an account's repo,
  all as `application/vnd.dasl.star`.

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
- **Takedowns.** A taken-down account's space repos aren't served and it
  can't write, manage its spaces or mint delegation tokens, as in the
  reference. A taken-down or deactivated space authority stops issuing
  credentials and listing writers (`RepoTakendown`, `RepoDeactivated`), but
  keeps accepting repo update notifications. Cocoon does not accept its admin
  password on the space read methods, nor a session created with
  `allowTakendown` for exporting a taken-down account's spaces; both are
  reference-only conveniences.
- **One retry worker.** The reference elects a notification retry worker and a
  KEM key backfill worker with leases. Cocoon runs each once in process. The
  worker also resends syncer notices (deletion and registration expiry).
- **No garbage collection.** Like the reference, Cocoon does not yet discard
  empty space repos or drop empty and removed repos from the writer set.
- **Syncer registrations.** The reference keeps them in the authority's actor
  store; Cocoon keeps them in `space_notify_registrations`, keyed by space,
  endpoint and token.
- **Stored field names.** The protocol renamed a commit's `hash` to `data`.
  Cocoon's `space_writers.hash` and `space_notification_retries.hash` columns
  keep their names, so no data migration was needed.
- **Outbound requests.** Managing-app checks and notifications go to
  endpoints that DID documents name or that syncers register. Cocoon sends them with its SSRF-guarded
  client, which refuses private and loopback addresses. The reference fetches
  them with `safeFetch`.
- **One process per database.** Like Cocoon's public repo writes, space writes
  and blob cleanup are serialized per account within one process. Running
  several Cocoon instances on one Postgres database could let blob cleanup race
  a space write that references the same blob.
- **Unresolvable space type.** The reference refuses to issue a token when a
  bare `space:<type>` grant's declaration can't be resolved. Cocoon issues the
  grant unchanged, which permits no writes.

## Upgrading from the October 22 alpha

Space tables migrate when the PDS starts (`server/space_migrate.go`):

- Each `simplespace_configs` row becomes a policy in `space_policies`, as the
  reference's migration does: a managing app on either side becomes a
  `managedspace` (which now asks the app about both reads and writes, and
  drops any app allow-list and member list), anything else becomes a
  `memberspace` (`publicRead`, `publicWrite`, `allowedApps`). A space whose
  managing app was stored as a bare DID can't reach its app (it must be a
  `did#serviceId` reference), so update its policy.
  A warning is logged for each space whose access changed this way.
  `simplespace_members` is renamed `memberspace_members`.
- Syncer registrations made with `registerNotify` name a service rather than
  an endpoint and have no token, so they are dropped, along with the pending
  deletion notices queued for them. Syncers re-register by including `notify`
  in their next `authorizeSpaceSync`.
- Space meta archives exported before this release no longer import, and STAR
  archives from earlier releases (no control bytes) don't parse. Re-export
  them from an upgraded host.

Back up the database before upgrading. Syncers, managing apps, account
migration peers and other repo hosts must be upgraded too: the old and new MAC
and signature formats are incompatible in both directions.

## Tests

The reference's Spaces test suites are ported case by case. Each Go test names
the reference case it ports.

| Reference suite | Go tests |
|---|---|
| `packages/space` unit tests (set hash, commits, MACs, KEM, tokens, HTTP signatures, STAR, space meta archives) | `space/*_test.go`, plus reference-generated vectors, an exported repo and space meta archive in `space/testdata`, and the DASL-STAR interop fixtures |
| `oauth-scopes` `space-permission.test.ts` | `oauth/scopes/space_test.go` |
| `pds/tests/space/records.test.ts` | `server/space_records_test.go`, `server/space_blobs_test.go` |
| `pds/tests/space/auth.test.ts` | `server/space_auth_test.go` |
| `pds/tests/space/policy.test.ts` (policies, members, publishing, managed spaces, deletion) | `server/space_policy_test.go` |
| `pds/tests/space/policy.test.ts` (notify registration), `notifications.test.ts` | `server/space_notifications_test.go` |
| `pds/tests/space/sync.test.ts` | `server/space_sync_test.go` |
| `pds/tests/space/migration.test.ts` | `server/space_migration_test.go` |
| `pds/tests/space-scope.test.ts` | `server/space_scope_test.go` |
| `pds/tests/client-attestation.test.ts` | `server/space_attestation_test.go` |
| `pds/tests/space/kem-key-backfill.test.ts`, `plc-operations.test.ts` (KEM keys) | `server/kem_key_test.go` |

The server tests run on a network of in-process PDSes sharing one in-memory DID
directory (`server/space_net_test.go`, `server/space_net_creds_test.go`), the
counterpart of the reference's `tests/_space.ts`. `server/space_migrate_test.go`
covers the startup migration of older space tables, including the October 22
simplespace configs.

Cases that don't apply, each noted in its test file: the app-password cases,
the cases that mock the clock or a background queue, the retry-worker and
backfill leases, the admin-token and `allowTakendown` export cases, the
space-record takedown subject cases, and the upstream `it.todo` for oplog
pruning.
