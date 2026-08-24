# Cocoon Atproto Spaces alpha

> **Experimental alpha.** Atproto Spaces is disabled by default with
> `COCOON_SPACES_ENABLED=false`. This implementation is pinned to reference
> SHA `89deb9faca20e56fa2a262fe9746ed52bc1095ba`.
>
> Spaces are an access-control mechanism, not encryption or confidentiality.
> They are unsuitable for sensitive data and unsuitable for production data.
> A private CDN is not a permission boundary. This document describes the
> implementation in this repository, not a promise of complete external
> interoperability or production readiness.

## Scope and enablement

Cocoon registers the Spaces routes only when `SpacesEnabled` is true. The CLI
flag is `--spaces-enabled`, and its environment variable is
`COCOON_SPACES_ENABLED`. The default is false. With the flag off, the two Space
namespace guards return `501 NotSupported`; those requests do not fall through
to Cocoon's generic XRPC proxy.

The pinned compatibility material is in
[`testdata/spaces-alpha/`](../testdata/spaces-alpha/). The reference Lexicons
and selected TypeScript helpers are fixtures for review and interoperability
vectors; they are not an assertion that every external implementation supports
this alpha.

## Registered routes

The following routes are registered by `server.addSpaceRoutes` when Spaces are
enabled. Names below omit the common `/xrpc/` prefix.

### `com.atproto.space`

| HTTP | Method | Route policy |
| --- | --- | --- |
| POST | `com.atproto.space.createRecord` | OAuth only |
| POST | `com.atproto.space.putRecord` | OAuth only |
| POST | `com.atproto.space.deleteRecord` | OAuth only |
| POST | `com.atproto.space.applyWrites` | OAuth only |
| GET | `com.atproto.space.listSpaces` | OAuth only |
| GET | `com.atproto.space.getDelegationToken` | OAuth only |
| GET | `com.atproto.space.getRecord` | OAuth or Space credential |
| GET | `com.atproto.space.listRecords` | OAuth or Space credential |
| GET | `com.atproto.space.getBlob` | OAuth or Space credential |
| GET | `com.atproto.space.listBlobs` | OAuth or Space credential |
| GET | `com.atproto.space.getLatestCommit` | OAuth or Space credential |
| GET | `com.atproto.space.getRepo` | OAuth or Space credential |
| GET | `com.atproto.space.listRepoOps` | OAuth or Space credential |
| GET | `com.atproto.space.listRepos` | Space credential only |
| POST | `com.atproto.space.getSpaceCredential` | Delegation exchange |
| POST | `com.atproto.space.registerNotify` | Space credential only |
| POST | `com.atproto.space.unregisterNotify` | Space credential only |
| POST | `com.atproto.space.notifyWrite` | Service auth only |
| POST | `com.atproto.space.notifySpaceDeleted` | Service auth only |

### `com.atproto.simplespace`

| HTTP | Method | Route policy |
| --- | --- | --- |
| POST | `com.atproto.simplespace.createSpace` | OAuth only |
| POST | `com.atproto.simplespace.updateSpace` | OAuth only |
| POST | `com.atproto.simplespace.deleteSpace` | OAuth only |
| GET | `com.atproto.simplespace.getSpace` | OAuth or Space credential |
| POST | `com.atproto.simplespace.addMember` | OAuth only |
| POST | `com.atproto.simplespace.removeMember` | OAuth only |
| GET | `com.atproto.simplespace.listMembers` | OAuth only |

The SimpleSpace implementation supports the pinned public, member-list, and
managing-app policy forms plus open and allow-list app access. A managing-app
policy requires an injected host authorizer; without one it fails closed.

## Authentication in one page

* **OAuth** supplies the user subject and scopes for management, record writes,
  discovery, and the OAuth-authorized read paths. Scopes select a space,
  collection, action, and, where applicable, blob media types.
* **Delegation and Space credentials** are signed tokens scoped to one Space.
  A delegation token is exchanged for a Space credential. The exchange and
  credential requests require DPoP proofs. Credentials are DPoP-bound through
  their confirmation key (`jkt`), and each request proof binds the HTTP method,
  URL, credential hash, and a unique JTI. This is request authentication and
  replay protection, not encryption.
* **Service auth** protects the notification receiver methods. Cocoon verifies
  the issuer's DID key and checks that the JWT audience is this PDS and `lxm`
  is the expected notification method. Service auth authenticates a service
  request; it does not make the notification transport automatic.
* **Replay storage** consumes each token/proof JTI once. A normal server uses
  the durable GORM-backed `SpaceReplayJTI` table; an explicitly constructed
  in-memory store is only process-local and is suitable for tests or an
  intentionally ephemeral deployment.

The implemented lifetimes are two hours for a Space credential, 60 seconds for
a delegation or client-attestation token, and at most 60 seconds for a DPoP
proof, with the configured clock-skew allowance. The durable replay row records
the relevant expiry deadline. There is no public replay-compaction endpoint.

## Direct PDS data flow

Spaces are direct, permissioned PDS state. An authorized client reads a Space
from the host PDS using the `com.atproto.space` routes, including the full CAR
returned by `getRepo`. Permissioned Space data does not use a relay or public
firehose, and permissioned records never enter Cocoon's public event manager.
The ordinary public repository and its public event stream remain a separate
path.

A Space write is committed atomically for one `(space, author)` repository. The
current record value is stored in `SpaceRecord`, the repository head and LtHash
in `SpaceRepo`, and each operation in `SpaceRepoOp`. Blob references are stored
in `SpaceBlobRef` with the full Space/author/collection/rkey identity. No Space
write is converted into a public `events.EventManager` event.

### Records, oplog, and recovery

`listRepoOps` reads the append-only Space oplog ordered by revision and index.
Pagination does not split one revision's atomic batch. `since` and opaque
cursors select the retained rows, and the terminal page includes the current
signed commit. The current implementation does not run a Space-specific oplog
pruner; normal record deletion removes the current record and its blob refs but
leaves the operation history. Space deletion and account deletion are the
explicit cleanup paths described below.

`getRepo` is the full current-state recovery path: it loads the current records,
reconstructs the canonical flat DRISL RepoIndex and two-root CAR, signs the
resulting Space commit with the account key, and returns
`application/vnd.ipld.car`. It is sufficient to recover the
current repository state even when an incremental consumer is starting over;
it is not an import API and does not include blob bytes.

### Blobs and public sync

A Space record can reference a blob uploaded by its author. The Space write
path verifies that the author owns the upload and stores a scoped
`SpaceBlobRef`.

* `com.atproto.space.getBlob` first authenticates the Space read, verifies the
  CID is referenced by that Space/author, and then streams the bytes through the
  PDS. OAuth callers additionally need a covering blob scope.
* Permissioned reads are an authenticated proxy only. They never redirect to a
  public or private CDN, even when S3/CDN configuration exists. A private CDN
  is not a substitute for the Space authorization check.
* The unauthenticated public `com.atproto.sync.listBlobs` and
  `com.atproto.sync.getBlob` queries only blobs with a positive public-repo
  `ref_count`. `SpaceBlobRef` rows do not make a blob public. Thus public sync
  exposes only public refs, never a Space-only reference.

## Notification outbox and transport

`registerNotify` stores a service identifier for 30 days. Re-registering updates
that expiry; `unregisterNotify` is idempotent. A successful Space write inserts
a durable, idempotent outbox row in the same database transaction. The row
contains the Space, author, revision, hash, service, and metadata-only payload;
it does not carry record values, collection/rkey values, CIDs, or blob bytes.
Space deletion similarly queues `notifySpaceDeleted` deliveries.

The worker is pull-based and retries pending rows with an idempotency key. It
expires registrations after 30 days and deliveries after seven days. Cocoon
starts the periodic worker only when Spaces are enabled **and** a
`SpaceNotificationSender` has been configured. The sender is an injected
network-facing dependency, and an optional resolver maps the service identifier
to a target. The host must also implement/configure the outbound HTTP and
service-auth signing/transport expected by the remote service. Registration and
outbox persistence alone do not send anything: there is no automatic outbound
delivery if the sender/service-auth transport is absent.

The inbound `notifyWrite` and `notifySpaceDeleted` methods require service-auth
JWTs. They update local writer/tombstone state and can enqueue forwarding rows,
but they do not turn permissioned records into public events.

## Deletion and residual windows

### Space deletion

The owner can delete a SimpleSpace. Cocoon marks the row deleted, creates a
durable `SpaceTombstone`, removes the authority's local records, blob refs,
oplog, repo head, and writer row, marks membership removed, and queues deletion
notifications. Recreating the same Space URI is rejected. Repositories hosted
for other authors are retained so their state is not silently destroyed by
authority cleanup; a tombstone revokes credential-backed access while allowing
the local OAuth cleanup/migration paths to identify the deletion.

The tombstone check rejects new Space credential use immediately on this PDS.
Already-issued credentials are nevertheless cryptographically self-contained,
and remote hosts cannot be forced to forget a credential or a copied CAR. The
nominal credential lifetime and notification delivery/registration expiries
therefore form the residual revocation window for external consumers.

### Account deletion

Account deletion includes owned-Space tombstoning in the account transaction,
removes all permissioned data authored by the account (including repos in
another authority's Space), removes its memberships, and deletes authored
write-delivery rows. Deletion-delivery outbox rows are intentionally retained
so a configured worker can fan out the deletion event. Blobs are removed only
when no public or surviving permissioned reference remains. Data already copied
to another host is outside the local deletion transaction.

## Backup, export, and migration limits

* Server database migrations include all Space models through `models.SpaceModels`.
  A normal SQLite database backup therefore includes local Space rows, but an
  S3-backed blob object is outside that database file and needs a matching
  object-store backup.
* For PostgreSQL, Cocoon skips its SQLite/S3 database-backup routine. Operators
  must use `pg_dump`, a managed-provider backup, and a separate blob-store
  backup. A backup is not a cross-version wire migration guarantee.
* `com.atproto.space.getRepo` is an authenticated per-repository CAR export and
  full current-state recovery mechanism. It is not a complete Space export
  bundle: notification registrations, tombstones, replay JTIs, writer metadata,
  and external blob objects require separate handling.
* There is **no complete import API** for Space CARs, records, or all of that
  metadata. Do not treat the ordinary `com.atproto.repo.importRepo` endpoint as
  a Space import path. Validate a target build, preserve the pinned fixtures,
  and test recovery before a migration.

## Compatibility fixture and update checklist

The fixture document and manifest live in
[`testdata/spaces-alpha/COMPATIBILITY.md`](../testdata/spaces-alpha/COMPATIBILITY.md).
`SHA256SUMS` is a deterministic manifest: each line is a SHA-256 digest followed
by a repository-relative path. It covers every copied upstream Lexicon and
selected reference helper; it excludes `SHA256SUMS` itself and the explanatory
`COMPATIBILITY.md`. The existing `space/compatibility_test.go` recomputes each
listed digest and requires the pinned fixture set to be present.

When intentionally updating compatibility:

1. Select and record one immutable upstream atproto commit; do not mix files
   from different proposal revisions.
2. Replace the copied Lexicons/reference helpers and regenerate `SHA256SUMS`.
3. Update the reference SHA, compatibility version, this document, and the
   fixture's compatibility notes together.
4. Regenerate and review cross-language vectors for token, DPoP, LtHash, commit,
   CAR, and sync behavior.
5. Review every changed Lexicon for route names, auth requirements, union
   variants, notification payloads, and blob visibility semantics.
6. Run the documentation contract test, fixture-manifest test, the full Go
   suite, and a diff/ownership check. Do not update implementation code merely
   to make a changed fixture pass without reviewing the wire contract.

## Minimal local workflow

The documentation and fixture checks do not need a running database:

```bash
go test ./space -run 'TestSpaces(ReadmeContract|FixtureManifestMatchesProtocolTypes|AlphaReferenceCommitPinned)$'
```

Run the complete suite before merging documentation or fixture changes:

```bash
go test ./...
```

The PostgreSQL Space repository tests are opt-in. They create and clean up an
isolated schema, so provide a PostgreSQL DSN through
`COCOON_TEST_POSTGRES_DSN`:

```bash
COCOON_TEST_POSTGRES_DSN='postgres://cocoon:password@localhost:5432/cocoon?sslmode=disable' \
  go test ./server -run 'TestPostgresSpaceRepo'
```

Keep `COCOON_SPACES_ENABLED=false` for an ordinary local server. To exercise
route registration deliberately, set `COCOON_SPACES_ENABLED=true` in the
process environment and use a disposable database.

## Explicit non-claims

This alpha does **not** claim end-to-end encryption, production readiness,
complete interoperability with every external Spaces implementation, automatic
outbound notification delivery without injected transport, or a complete
Space import/migration API. It is access-controlled local PDS functionality
anchored to the pinned reference and its reviewed fixtures.
