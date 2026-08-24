# Cocoon

> [!WARNING]
> I migrated and have been running my main account on this PDS for months now without issue, however, I am still not responsible if things go awry, particularly during account migration. Please use caution.

Cocoon is a PDS implementation in Go. It is highly experimental, and is not ready for any production use.

> [!WARNING]
> **Atproto Spaces is an experimental alpha.** It is **disabled by default**: leave `COCOON_SPACES_ENABLED=false` (or omit the flag) unless you are deliberately testing it. The implementation is pinned to the atproto reference SHA `89deb9faca20e56fa2a262fe9746ed52bc1095ba`. Spaces provide **access control, not encryption or confidentiality**; they are unsuitable for sensitive data and unsuitable for production data. This alpha is not a claim of complete external interoperability or production readiness.

## Atproto Spaces alpha

Spaces are permissioned, host-local PDS routes. They are not a replacement for the ordinary public repository/sync surface. Enable them only for a controlled experiment:

```bash
COCOON_SPACES_ENABLED=true
```

When the flag is false, Cocoon does not register the alpha handlers. The `com.atproto.space.*` and `com.atproto.simplespace.*` namespace guards return `501 NotSupported` instead of allowing an unknown method to fall through to the generic proxy.

### Registered endpoints

These are the routes currently registered when Spaces are enabled (the HTTP method is shown first):

- **`com.atproto.space`**
  - `POST createRecord`, `POST putRecord`, `POST deleteRecord`, `POST applyWrites`
  - `GET listSpaces`, `GET getDelegationToken`
  - `GET getRecord`, `GET listRecords`, `GET getBlob`, `GET listBlobs`
  - `GET getLatestCommit`, `GET getRepo`, `GET listRepoOps`, `GET listRepos`
  - `POST getSpaceCredential`
  - `POST registerNotify`, `POST unregisterNotify`
  - `POST notifyWrite`, `POST notifySpaceDeleted`
- **`com.atproto.simplespace`**
  - `POST createSpace`, `POST updateSpace`, `POST deleteSpace`
  - `GET getSpace`
  - `POST addMember`, `POST removeMember`, `GET listMembers`

OAuth scopes authorize the OAuth routes. Space credentials and their DPoP proofs authorize credential routes; delegation exchange uses a short-lived delegation token and DPoP proof. Service-auth JWTs are used by the notification receiver and are checked for the expected audience (this PDS) and lexicon method (`lxm`). At a high level, DPoP binds a credential to a client key and protects each request against proof replay; it does not encrypt the record or blob.

### Data flow and boundaries

- Permissioned records sync directly with an authorized PDS client through the `com.atproto.space` read/CAR routes. Space data does not use a relay or a public firehose: permissioned records never enter Cocoon's public event manager. Ordinary public repositories retain their separate public sync/firehose behavior.
- `com.atproto.space.getRepo` is an authenticated full current-state CAR recovery path. `listRepoOps` reads the retained, append-only Space oplog by revision and cursor; Space records retain the current value separately. There is no complete import API and no Space-specific pruning, so a CAR is an export/recovery representation, not a general migration import contract.
- Permissioned blob references are checked against the authorized Space record. `com.atproto.space.getBlob` is an authenticated PDS proxy only and never redirects to a CDN, including when public S3/CDN storage is configured. A private CDN is not a permission boundary. Public `com.atproto.sync.listBlobs` and `com.atproto.sync.getBlob` expose only blobs referenced by a public repository; a Space-only reference is not a public reference.
- Writes enqueue metadata-only notification outbox rows after the Space transaction's state changes. The outbox carries Space/repo/revision/hash metadata, not record values or blob bytes. A host must configure/inject the outbound `SpaceNotificationSender` and any target resolver/service-auth transport; there is no automatic outbound delivery when that sender is absent. The worker retries with idempotency and expires registrations after 24 hours and deliveries after 7 days.

### Deletion, retention, and recovery limits

Deleting a Space creates a durable tombstone, removes the authority's local Space rows, marks members removed, and queues deletion notifications; Space URIs are not reusable. Account deletion removes the account's authored permissioned records, refs, repos, oplog rows, and credentials-related account state while preserving the tombstone/deletion outbox semantics and any remote data that other hosts already retained. Remote consumers can retain copies.

Space credentials live for two hours; delegation/client-attestation tokens live for 60 seconds, and DPoP proofs are accepted for at most 60 seconds (with clock skew). A local tombstone check rejects credential use immediately, but there is no global revocation protocol for already-cached remote credentials or data. Plan for this residual credential-expiry/notification window: registrations can remain until their 24-hour expiry and queued deliveries until their 7-day expiry unless explicitly handled by the configured worker.

The normal server uses PostgreSQL/SQLite persistence for Space state and durable replay JTIs. Replay JTIs are single-use and carry an expiry deadline, but this alpha has no complete export/import or replay-compaction API. PostgreSQL backups are an operator responsibility (`pg_dump` or the provider); SQLite backup covers the local database, while externally stored S3 blob bytes still require their own backup. See [the detailed Spaces alpha guide](docs/spaces-alpha.md) and the pinned [compatibility fixture](testdata/spaces-alpha/COMPATIBILITY.md) before updating the reference.

### Minimal local test workflow

The documentation contract test is deterministic and checks only key claims rather than snapshotting this README. Run the normal suite with:

```bash
go test ./space -run 'TestSpaces(ReadmeContract|FixtureManifestMatchesProtocolTypes|AlphaReferenceCommitPinned)$'
go test ./...
```

The reference PDS test harness creates TypeScript PDS instances internally and
cannot be pointed at an external PDS. To exercise Cocoon with the pinned
atproto generated client and Lexicons, run the Cocoon-backed interop harness:

```bash
ATPROTO_ROOT=~/worktrees/atproto/private-spaces-reference \
  ./interop/atproto/run.sh
```

This starts a disposable Cocoon instance, seeds test accounts, obtains real
session tokens, and validates Space creation, membership, record CRUD, JSON
wire shapes, signed commits, CAR retrieval, oplog cursors/nullability, Space
discovery, and owner-only SimpleSpace authorization over HTTP.

The PostgreSQL concurrency/durability tests are opt-in and use an isolated schema. With a reachable PostgreSQL database, pass its DSN as `COCOON_TEST_POSTGRES_DSN`:

```bash
COCOON_TEST_POSTGRES_DSN='postgres://cocoon:password@localhost:5432/cocoon?sslmode=disable' \\
  go test ./server -run 'TestPostgresSpaceRepo'
```

## Quick Start with Docker Compose

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server (for automatic HTTPS)
- Ports 80 and 443 open in i.e. UFW

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/haileyok/cocoon.git
   cd cocoon
   ```

2. **Create your configuration file**
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env` with your settings**

   Required settings:
   ```bash
   COCOON_DID="did:web:your-domain.com"
   COCOON_HOSTNAME="your-domain.com"
   COCOON_CONTACT_EMAIL="you@example.com"
   COCOON_RELAYS="https://bsky.network"

   # Generate with: openssl rand -hex 16
   COCOON_ADMIN_PASSWORD="your-secure-password"

   # Generate with: openssl rand -hex 32
   COCOON_SESSION_SECRET="your-session-secret"
   ```

4. **Start the services**
   ```bash
   # Pull pre-built image from GitHub Container Registry
   docker-compose pull
   docker-compose up -d
   ```

   Or build locally:
   ```bash
   docker-compose build
   docker-compose up -d
   ```

   **For PostgreSQL deployment:**
   ```bash
   # Add POSTGRES_PASSWORD to your .env file first!
   docker-compose -f docker-compose.postgres.yaml up -d
   ```

5. **Get your invite code**

   On first run, an invite code is automatically created. View it with:
   ```bash
   docker-compose logs create-invite
   ```

   Or check the saved file:
   ```bash
   cat keys/initial-invite-code.txt
   ```

   **IMPORTANT**: Save this invite code! You'll need it to create your first account.

6. **Monitor the services**
   ```bash
   docker-compose logs -f
   ```

### What Gets Set Up

The Docker Compose setup includes:

- **init-keys**: Automatically generates cryptographic keys (rotation key and JWK) on first run
- **cocoon**: The main PDS service running on port 8080
- **create-invite**: Automatically creates an initial invite code after Cocoon starts (first run only)
- **caddy**: Reverse proxy with automatic HTTPS via Let's Encrypt

### Data Persistence

The following directories will be created automatically:

- `./keys/` - Cryptographic keys (generated automatically)
  - `rotation.key` - PDS rotation key
  - `jwk.key` - JWK private key
  - `initial-invite-code.txt` - Your first invite code (first run only)
- `./data/` - SQLite database and blockstore
- Docker volumes for Caddy configuration and certificates

### Optional Configuration

#### Database Configuration

By default, Cocoon uses SQLite which requires no additional setup. For production deployments with higher traffic, you can use PostgreSQL:

```bash
# Database type: sqlite (default) or postgres
COCOON_DB_TYPE="postgres"

# PostgreSQL connection string (required if db-type is postgres)
# Format: postgres://user:password@host:port/database?sslmode=disable
COCOON_DATABASE_URL="postgres://cocoon:password@localhost:5432/cocoon?sslmode=disable"

# Or use the standard DATABASE_URL environment variable
DATABASE_URL="postgres://cocoon:password@localhost:5432/cocoon?sslmode=disable"
```

For SQLite (default):
```bash
COCOON_DB_TYPE="sqlite"
COCOON_DB_NAME="/data/cocoon/cocoon.db"
```

> **Note**: When using PostgreSQL, database backups to S3 are not handled by Cocoon. Use `pg_dump` or your database provider's backup solution instead.

#### SMTP Email Settings
```bash
COCOON_SMTP_USER="your-smtp-username"
COCOON_SMTP_PASS="your-smtp-password"
COCOON_SMTP_HOST="smtp.example.com"
COCOON_SMTP_PORT="587"
COCOON_SMTP_EMAIL="noreply@example.com"
COCOON_SMTP_NAME="Cocoon PDS"
```

#### S3 Storage

Cocoon supports S3-compatible storage for both database backups (SQLite only) and blob storage (images, videos, etc.):

```bash
# Enable S3 backups (SQLite databases only - hourly backups)
COCOON_S3_BACKUPS_ENABLED=true

# Enable S3 for blob storage (images, videos, etc.)
# When enabled, blobs are stored in S3 instead of the database
COCOON_S3_BLOBSTORE_ENABLED=true

# S3 configuration (works with AWS S3, MinIO, Cloudflare R2, etc.)
COCOON_S3_REGION="us-east-1"
COCOON_S3_BUCKET="your-bucket"
COCOON_S3_ENDPOINT="https://s3.amazonaws.com"
COCOON_S3_ACCESS_KEY="your-access-key"
COCOON_S3_SECRET_KEY="your-secret-key"

# Optional: CDN/public URL for blob redirects
# When set, com.atproto.sync.getBlob redirects to this URL instead of proxying
COCOON_S3_CDN_URL="https://cdn.example.com"
```

**Blob Storage Options:**
- `COCOON_S3_BLOBSTORE_ENABLED=false` (default): Blobs stored in the database
- `COCOON_S3_BLOBSTORE_ENABLED=true`: New blobs are stored under an immutable generation-specific key such as `blobs/{did}/{cid}/{generation}`. Legacy rows with an empty persisted key continue to use `blobs/{did}/{cid}`.

**Blob Serving Options:**
- Without `COCOON_S3_CDN_URL`: Blobs are proxied through the PDS server
- With `COCOON_S3_CDN_URL`: `getBlob` redirects to the blob's persisted object key (legacy rows use `{CDN_URL}/blobs/{did}/{cid}`)

> **Tip**: For Cloudflare R2, you can use the public bucket URL as the CDN URL. For AWS S3, you can use CloudFront or the S3 bucket URL directly if public access is enabled.

#### Alpine based image

The default image is based on Debian. You can use the Alpine-based image if you prefer.

> [!NOTE]
> Currently, we do not have pre-built Alpine-based image on the GitHub Container Registry. You have to build them locally.

In the compose file, replace every `dockerfile: Dockerfile` by `dockerfile: Dockerfile.alpine`, e.g.
```yml
services:
  cocoon:
    build:
      context: .
      dockerfile: Dockerfile.alpine
```

You can also build the image locally with
```bash
docker build -f Dockerfile.alpine -t cocoon:alpine .
```

### Management Commands

Create an invite code:
```bash
docker exec cocoon-pds /cocoon create-invite-code --uses 1
```

Reset a user's password:
```bash
docker exec cocoon-pds /cocoon reset-password --did "did:plc:xxx"
```

### Updating

```bash
docker-compose pull
docker-compose up -d
```

## Implemented Endpoints

> [!NOTE]
Just because something is implemented doesn't mean it is finished. Tons of these are returning bad errors, don't do validation properly, etc. I'll make a "second pass" checklist at some point to do all of that.

### Identity

- [x] `com.atproto.identity.getRecommendedDidCredentials`
- [x] `com.atproto.identity.requestPlcOperationSignature`
- [x] `com.atproto.identity.resolveHandle`
- [x] `com.atproto.identity.signPlcOperation`
- [x] `com.atproto.identity.submitPlcOperation`
- [x] `com.atproto.identity.updateHandle`

### Repo

- [x] `com.atproto.repo.applyWrites`
- [x] `com.atproto.repo.createRecord`
- [x] `com.atproto.repo.putRecord`
- [x] `com.atproto.repo.deleteRecord`
- [x] `com.atproto.repo.describeRepo`
- [x] `com.atproto.repo.getRecord`
- [x] `com.atproto.repo.importRepo` (Works "okay". Use with extreme caution.)
- [x] `com.atproto.repo.listRecords`
- [x] `com.atproto.repo.listMissingBlobs`

### Server

- [x] `com.atproto.server.activateAccount`
- [x] `com.atproto.server.checkAccountStatus`
- [x] `com.atproto.server.confirmEmail`
- [x] `com.atproto.server.createAccount`
- [x] `com.atproto.server.createInviteCode`
- [x] `com.atproto.server.createInviteCodes`
- [x] `com.atproto.server.deactivateAccount`
- [x] `com.atproto.server.deleteAccount`
- [x] `com.atproto.server.deleteSession`
- [x] `com.atproto.server.describeServer`
- [ ] `com.atproto.server.getAccountInviteCodes`
- [x] `com.atproto.server.getServiceAuth`
- ~~[ ] `com.atproto.server.listAppPasswords`~~ - not going to add app passwords
- [x] `com.atproto.server.refreshSession`
- [x] `com.atproto.server.requestAccountDelete`
- [x] `com.atproto.server.requestEmailConfirmation`
- [x] `com.atproto.server.requestEmailUpdate`
- [x] `com.atproto.server.requestPasswordReset`
- [x] `com.atproto.server.reserveSigningKey`
- [x] `com.atproto.server.resetPassword`
- ~~[] `com.atproto.server.revokeAppPassword`~~ - not going to add app passwords
- [x] `com.atproto.server.updateEmail`

### Sync

- [x] `com.atproto.sync.getBlob`
- [x] `com.atproto.sync.getBlocks`
- [x] `com.atproto.sync.getLatestCommit`
- [x] `com.atproto.sync.getRecord`
- [x] `com.atproto.sync.getRepoStatus`
- [x] `com.atproto.sync.getRepo`
- [x] `com.atproto.sync.listBlobs`
- [x] `com.atproto.sync.listRepos`
- ~~[ ] `com.atproto.sync.notifyOfUpdate`~~ - BGS doesn't even have this implemented lol
- [x] `com.atproto.sync.requestCrawl`
- [x] `com.atproto.sync.subscribeRepos`

### Other

- [x] `com.atproto.label.queryLabels`
- [x] `com.atproto.moderation.createReport` (Note: this should be handled by proxying, not actually implemented in the PDS)
- [x] `app.bsky.actor.getPreferences`
- [x] `app.bsky.actor.putPreferences`

## License

This project is licensed under MIT license. `server/static/pico.css` is also licensed under MIT license, available at [https://github.com/picocss/pico/](https://github.com/picocss/pico/).
