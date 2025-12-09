# Cocoon

> [!WARNING]
I migrated and have been running my main account on this PDS for months now without issue, however, I am still not responsible if things go awry, particularly during account migration. Please use caution.

Cocoon is a PDS implementation in Go. It is highly experimental, and is not ready for any production use.

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
- `COCOON_S3_BLOBSTORE_ENABLED=true`: Blobs stored in S3 bucket under `blobs/{did}/{cid}`

**Blob Serving Options:**
- Without `COCOON_S3_CDN_URL`: Blobs are proxied through the PDS server
- With `COCOON_S3_CDN_URL`: `getBlob` returns a 302 redirect to `{CDN_URL}/blobs/{did}/{cid}`

> **Tip**: For Cloudflare R2, you can use the public bucket URL as the CDN URL. For AWS S3, you can use CloudFront or the S3 bucket URL directly if public access is enabled.

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

- [ ] `com.atproto.label.queryLabels`
- [x] `com.atproto.moderation.createReport` (Note: this should be handled by proxying, not actually implemented in the PDS)
- [x] `app.bsky.actor.getPreferences`
- [x] `app.bsky.actor.putPreferences`

## License

This project is licensed under MIT license. `server/static/pico.css` is also licensed under MIT license, available at [https://github.com/picocss/pico/](https://github.com/picocss/pico/).
