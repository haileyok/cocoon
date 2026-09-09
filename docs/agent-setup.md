# Cocoon for Agents: headless setup, OAuth, and management

This runbook lets an autonomous agent stand up a Cocoon PDS, provision its own
account, obtain session or OAuth tokens, and manage the service end-to-end —
using only documented, machine-parseable interfaces. No browser is required at
any step. Every step is a verifiable command; every artifact is a parseable
output.

Conventions used below:

- `$HOST` — your PDS hostname (e.g. `pds.example.com`)
- `$ADMIN_PASSWORD` — the value of `COCOON_ADMIN_PASSWORD` in `.env`
- Admin HTTP auth is HTTP Basic with username `admin` and that password
- JSON parsing is with `jq`; commands are `bash`

## 1. Deploy

Prerequisites: Docker and Docker Compose, a domain pointed at the server,
ports 80/443 open.

```bash
git clone https://github.com/haileyok/cocoon.git
cd cocoon
cp .env.example .env
```

Set these six required variables in `.env`:

```bash
COCOON_DID="did:web:$HOST"                 # or your did:plc
COCOON_HOSTNAME="$HOST"
COCOON_ROTATION_KEY_PATH="./rotation.key"  # generated automatically if absent
COCOON_JWK_PATH="./jwk.key"                # generated automatically if absent
COCOON_CONTACT_EMAIL="you@example.com"
COCOON_RELAYS="https://bsky.network"       # optional but recommended
COCOON_ADMIN_PASSWORD="$(openssl rand -hex 16)"
COCOON_SESSION_SECRET="$(openssl rand -hex 32)"
```

Start and wait for health:

```bash
docker compose up -d
# Poll until this returns 200:
curl -fsS "https://$HOST/xrpc/_health"
```

The container generates `./rotation.key` and `./jwk.key` under `./keys/` on
first boot if absent; data lives in `./data/`.

## 2. Invite code

By default Cocoon requires an invite code to create an account. Three ways to
get one:

a. **Read the initial invite** the container creates on first boot:

```bash
docker compose exec cocoon cat /keys/initial-invite-code.txt
```

b. **Mint one over HTTP** (admin Basic auth):

```bash
curl -fsS -u "admin:$ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"useCount": 1}' \
  "https://$HOST/xrpc/com.atproto.server.createInviteCode"
# {"code":"<uuid>"}
```

c. **Via the CLI** (machine-parseable with --json):

```bash
docker compose exec cocoon /cocoon create-invite-code --json --uses 1
# {"code":"<code>","uses":1,"for":""}
```

`COCOON_REQUIRE_INVITE=false` disables invite requirements entirely — only do
this for a single-operator private PDS that is not publicly reachable, since
otherwise anyone can create accounts.

## 3. Provision an account

```bash
curl -fsS -X POST "https://$HOST/xrpc/com.atproto.server.createAccount" \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "agent@example.com",
    "handle": "agent.example.com",
    "password": "<choose-a-password>",
    "inviteCode": "<from-step-2>"
  }'
```

Response: `{"accessJwt": "...", "refreshJwt": "...", "handle": "...", "did": "did:plc:..."}`.

Notes:

- **`did` field**: omit it and the server mints a fresh `did:plc` by calling
  plc.directory **over the network** — a hang here is almost always DNS or
  egress to `https://plc.directory`. To skip the network entirely, pass an
  existing `did` you control (advanced; see the atproto DID docs).
- **Handles**: handles live under the PDS hostname by default (e.g.
  `agent.pds.example.com`); subdomain handle resolution is served by the PDS's
  `/.well-known/atproto-did` route.
- **SMTP is optional**: all mail functions no-op when unset, and email
  confirmation is never a gate — the account is usable immediately.
- The invite code is consumed atomically: a failed createAccount does not burn
  it (unless the failure is after consumption, which is a single transaction).

## 4. Session tokens

For all XRPC calls you can use the legacy session tokens — this is the
simplest authenticated path:

```bash
curl -fsS -X POST "https://$HOST/xrpc/com.atproto.server.createSession" \
  -H 'Content-Type: application/json' \
  -d '{"identifier": "agent.example.com", "password": "<password>"}'
# {"accessJwt": "...", "refreshJwt": "...", ...}
```

Use `Authorization: Bearer <accessJwt>` on subsequent XRPC calls; refresh via
`POST /xrpc/com.atproto.server.refreshSession` with the refresh token in the
`Authorization` header.

2FA is off by default. If enabled, `createSession` requires an emailed
`authFactorToken` — keep 2FA off for agent-operated accounts, since reading
email is not headless.

## 5. First write

Prove the write loop works with a concrete record:

```bash
RKEY="self-test-$(date +%s)"
curl -fsS -X POST "https://$HOST/xrpc/com.atproto.repo.createRecord" \
  -H "Authorization: Bearer $ACCESS_JWT" \
  -H 'Content-Type: application/json' \
  -d '{
    "repo": "<did from step 3>",
    "collection": "com.atproto.identity.verifiableStatement",
    "rkey": "'"$RKEY"'",
    "record": {"$type": "com.atproto.identity.verifiableStatement", "name": "agent setup self-test", "createdAt": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}
  }'
# {"uri": "at://<did>/com.atproto.identity.verifiableStatement/$RKEY", "cid": "..."}
```

Verify it reads back:

```bash
curl -fsS "https://$HOST/xrpc/com.atproto.repo.getRecord?repo=<did>&collection=com.atproto.identity.verifiableStatement&rkey=$RKEY"
```

## 6. Full OAuth client flow (DPoP-bound, spec-compliant)

Use this when you want OAuth tokens per the atproto OAuth spec (recommended
for any client that talks to multiple PDSes). This flow is fully headless:
**the consent step is completed by admin authority** instead of a human
clicking "Accept" in a browser. That means the PDS operator authorizes the
grant — intended for self-hosted PDSes where the operator owns the accounts.
Do not use the admin endpoint on a PDS where account owners are untrusted.

Steps:

1. **Fetch metadata**:

```bash
curl -fsS "https://$HOST/.well-known/oauth-protected-resource"
curl -fsS "https://$HOST/.well-known/oauth-authorization-server"
```

2. **Register a client**: host a client metadata document at an `https://`
   URL and use that URL as your `client_id`, **or** use the built-in
   `http://localhost` virtual dev client (no registration needed, loopback
   redirect URIs only, auth method `none`).

3. **PAR request** (pushed authorization request) — this creates a pending
   authorization request and returns a `request_uri`:

```bash
curl -fsS -X POST "https://$HOST/oauth/par" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "DPoP: <your-dpop-proof-jwt>" \
  --data-urlencode "client_id=http://localhost" \
  --data-urlencode "response_type=code" \
  --data-urlencode "code_challenge=<S256-of-code-verifier>" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=<random-state>" \
  --data-urlencode "redirect_uri=http://127.0.0.1/" \
  --data-urlencode "scope=atproto transition:generic" \
  --data-urlencode "dpop_jkt=<jkt-of-your-dpop-key>"
# {"expires_in": N, "request_uri": "urn:ietf:params:oauth:request_uri:..."}
```

   **PAR requests expire** (`expires_in`, on the order of minutes) — the
   admin consent step must be completed promptly after this.

4. **Admin-minted consent** — replaces the human "Accept" click:

```bash
curl -fsS -X POST "https://$HOST/admin/oauth/authorize" \
  -u "admin:$ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"requestUri": "<request_uri from step 3>", "did": "<did from step 3 of setup>"}'
# {"code": "...", "state": "...", "redirectUri": "...", "iss": "https://$HOST"}
```

   This mints exactly the authorization code a signed-in human would receive;
   DPoP `jkt` and PKCE binding are still enforced at the token endpoint, so
   only the client that made the PAR request can exchange the code.

5. **Token exchange** (standard OAuth):

```bash
curl -fsS -X POST "https://$HOST/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "DPoP: <your-dpop-proof-jwt>" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=http://localhost" \
  --data-urlencode "code=<code from step 4>" \
  --data-urlencode "redirect_uri=http://127.0.0.1/" \
  --data-urlencode "code_verifier=<the-verifier>"
# {"access_token": "...", "refresh_token": "...", "token_type": "DPoP", "scope": "...", "sub": "<did>"}
```

Use `Authorization: DPoP <access_token>` plus a fresh DPoP proof header on
resource requests; refresh with `grant_type=refresh_token`.

## 7. Manage

All admin HTTP endpoints use Basic auth (`admin:$ADMIN_PASSWORD`).

**List accounts** (paginated; `limit` default 100, max 500; `offset` for paging):

```bash
curl -fsS -u "admin:$ADMIN_PASSWORD" "https://$HOST/admin/accounts?limit=100&offset=0"
# [{"did":"...","handle":"...","email":"...","active":true,"status":"","createdAt":"..."}]
```

**Account detail**:

```bash
curl -fsS -u "admin:$ADMIN_PASSWORD" "https://$HOST/admin/account?did=<did>"
# {"did":"...","handle":"...","email":"...","emailConfirmed":false,"active":true,"status":"","twoFactorType":"none","createdAt":"...","rev":"..."}
```

`active` is derived (true unless the account is taken down/suspended/deactivated);
`status` is the specific state (`takendown`/`suspended`/`deactivated`) or empty.

**Mint invite codes** — see step 2. `createInviteCodes` (plural) takes
`{"useCount": N}` and mints multiple codes.

**Reset a password** (CLI, machine-parseable):

```bash
docker compose exec cocoon /cocoon reset-password --json --did <did>
# {"did":"...","password":"..."}
```

**Recommit repos** — re-mints valid TID revs for repos with invalid revs and
re-announces their state on the firehose. **WARNING (verbatim from the CLI
usage): because firehose events use an in-memory sequence counter, the PDS
MUST be stopped while this runs, or sequence numbers will collide with the
live server.**

```bash
docker compose stop cocoon
docker compose run --rm cocoon /cocoon recommit-repos --json --dids <did>[,<did2>...]
# [{"did":"...","oldRev":"...","newRev":"...","oldHead":"...","newHead":"...","recommitted":true}]
# add --confirm to apply (default is dry-run); banners go to stderr, stdout is pure JSON
docker compose start cocoon
```

## 8. Troubleshooting

**Startup exits immediately** — these validation errors are fatal and specific
(see `server/server.go`):

- `cocoon did must be set` → `COCOON_DID` missing
- `cocoon hostname must be set` → `COCOON_HOSTNAME` missing
- `contact email must be set` → `COCOON_CONTACT_EMAIL` missing
- `admin password must be set` → `COCOON_ADMIN_PASSWORD` missing
- `SESSION SECRET WAS NOT SET. THIS IS REQUIRED.` → `COCOON_SESSION_SECRET` missing (panics)
- `database-url must be set when using postgres` → using `db-type=postgres` without `COCOON_DATABASE_URL`

**Health**: `curl -fsS "https://$HOST/xrpc/_health"` must return 200.

**Where things live**:

- `./data/` — SQLite database (or Postgres if configured)
- `./keys/` — `rotation.key`, `jwk.key`, `initial-invite-code.txt`

**Account creation hangs** → check network egress to `https://plc.directory`
(the `did:plc` minting path).

**OAuth admin consent returns "the request has expired"** → PAR requests
expire quickly; redo step 3 (PAR) and immediately step 4 (admin consent).

**401/400 on admin endpoints** → Basic auth is `admin` + the exact
`COCOON_ADMIN_PASSWORD` value; note the server returns HTTP 400 (not 401) for
bad credentials on admin routes.
