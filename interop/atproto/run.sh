#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
atproto_root=${ATPROTO_ROOT:-"$HOME/worktrees/atproto/private-spaces-reference"}
port=${COCOON_INTEROP_PORT:-18080}
tmp=$(mktemp -d)
pid=

cleanup() {
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

go build -o "$tmp/cocoon" ./cmd/cocoon
"$tmp/cocoon" create-rotation-key --out "$tmp/rotation.key"
"$tmp/cocoon" create-private-jwk --out "$tmp/jwk.json"
go run ./interop/atproto/seed --db "$tmp/cocoon.db"

COCOON_ADDR="127.0.0.1:$port" \
COCOON_DB_NAME="$tmp/cocoon.db" \
COCOON_DID="did:web:interop.pds.test" \
COCOON_HOSTNAME="127.0.0.1:$port" \
COCOON_ROTATION_KEY_PATH="$tmp/rotation.key" \
COCOON_JWK_PATH="$tmp/jwk.json" \
COCOON_CONTACT_EMAIL="interop@pds.test" \
COCOON_ADMIN_PASSWORD="interop-admin" \
COCOON_SESSION_SECRET="interop-session-secret" \
COCOON_REQUIRE_INVITE=false \
COCOON_SPACES_ENABLED=true \
"$tmp/cocoon" run >"$tmp/cocoon.log" 2>&1 &
pid=$!

ready=false
for _ in $(seq 1 60); do
  if curl --silent --fail "http://127.0.0.1:$port/xrpc/_health" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  cat "$tmp/cocoon.log" >&2
  exit 1
fi

ATPROTO_ROOT="$atproto_root" \
COCOON_INTEROP_URL="http://127.0.0.1:$port" \
node "$repo_root/interop/atproto/reference-client.mjs"
