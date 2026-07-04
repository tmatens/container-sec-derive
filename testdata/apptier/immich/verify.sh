#!/usr/bin/env bash
# immich app-tier check (run by scripts/apptier_verify.sh against the stack in
# ./docker-compose.yml). Drives immich's REAL REST API the way the app does:
# admin sign-up -> login -> upload a photo -> read it back -> search. Each step
# exercises the DB (and redis) that the leaf hardening touches, so if the applied
# caps break the DB's init / privilege-drop, immich never comes up and this fails.
#
# It uses a small COMMITTED synthetic JPEG (fixture.jpg) so no upstream test-assets
# submodule is needed — the "pull the pieces we need" approach (the real API +
# a real-enough asset), not immich's full pnpm/vitest e2e suite.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
API="${IMMICH_API:-http://127.0.0.1:2285/api}"
FIXTURE="${IMMICH_FIXTURE:-$HERE/fixture.jpg}"
[ -f "$FIXTURE" ] || { echo "no fixture at $FIXTURE"; exit 1; }

# immich-server runs DB migrations on first boot (~30-60s) — wait for it.
ready=""
for _ in $(seq 1 45); do
  if curl -fsS --max-time 3 "$API/server/ping" >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ -n "$ready" ] || { echo "immich-server never became reachable (migrations failed under the hardening?)"; exit 1; }

# 1. first-user admin sign-up (DB write). Idempotent-ish: ignore a 4xx if it exists.
curl -fsS -X POST "$API/auth/admin-sign-up" -H 'Content-Type: application/json' \
  -d '{"email":"admin@csd.test","password":"password","name":"CSD"}' >/dev/null 2>&1 || true

# 2. login (DB read + auth) -> bearer token
TOKEN="$(curl -fsS -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"admin@csd.test","password":"password"}' 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["accessToken"])' 2>/dev/null)"
[ -n "$TOKEN" ] || { echo "login failed"; exit 1; }

# 3. upload a real asset (DB write + file store + processing)
AID="$(curl -fsS -X POST "$API/assets" -H "Authorization: Bearer $TOKEN" \
  -F "assetData=@$FIXTURE" -F deviceAssetId=csd-1 -F deviceId=csd \
  -F fileCreatedAt=2026-01-01T00:00:00.000Z -F fileModifiedAt=2026-01-01T00:00:00.000Z 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)"
[ -n "$AID" ] || { echo "asset upload failed"; exit 1; }

# 4. read it back (DB read)
curl -fsS "$API/assets/$AID" -H "Authorization: Bearer $TOKEN" >/dev/null 2>&1 \
  || { echo "asset read-back failed"; exit 1; }

# 5. metadata search (DB query)
N="$(curl -fsS -X POST "$API/search/metadata" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{}' 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["assets"]["total"])' 2>/dev/null)"
[ "$N" = 1 ] || { echo "metadata search returned ${N:-?} assets (expected 1)"; exit 1; }

echo "immich app-tier OK: sign-up + login + upload + read-back + search (1 asset)"
