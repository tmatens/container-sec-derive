#!/usr/bin/env bash
# Correctness for a postgres service under its REAL compose (e.g. immich's
# `database`). The credentials come from the compose's POSTGRES_* env — which
# compose_derive may have replaced with a synthetic placeholder where the compose
# used a ${VAR} secret — so read them FROM THE CONTAINER rather than assuming the
# "postgres" defaults, then drive the reference workload with them. Also assert the
# server dropped to a non-root uid: the entrypoint starts as root and drops via
# gosu (SETUID/SETGID), and on a fresh data dir it chowns + initdb's (CHOWN); if
# those startup caps are missing the drop/init fails and the container never
# becomes ready. Asserting the non-root uid guards the "healthy-while-root" trap.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
C="$DROP_TEST_CONTAINER"
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"

# Credentials as this container was actually initialized (fall back to postgres
# defaults for an image that hard-codes them).
U="$(docker exec "$C" printenv POSTGRES_USER 2>/dev/null || true)"; U="${U:-postgres}"
P="$(docker exec "$C" printenv POSTGRES_PASSWORD 2>/dev/null || true)"; P="${P:-postgres}"
D="$(docker exec "$C" printenv POSTGRES_DB 2>/dev/null || true)"; D="${D:-$U}"

PGCONTAINER="$C" PGUSER="$U" PGPASSWORD="$P" PGDATABASE="$D" \
  bash "${REPO}/testdata/postgres/workload.sh" || { echo "workload failed / not ready"; exit 1; }

uid="$(docker exec "$C" awk '/^Uid:/{print $2}' /proc/1/status 2>/dev/null)"
if [ "${uid:-0}" = "0" ]; then
  echo "postgres running as ROOT (privilege drop failed)"
  exit 1
fi
echo "correct: workload passed as user=${U}, server uid=${uid} (non-root)"
