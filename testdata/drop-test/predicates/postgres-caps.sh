#!/usr/bin/env bash
# Correct iff postgres serves the workload AND its server process runs as the
# non-root postgres user. The official entrypoint starts as root and drops to
# the postgres user via gosu at startup (needs SETUID/SETGID); on a fresh data
# dir it also creates + chowns the data dir (initdb). Without those startup caps
# gosu/initdb fails and the container never becomes ready — so this asserts both
# workload correctness and that the privilege drop actually happened (the
# "healthy-while-root" trap, per the netdata lesson).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
C="$DROP_TEST_CONTAINER"
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"

# Workload: readiness poll + CREATE/INSERT/SELECT/DROP + a SIGHUP reload.
PGCONTAINER="$C" bash "${REPO}/testdata/postgres/workload.sh" || { echo "workload failed / not ready"; exit 1; }

# Privilege drop: the postgres server (PID 1) must not be running as root.
uid="$(docker exec "$C" awk '/^Uid:/{print $2}' /proc/1/status 2>/dev/null)"
if [ "${uid:-0}" = "0" ]; then
  echo "postgres running as ROOT (privilege drop failed)"
  exit 1
fi
echo "correct: workload passed, server uid=${uid} (non-root)"
