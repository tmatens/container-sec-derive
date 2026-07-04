#!/usr/bin/env bash
# App-tier verify — the second correctness tier for a MULTI-CONTAINER service
# (docs/app-tier-verification.md).
#
# The drop-test loop derives each container's minimum caps cheaply, one container
# at a time (a container's caps are composition-independent). But a service like
# immich is several containers working together, and "the DB is correct in
# isolation" is not "immich still works." This harness closes that gap: it brings
# up the WHOLE stack with the hardening applied and runs a service-level check
# that drives the app's REAL API — reusing the upstream project's fixtures rather
# than standing up its full (CI-coupled) e2e suite.
#
# The compose file should already encode the caps you're validating (the derived
# minimums). The verify script exits 0 iff the service does its real job.
#
#   scripts/apptier_verify.sh <compose.yml> <verify.sh>
#
# Live only: needs docker + the `docker compose` v2 plugin (and, per service, a
# network pull). Not a hermetic/per-PR gate — run on demand / on the BPF host.
set -uo pipefail

COMPOSE="${1:?usage: apptier_verify.sh <compose.yml> <verify.sh>}"
VERIFY="${2:?usage: apptier_verify.sh <compose.yml> <verify.sh>}"
command -v docker >/dev/null 2>&1 || { echo "apptier: docker required" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "apptier: the docker compose v2 plugin is required" >&2; exit 2; }
[ -f "$COMPOSE" ] || { echo "apptier: no compose file at $COMPOSE" >&2; exit 2; }
[ -x "$VERIFY" ] || [ -f "$VERIFY" ] || { echo "apptier: no verify script at $VERIFY" >&2; exit 2; }
CF="$(cd "$(dirname "$COMPOSE")" && pwd)/$(basename "$COMPOSE")"

teardown() { docker compose -f "$CF" down -v >/dev/null 2>&1; }
trap teardown EXIT

echo "apptier: bringing up the stack — docker compose -f ${COMPOSE} up -d" >&2
if ! docker compose -f "$CF" up -d >/dev/null 2>"$CF.uperr"; then
  echo "apptier: compose up failed" >&2; tail -10 "$CF.uperr" >&2; rm -f "$CF.uperr"; exit 3
fi
rm -f "$CF.uperr"

bash "$VERIFY"; rc=$?
if [ "$rc" = 0 ]; then
  echo "apptier: PASS — the service works with the applied hardening" >&2
else
  echo "apptier: FAIL (rc=${rc}) — the hardening broke the service (see the check output above)" >&2
fi
exit "$rc"
