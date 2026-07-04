#!/usr/bin/env bash
# Correct iff netdata becomes ready (API + apps.plugin, which needs SYS_PTRACE)
# AND the daemon dropped from root to a non-root uid. Liveness alone is not
# enough: without SETUID/SETGID netdata runs "healthy" as root — the exact trap.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
ready=0; st=""
deadline=$((SECONDS+90))
while (( SECONDS < deadline )); do
  st="$(docker inspect -f '{{.State.Status}}' "$C" 2>/dev/null)"
  [ "$st" != running ] && break
  charts="$(curl -fsS --max-time 4 http://localhost:19999/api/v1/charts 2>/dev/null || true)"
  # capture then grep — piping a large response into `grep -q` can SIGPIPE curl
  # and, under pipefail, mark the pipeline failed despite a match.
  if grep -q '"apps\.' <<<"$charts"; then ready=1; break; fi
  sleep 3
done
[ "$ready" = 1 ] || { echo "not ready (status=${st}): API/apps.plugin not up"; exit 1; }
# Identity guard: with --network host, :19999 is host-wide, so a stale/foreign
# netdata would answer the queries above and we'd grade the wrong container.
# Confirm the instance responding is THIS container: its own machine guid (in its
# ephemeral fs) must equal the uid the API reports. Skip only if the guid can't be
# read (best-effort; the harness port preflight is the primary guard).
api_uid="$(curl -fsS --max-time 4 http://localhost:19999/api/v1/info 2>/dev/null \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("uid",""))' 2>/dev/null)"
c_guid="$(docker exec "$C" cat /var/lib/netdata/registry/netdata.public.unique.id 2>/dev/null | tr -d '[:space:]')"
if [ -n "$c_guid" ] && [ -n "$api_uid" ] && [ "$c_guid" != "$api_uid" ]; then
  echo "identity mismatch: :19999 (uid=${api_uid}) is NOT this container (${c_guid}) — port pollution"; exit 1
fi
pid="$(docker inspect -f '{{.State.Pid}}' "$C")"
uid="$(awk '/^Uid:/{print $2}' /proc/"$pid"/status 2>/dev/null)"
[ "$uid" != 0 ] || { echo "daemon running as ROOT (privilege drop failed)"; exit 1; }
echo "correct: ready, apps.plugin collecting, daemon uid=${uid}"
