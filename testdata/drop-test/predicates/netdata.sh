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
  if curl -fsS --max-time 4 http://localhost:19999/api/v1/charts 2>/dev/null | grep -q '"apps\.'; then ready=1; break; fi
  sleep 3
done
[ "$ready" = 1 ] || { echo "not ready (status=${st}): API/apps.plugin not up"; exit 1; }
pid="$(docker inspect -f '{{.State.Pid}}' "$C")"
uid="$(awk '/^Uid:/{print $2}' /proc/"$pid"/status 2>/dev/null)"
[ "$uid" != 0 ] || { echo "daemon running as ROOT (privilege drop failed)"; exit 1; }
echo "correct: ready, apps.plugin collecting, daemon uid=${uid}"
