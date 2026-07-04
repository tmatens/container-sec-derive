#!/usr/bin/env bash
# netdata correctness check — asserts the container is not merely alive but
# delivering its real monitoring value, so capabilities can be honestly
# drop-tested. Four assertions, each tied to what a cap gates:
#   1. API + apps.plugin up (readiness).
#   2. Identity: the netdata answering :19999 is THIS container (port-pollution
#      guard; --network host makes :19999 host-wide).
#   3. The daemon dropped root -> a non-root uid. Liveness alone is not enough:
#      without SETUID/SETGID netdata runs "healthy" AS ROOT — the exact trap.
#   4. Per-process io/fd metrics carry data for a NON-ROOT process group
#      (netdata's own uid-201 processes). Reading another uid's /proc/<pid>/io
#      and /fd is what DAC_OVERRIDE / SYS_PTRACE would gate — asserting a
#      non-root group's data (not a root process, which any root reader sees for
#      free) is what makes those caps honestly testable. If the check only
#      asserted "apps.plugin up", a needed cap would read as removable.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

API=http://localhost:19999
# chart_has_data <chart-id> -> 0 if the chart's latest sample has a non-null
# value on any dimension (0 counts as data — the point is it's being collected).
chart_has_data() {
  curl -fsS --max-time 4 "${API}/api/v1/data?chart=$1&after=-20&points=1&format=json" 2>/dev/null \
    | python3 -c 'import sys,json
try:
 rows=json.load(sys.stdin).get("data",[])
 sys.exit(0 if [v for r in rows for v in r[1:] if v is not None] else 1)
except Exception:
 sys.exit(1)'
}

# 1. readiness: apps.plugin charts defined
ready=0; st=""
deadline=$((SECONDS+90))
while (( SECONDS < deadline )); do
  st="$(docker inspect -f '{{.State.Status}}' "$C" 2>/dev/null)"
  [ "$st" != running ] && break
  charts="$(curl -fsS --max-time 4 "${API}/api/v1/charts" 2>/dev/null || true)"
  # capture then grep — piping a large response into `grep -q` can SIGPIPE curl
  # and, under pipefail, mark the pipeline failed despite a match.
  if grep -q '"apps\.' <<<"$charts"; then ready=1; break; fi
  sleep 3
done
[ "$ready" = 1 ] || { echo "not ready (status=${st}): API/apps.plugin not up"; exit 1; }

# 2. identity guard: the machine guid the API reports must equal this
# container's own guid file (else a foreign netdata is answering :19999).
api_uid="$(curl -fsS --max-time 4 "${API}/api/v1/info" 2>/dev/null \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("uid",""))' 2>/dev/null)"
c_guid="$(docker exec "$C" cat /var/lib/netdata/registry/netdata.public.unique.id 2>/dev/null | tr -d '[:space:]')"
if [ -n "$c_guid" ] && [ -n "$api_uid" ] && [ "$c_guid" != "$api_uid" ]; then
  echo "identity mismatch: :19999 (uid=${api_uid}) is NOT this container (${c_guid}) — port pollution"; exit 1
fi

# 3. daemon dropped to a non-root uid
pid="$(docker inspect -f '{{.State.Pid}}' "$C")"
uid="$(awk '/^Uid:/{print $2}' /proc/"$pid"/status 2>/dev/null)"
[ "$uid" != 0 ] || { echo "daemon running as ROOT (privilege drop failed)"; exit 1; }

# 4. per-process metrics collect for a NON-ROOT group (netdata, uid 201).
# apps.plugin needs a few cycles after the charts appear to populate data, so
# poll. app.netdata_fds_open is a stable non-null signal (a live process always
# has open fds); reading it for a non-root process is the DAC_OVERRIDE/SYS_PTRACE
# sensitive path. Fall back across a couple of non-root groups for robustness.
ppdata=0
for _ in 1 2 3 4 5 6 7 8; do
  for ch in app.netdata_fds_open app.netdata_disk_logical_io app.polkitd_fds_open; do
    if chart_has_data "$ch"; then ppdata=1; PPCH="$ch"; break 2; fi
  done
  sleep 3
done
[ "$ppdata" = 1 ] || { echo "no per-process metrics for a non-root group (DAC_OVERRIDE/SYS_PTRACE gap): apps.plugin can't read non-root /proc/<pid>"; exit 1; }

echo "correct: ready, daemon uid=${uid}, per-process metrics collecting for non-root group (${PPCH})"
