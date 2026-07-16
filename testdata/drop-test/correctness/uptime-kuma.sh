#!/usr/bin/env bash
# uptime-kuma correctness (capabilities): default v2 invocation. Real function
# now includes a RUNNING HTTP monitor, driven over socket.io (the admin/monitor
# API is socket.io-only — no REST). Flow: HTTP database setup, then a socket.io
# probe (setup admin -> login -> add an HTTP monitor -> confirm an UP
# heartbeat) run from a SIDECAR using the uptime-kuma image itself (node +
# socket.io-client baked in) sharing the target's netns, with the probe script
# bind-mounted so nothing is written inside the target.
#
# The paired ping spec (uptime-kuma-ping-caps.yaml) runs the same probe with a
# PING monitor; the NET_RAW delta between the two isolates ping's raw-ICMP
# requirement as measured evidence.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"
# The spec selects the monitor type via run.env (CSD_UK_MONITOR), which lands in
# the CONTAINER, not this host-side script — so read it back from the container
# (default http). The ping spec sets it to `ping`.
MON_TYPE="$(docker exec "$C" printenv CSD_UK_MONITOR 2>/dev/null || true)"
MON_TYPE="${MON_TYPE:-http}"
# Absolute path — docker -v rejects a relative source.
PROBE_JS="$(cd "$(dirname "$0")/lib" && pwd)/uptime-kuma-probe.cjs"
# The uptime-kuma image, pinned by digest, doubles as the socket.io probe image.
UK_PROBE_IMAGE="${CSD_PROBE_UK_IMAGE:-louislam/uptime-kuma@sha256:91e963bfda569ba115206e843febb446f473ab525add4e08b2b9e3beffa16985}"

# Web tier up (302 to login is "ready").
deadline=$((SECONDS+90))
until case "$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:3001/api/entry-page 2>/dev/null)" in 200|30?|40?) true;; *) false;; esac; do
  (( SECONDS >= deadline )) && { echo "uptime-kuma web never answered"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 3
done

# Choose the embedded sqlite backend (a real persistent write under /app/data).
code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H 'Content-Type: application/json' -d '{"dbConfig":{"type":"sqlite"}}' http://localhost:3001/setup-database 2>/dev/null)"
[ "$code" = 200 ] || { echo "setup-database failed: HTTP ${code:-none}"; exit 1; }
sleep 3
# Serving again after the self-restart.
deadline=$((SECONDS+90))
until grep -q entryPage <<<"$(sidecar_curl -s --max-time 5 http://localhost:3001/api/entry-page 2>/dev/null)"; do
  (( SECONDS >= deadline )) && { echo "server did not serve after DB setup"; exit 1; }
  sleep 3
done

# socket.io probe: add a monitor of MON_TYPE and confirm it reports UP. Runs in
# a throwaway sidecar in the target's netns, probe script bind-mounted read-only
# INTO /app so node resolves the image's baked-in socket.io-client from
# /app/node_modules (a script at / would look in the absent /node_modules).
docker run --rm --network "container:${C}" -w /app \
  -v "$PROBE_JS:/app/csd-uk-probe.cjs:ro" \
  "$UK_PROBE_IMAGE" node /app/csd-uk-probe.cjs "$MON_TYPE" \
  || { echo "socket.io ${MON_TYPE} monitor did not run"; exit 1; }

echo "correct: sqlite setup + ${MON_TYPE} monitor running (UP heartbeat)"
