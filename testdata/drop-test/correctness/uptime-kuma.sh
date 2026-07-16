#!/usr/bin/env bash
# uptime-kuma correctness (capabilities): default v2 invocation. Drives what
# the REST surface allows: entry-page, database setup with embedded sqlite (a
# real persistent write under /app/data), the server's self-restart, then
# serving again + the metrics auth layer answering 401 (auth stack up).
# Admin/monitor CRUD is socket.io-only — see the spec's coverage note.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

wait_api() { # <deadline-seconds> <want-substr>
  local dl=$((SECONDS+$1))
  while :; do
    local r; r="$(sidecar_curl -s --max-time 5 http://localhost:3001/api/entry-page 2>/dev/null)"
    case "$r" in *"$2"*) return 0;; esac
    (( SECONDS >= dl )) && { echo "entry-page never matched '$2' (last: ${r:0:60})"; return 1; }
    [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; return 1; }
    sleep 3
  done
}

wait_api 90 "setup-database" || exit 1
code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H 'Content-Type: application/json' -d '{"dbConfig":{"type":"sqlite"}}' http://localhost:3001/setup-database 2>/dev/null)"
[ "$code" = 200 ] || { echo "setup-database failed: HTTP ${code:-none}"; exit 1; }
# The server restarts itself after DB setup; wait for it to serve again.
sleep 3
wait_api 90 "entryPage" || exit 1
mcode="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:3001/metrics 2>/dev/null)"
[ "$mcode" = 401 ] || { echo "metrics auth layer unexpected: HTTP ${mcode:-none}"; exit 1; }

echo "correct: sqlite setup + self-restart + serving, auth layer up"
