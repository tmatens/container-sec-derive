#!/usr/bin/env bash
# loki correctness (filesystem). loki is DISTROLESS (no shell/curl), so it is
# probed from a SIDECAR sharing its network namespace (see lib/sidecar.sh), not
# via `docker exec`. loki runs as a non-root user (uid 10001) and writes its data
# under /loki — a PERSISTENT VOLUME in real deployments (chunks, WAL, index; must
# survive restarts, so NOT tmpfs). The drop-test supplies /loki as a writable
# stand-in via run.tmpfs (mode=1777 so the non-root uid can write it) and never
# counts it in the derived tmpfs minimum.
#
# This exercises loki's real read+write path, not liveness: push a log line and
# query it back.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

# 1. ready
deadline=$((SECONDS+60))
until [ "$(sidecar_curl -s http://localhost:3100/ready 2>/dev/null)" = ready ]; do
  (( SECONDS >= deadline )) && { echo "loki /ready never reported ready"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

# 2. push a log line (nanosecond timestamp computed here on the host)
ts="$(date +%s%N)"
code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  --data "{\"streams\":[{\"stream\":{\"job\":\"csd\"},\"values\":[[\"$ts\",\"csd-probe-line\"]]}]}" \
  http://localhost:3100/loki/api/v1/push 2>/dev/null)"
[ "$code" = 204 ] || { echo "loki push returned HTTP $code (expected 204)"; exit 1; }

# 3. query it back (read from the ingester); retry for the brief ingest delay
start=$((ts-300000000000)); end=$((ts+300000000000))
found=""
for _ in 1 2 3 4 5; do
  # capture-then-match via herestring — never `sidecar_curl | grep -q` under
  # pipefail (grep -q's early exit SIGPIPEs curl → a matching but large query
  # result can false-negative once it outgrows the pipe buffer).
  if grep -q csd-probe-line <<<"$(sidecar_curl -s "http://localhost:3100/loki/api/v1/query_range?query=%7Bjob%3D%22csd%22%7D&start=$start&end=$end&limit=5" 2>/dev/null)"; then
    found=1; break
  fi
  sleep 1
done
[ -n "$found" ] || { echo "pushed log line not returned by query (loki read/write path broken)"; exit 1; }

echo "correct: loki ready, log push (204) + query round-trip returned the line"
