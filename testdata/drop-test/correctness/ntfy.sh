#!/usr/bin/env bash
# ntfy correctness (capabilities + filesystem): default `serve` invocation.
# Real function = publish a message to a topic and poll it back, matching the
# payload. Probes ride the curl sidecar, write nothing in the target, and
# capture-then-match (never `curl | grep -q` under pipefail).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

deadline=$((SECONDS+30))
until [ "$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:80/v1/health 2>/dev/null)" = 200 ]; do
  (( SECONDS >= deadline )) && { echo "ntfy never healthy: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 -d "csd-msg-42" http://localhost:80/csdtopic 2>/dev/null)"
[ "$code" = 200 ] || { echo "publish failed: HTTP ${code:-none}"; exit 1; }
got="$(sidecar_curl -s --max-time 5 "http://localhost:80/csdtopic/json?poll=1&since=all" 2>/dev/null)"
case "$got" in *'"message":"csd-msg-42"'*) ;; *) echo "poll missing message (got: ${got:0:80})"; exit 1;; esac

echo "correct: publish/poll round-trip ok"
