#!/usr/bin/env bash
# haproxy correctness (capabilities): reverse-proxy invocation. Real function
# = a request on frontend :8080 proxied to the in-stack caddy `backend` and
# answered with its content. Probed from the curl sidecar; haproxy runs as
# USER haproxy (non-root by construction — assert it anyway).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

deadline=$((SECONDS+30))
while :; do
  body="$(sidecar_curl -s --max-time 5 http://localhost:8080/ 2>/dev/null)"
  case "$body" in *[Cc]addy*) break;; esac
  (( SECONDS >= deadline )) && { echo "no proxied backend response (last: ${body:0:60})"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

uid="$(docker exec "$C" sh -c 'awk "/^Uid:/{print \$2}" /proc/1/status')"
[ "${uid:-0}" != 0 ] || { echo "haproxy running as ROOT (image should be USER haproxy)"; exit 1; }

echo "correct: :8080 proxied to caddy backend, haproxy uid=$uid (non-root)"
