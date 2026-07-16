#!/usr/bin/env bash
# httpd correctness (capabilities): default invocation. The master stays root
# and forks workers that setuid/setgid to www-data — so pass requires BOTH the
# served default page and a non-root worker process.
#
# The uid assert is mandatory (redis-class sharp edge, master/worker variant):
# with SETUID/SETGID dropped, httpd logs "could not set gid/uid" but KEEPS
# SERVING with root workers — the content check alone false-passes.
#
# The image ships no curl/wget, so the page is fetched from the curl sidecar
# (lib/sidecar.sh). The uid probe reads world-readable /proc files only, so it
# cannot pollute the minimum.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

deadline=$((SECONDS+30))
while :; do
  body="$(sidecar_curl -s --max-time 5 http://localhost:80/ 2>/dev/null)"
  case "$body" in *"It works!"*) break;; esac
  (( SECONDS >= deadline )) && { echo "default page never served (last: ${body:0:60})"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# A worker (a non-PID-1 httpd) must run NON-root — the www-data drop.
wuid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do pid=${p#/proc/}; [ "$pid" = 1 ] && continue; a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in httpd|*/httpd) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$wuid" ] && [ "$wuid" != 0 ] || { echo "httpd workers running as ROOT or not found (drop failed): uid=${wuid:-none}"; exit 1; }

echo "correct: default page served, worker uid=$wuid (non-root)"
