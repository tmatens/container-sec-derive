#!/usr/bin/env bash
# traefik correctness (filesystem): same routed-proxy pass signal as traefik.sh
# (:80 -> router -> the in-stack caddy `backend`), but the dynamic file-provider
# config is supplied by a READ-ONLY seed_mount fixture (run.seed_mounts with
# read_only:true), NOT docker-cp'd into a writable /tmp. That is the whole point
# of the fs variant: the caps check writes the config into /tmp, which under
# --read-only would falsely require a /tmp tmpfs; here the config rides a
# read-only mount, so the derivation sees traefik's real (empty) rootfs write set.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

# The routed response must come from the caddy backend (its default page).
deadline=$((SECONDS+45))
while :; do
  body="$(sidecar_curl -s --max-time 5 http://localhost:80/ 2>/dev/null)"
  case "$body" in *[Cc]addy*) break;; esac
  (( SECONDS >= deadline )) && { echo "no routed backend response (last: ${body:0:60})"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done
echo "correct: :80 routed through traefik to the caddy backend (read-only rootfs)"
