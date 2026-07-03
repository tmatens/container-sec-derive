#!/usr/bin/env bash
# Correct iff caddy serves the default file server: a GET on :80 returns.
# NET_BIND_SERVICE is required to bind the privileged :80; without it caddy
# cannot listen and this fails. The caddy image ships wget, so the check runs
# via docker exec inside the container — no host ports to publish (drop-test
# runs many containers; keeping it port-free avoids collisions).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS + 20))
while (( SECONDS < deadline )); do
  if docker exec "$C" wget -qO- http://localhost/ >/dev/null 2>&1; then
    echo "caddy serving the file server on :80"
    exit 0
  fi
  # If caddy could not bind :80 it exits — stop waiting on a dead container.
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = "true" ] || break
  sleep 1
done
echo "caddy not serving on :80 (bind failed or container exited)"
exit 1
