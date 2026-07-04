#!/usr/bin/env bash
# alloy correctness (filesystem). Grafana Alloy is DISTROLESS (no shell/curl), so
# it is probed from a SIDECAR sharing its network namespace (lib/sidecar.sh) — the
# same reusable helper loki uses. Under the image default invocation
# (`run /etc/alloy/config.alloy --storage.path=/var/lib/alloy/data`) alloy loads its
# pipeline (a unix-exporter scrape -> remote_write WAL) and writes its data under
# storage.path. alloy FATALS at startup if storage.path isn't writable, so
# "ready + a live pipeline" already exercises the storage.path write. alloy runs as
# the non-root alloy user (uid 473), so the /var/lib/alloy stand-in is mode=1777.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

deadline=$((SECONDS+45))
until [ "$(sidecar_curl -s -o /dev/null -w '%{http_code}' http://localhost:12345/-/ready 2>/dev/null)" = 200 ]; do
  (( SECONDS >= deadline )) && { echo "alloy /-/ready never returned 200"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# real pipeline loaded: alloy exports its own component/build metrics once running
n="$(sidecar_curl -s http://localhost:12345/metrics 2>/dev/null | grep -c '^alloy_')"
[ "${n:-0}" -ge 1 ] || { echo "no alloy_ metrics — pipeline not running"; exit 1; }

echo "correct: alloy ready, pipeline live ($n alloy_ metrics), storage.path writable"
