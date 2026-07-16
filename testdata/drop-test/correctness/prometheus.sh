#!/usr/bin/env bash
# prometheus correctness (capabilities + filesystem): default invocation. The
# image runs as USER nobody (uid 65534) from the start — no root phase, no
# privilege drop — so docker exec inherits nobody and the probe cannot pollute
# a caps minimum (the rabbitmq lesson, avoided by construction).
#
# Real function: readiness, then the query API must show the default config's
# SELF-SCRAPE actually produced samples (up == 1 for localhost:9090). A ready
# endpoint alone passes before the first scrape completes, so we wait for the
# scrape (default interval 15s in the bundled config). Probes use the in-image
# busybox wget.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

# capture-then-match via a herestring throughout — never `wget | grep -q`
# under pipefail (grep -q's early exit SIGPIPEs wget → the loop condition
# can false-negative on a matching body once it outgrows the pipe buffer).
deadline=$((SECONDS+45))
until grep -qi ready <<<"$(docker exec "$C" wget -qO- http://localhost:9090/-/ready 2>/dev/null)"; do
  (( SECONDS >= deadline )) && { echo "prometheus never ready"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# Wait for the first self-scrape to land: up{job="prometheus"} == 1.
deadline=$((SECONDS+45))
until grep -q '"value":\[[0-9.]*,"1"\]' <<<"$(docker exec "$C" wget -qO- 'http://localhost:9090/api/v1/query?query=up' 2>/dev/null)"; do
  (( SECONDS >= deadline )) && { echo "self-scrape never produced up==1"; exit 1; }
  sleep 2
done

# TSDB actually ingested samples (exercises the /prometheus write path). The
# counter reads 0 on the scrape that first reports it (appends land after the
# scrape), so poll until a later scrape shows a non-zero value.
deadline=$((SECONDS+60))
until grep -qE '"value":\[[0-9.]*,"[1-9][0-9]*"' <<<"$(docker exec "$C" wget -qO- 'http://localhost:9090/api/v1/query?query=prometheus_tsdb_head_samples_appended_total' 2>/dev/null)"; do
  (( SECONDS >= deadline )) && { echo "TSDB never appended samples"; exit 1; }
  sleep 2
done

# Serving as non-root (USER nobody, no drop to perform — assert it anyway).
uid="$(docker exec "$C" sh -c 'awk "/^Uid:/{print \$2}" /proc/1/status')"
[ "${uid:-0}" != 0 ] || { echo "prometheus running as ROOT"; exit 1; }

echo "correct: self-scrape up==1, TSDB appending samples, prometheus uid=${uid} (non-root)"
