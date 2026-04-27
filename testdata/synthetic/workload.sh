#!/usr/bin/env bash
# Workload script for the synthetic cap-exerciser fixture.
#
# Unlike the postgres/caddy/tailscale workloads, this script does NOT
# drive the container — the container's ENTRYPOINT (the exerciser
# binary) drives capable() events on its own, in a continuous loop.
# This script just verifies the exerciser is alive and producing
# cycle output, then sleeps to keep the workload script in scope for
# csd's confidence rubric "workload script provided" factor.
#
# Required env: CONTAINER (target container name or id).
set -euo pipefail

: "${CONTAINER:?CONTAINER must be set}"

deadline=$((SECONDS + 30))
until docker logs "${CONTAINER}" 2>&1 | grep -q '^cycle='; do
    if (( SECONDS >= deadline )); then
        echo "exerciser produced no cycle logs in 30s" >&2
        exit 1
    fi
    sleep 1
done
echo "exerciser is cycling"
