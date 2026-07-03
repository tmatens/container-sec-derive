#!/usr/bin/env bash
# Generic deploy-time predicate: the container is still running a few seconds
# after start (didn't crash-loop on a missing capability).
#
# This is deliberately WEAK, and the weakness is the point to understand: "still
# running" is not "correct." A container can stay up while doing the wrong thing
# — netdata drops SETUID/SETGID and keeps running, but as ROOT. Deriving against
# a service's real invocation removes the *matching* guesswork, but the
# correctness bar is still per-service: prefer a predicate that asserts the
# intended posture (a request served, a non-root uid, a passing workload). Supply
# one via PREDICATE; this default is the floor when none is given.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
C="$DROP_TEST_CONTAINER"

sleep 4
if [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = "true" ]; then
  echo "container running (generic liveness — not a correctness proof)"
  exit 0
fi
echo "container exited: $(docker inspect -f '{{.State.Status}} rc={{.State.ExitCode}}' "$C" 2>/dev/null)"
exit 1
