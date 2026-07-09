#!/usr/bin/env bash
# Correctness check for the seed-fidelity synthetic (csd#340 item 2). Correct iff
# the entrypoint reached its READY marker — i.e. it successfully read the mounted
# content (or found none, in the fresh control). A trial that dropped the required
# CAP_DAC_OVERRIDE while a foreign-owned 0600 file is present fails the read,
# exits before the marker, and is graded incorrect → the cap derives needed.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
C="$DROP_TEST_CONTAINER"

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if docker exec "$C" cat /tmp/csd-ready >/dev/null 2>&1; then
    echo "correct: entrypoint reached READY (content accessible)"
    exit 0
  fi
  # If the container already exited (read denied → non-zero exit), stop waiting.
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || break
  sleep 0.5
done

echo "incorrect: entrypoint never reached READY — $(docker logs "$C" 2>&1 | grep -v '^[[:space:]]*$' | tail -1)"
exit 1
