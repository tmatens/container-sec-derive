#!/usr/bin/env bash
# mosquitto correctness (capabilities + filesystem): default invocation. Real
# function = a publish/subscribe round-trip via the in-image mosquitto_sub /
# mosquitto_pub clients, driven as --user mosquitto so the probe cannot
# pollute a caps minimum (the rabbitmq lesson). Plus the non-root uid assert:
# the broker drops privileges IN-PROCESS when started as root — if the drop is
# broken it must not pass while serving as root.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS+20))
until grep -q "mosquitto version .* running" <<<"$(docker logs "$C" 2>&1)"; do
  (( SECONDS >= deadline )) && { echo "broker never reported running: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# pub/sub round-trip: subscriber in the foreground prints the one message to
# stdout; the publisher fires after a beat from the background. NO in-container
# file writes — a probe temp file under /tmp would derive the fs dimension's
# /tmp candidate falsely-required (probe pollution, filesystem edition).
got="$(docker exec --user mosquitto "$C" sh -c '
  (sleep 1; mosquitto_pub -h 127.0.0.1 -t csd/probe -m csd-42 2>/dev/null) &
  mosquitto_sub -h 127.0.0.1 -t csd/probe -C 1 -W 10 2>/dev/null' 2>/dev/null)"
[ "$got" = "csd-42" ] || { echo "pub/sub round-trip failed (got: ${got:-nothing})"; exit 1; }

# Broker dropped to a non-root uid (its own in-process drop).
uid="$(docker exec "$C" sh -c 'awk "/^Uid:/{print \$2}" /proc/1/status')"
[ "${uid:-0}" != 0 ] || { echo "mosquitto running as ROOT (in-process drop failed)"; exit 1; }

echo "correct: pub/sub round-trip ok, mosquitto uid=$uid (non-root)"
