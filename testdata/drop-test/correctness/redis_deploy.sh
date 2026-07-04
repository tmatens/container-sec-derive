#!/usr/bin/env bash
# valkey/redis correctness: accepts connections + a SET/GET round-trip, and the
# server dropped to a non-root uid (the entrypoint gosu-drops via SETUID/SETGID;
# on a foreign-owned data dir it also chowns it — CHOWN).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
deadline=$((SECONDS+30))
until docker exec "$C" redis-cli ping 2>/dev/null | grep -qi PONG; do
  (( SECONDS >= deadline )) && { echo "redis not responding to PING"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done
docker exec "$C" redis-cli set csd:probe ok >/dev/null 2>&1 || { echo "SET failed"; exit 1; }
v="$(docker exec "$C" redis-cli get csd:probe 2>/dev/null | tr -d '[:space:]')"
[ "$v" = ok ] || { echo "GET returned '$v' (expected ok)"; exit 1; }
uid="$(docker exec "$C" awk '/^Uid:/{print $2}' /proc/1/status 2>/dev/null)"
[ "${uid:-0}" != 0 ] || { echo "redis running as ROOT (privilege drop failed)"; exit 1; }
echo "correct: PING + SET/GET, server uid=${uid} (non-root)"
