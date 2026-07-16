#!/usr/bin/env bash
# redis correctness: accepts connections, a SET/GET round-trip, AND a synchronous
# SAVE (a real RDB write to /data), and the server dropped to a non-root uid.
#
# The SAVE step (vs. the plainer redis_deploy.sh) exercises the persistence write
# path — the catalog evidence records "SET/GET + SAVE ok". With the image's
# pre-owned anonymous /data it succeeds with no CHOWN; a foreign-owned bind would
# make it the CHOWN-revealing step.
#
# SHARP EDGE: with SETUID/SETGID dropped, gosu cannot re-exec as redis and the
# server keeps serving correctly AS ROOT. The non-root uid assert is the ONLY
# signal that catches it — a round-trip-only check falsely derives both removable.
#
# Probes exec as the redis user (never root — a root probe's own needs would
# pollute the minimum) and /proc/1/status is parsed tool-free (no awk/cut, which
# a minimal base may lack).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS+30))
until grep -qi PONG <<<"$(docker exec --user redis "$C" redis-cli ping 2>/dev/null)"; do
  if (( SECONDS >= deadline )); then
    echo "redis not responding to PING"
    echo "  pid1: $(docker exec "$C" cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ')"
    echo "  logs: $(docker logs "$C" 2>&1 | tail -3 | tr '\n' '|')"
    exit 1
  fi
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

docker exec --user redis "$C" redis-cli set csd:probe ok >/dev/null 2>&1 || { echo "SET failed"; exit 1; }
v="$(docker exec --user redis "$C" redis-cli get csd:probe 2>/dev/null | tr -d '[:space:]')"
[ "$v" = ok ] || { echo "GET returned '$v' (expected ok)"; exit 1; }

grep -q OK <<<"$(docker exec --user redis "$C" redis-cli save 2>/dev/null)" || { echo "SAVE failed (cannot write the RDB to /data)"; exit 1; }

# Non-root server uid — parsed tool-free from /proc/1/status (the SHARP EDGE assert).
uid=""
while read -r k v _; do [ "$k" = "Uid:" ] && { uid="$v"; break; }; done < <(docker exec "$C" cat /proc/1/status 2>/dev/null)
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "redis running as ROOT (privilege drop failed; uid='${uid}')"; exit 1; }

echo "correct: SET/GET + SAVE ok, redis-server uid=${uid} (non-root)"
