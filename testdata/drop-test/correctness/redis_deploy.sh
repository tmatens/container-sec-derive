#!/usr/bin/env bash
# valkey/redis correctness: accepts connections + a SET/GET round-trip, and the
# server dropped to a non-root uid (the entrypoint gosu/setpriv-drops via
# SETUID/SETGID; on a foreign-owned data dir it also chowns it — CHOWN).
#
# Auth-aware (#332): a valkey/redis started with `--requirepass <pw>` (immich
# added this in #36) answers an *unauthenticated* PING with NOAUTH, never PONG —
# so the old unauth PING looped to its deadline and the whole service derived as
# derive-error. We recover the password the server was actually started with from
# its argv (/proc/1/cmdline) and authenticate, so this works whether or not the
# service requires a password. The compose_derive ${VAR} placeholder is
# transparent: we read back whatever value the server was launched with (empty
# placeholder → no auth needed → plain PING still works).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS+30))
authflag=()
while :; do
  # (Re)discover any --requirepass from the running server's argv. cat runs in the
  # container; tr/awk parse on the host (so no awk is required inside the image).
  pw="$(docker exec "$C" cat /proc/1/cmdline 2>/dev/null | tr '\0' '\n' \
        | awk '/^--requirepass$/{if(getline v)print v; exit} /^--requirepass=/{sub(/^--requirepass=/,""); print; exit}')"
  authflag=(); [ -n "$pw" ] && authflag=(-a "$pw" --no-auth-warning)
  docker exec "$C" redis-cli "${authflag[@]}" ping 2>/dev/null | grep -qi PONG && break
  (( SECONDS >= deadline )) && { echo "redis not responding to PING (auth=$([ -n "$pw" ] && echo yes || echo no))"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done
docker exec "$C" redis-cli "${authflag[@]}" set csd:probe ok >/dev/null 2>&1 || { echo "SET failed"; exit 1; }
v="$(docker exec "$C" redis-cli "${authflag[@]}" get csd:probe 2>/dev/null | tr -d '[:space:]')"
[ "$v" = ok ] || { echo "GET returned '$v' (expected ok)"; exit 1; }
uid="$(docker exec "$C" cat /proc/1/status 2>/dev/null | awk '/^Uid:/{print $2}')"
[ "${uid:-0}" != 0 ] || { echo "redis running as ROOT (privilege drop failed)"; exit 1; }
echo "correct: PING + SET/GET (auth=$([ -n "$pw" ] && echo yes || echo no)), server uid=${uid} (non-root)"
