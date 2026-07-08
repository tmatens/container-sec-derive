#!/usr/bin/env bash
# valkey/redis correctness: accepts connections + a SET/GET round-trip, and the
# server dropped to a non-root uid (the entrypoint gosu/setpriv-drops via
# SETUID/SETGID; on a foreign-owned data dir it also chowns it — CHOWN).
#
# Auth-aware (#332): a valkey/redis started with `--requirepass <pw>` (immich
# added this in #36) answers an *unauthenticated* PING with NOAUTH, never PONG,
# so an unauth check loops to its deadline and the whole service derives as
# derive-error. We recover the password from the container's CONFIGURED command
# (`docker inspect` .Config.Entrypoint/.Config.Cmd), NOT /proc/1/cmdline — an
# entrypoint/setpriv wrapper can leave pid 1 as something other than
# valkey-server, so the argv of pid 1 misses the flag while the child still
# enforces it. compose_derive doesn't substitute placeholders in `command`, so
# the server's requirepass is the literal ${VAR} string and we read back exactly
# that; a server with no requirepass needs no password (plain PING).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

# Recover any --requirepass from the container's configured argv (entrypoint +
# cmd), one token per line, parsed on the host.
argv="$(docker inspect -f '{{range .Config.Entrypoint}}{{println .}}{{end}}{{range .Config.Cmd}}{{println .}}{{end}}' "$C" 2>/dev/null)"
pw="$(printf '%s\n' "$argv" | awk '/^--requirepass$/{if(getline v)print v; exit} /^--requirepass=/{sub(/^--requirepass=/,""); print; exit}')"
authflag=(); [ -n "$pw" ] && authflag=(-a "$pw" --no-auth-warning)

deadline=$((SECONDS+30))
until docker exec "$C" redis-cli "${authflag[@]}" ping 2>/dev/null | grep -qi PONG; do
  if (( SECONDS >= deadline )); then
    # Rich diagnostics so a residual failure is legible, not another guess.
    echo "redis not responding to PING (auth=$([ -n "$pw" ] && echo yes || echo no))"
    echo "  cfg-cmd: $(printf '%s' "$argv" | tr '\n' ' ')"
    echo "  pid1:    $(docker exec "$C" cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ')"
    echo "  ping:    $(docker exec "$C" redis-cli "${authflag[@]}" ping 2>&1 | head -1)"
    echo "  logs:    $(docker logs "$C" 2>&1 | tail -3 | tr '\n' '|')"
    exit 1
  fi
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done
docker exec "$C" redis-cli "${authflag[@]}" set csd:probe ok >/dev/null 2>&1 || { echo "SET failed"; exit 1; }
v="$(docker exec "$C" redis-cli "${authflag[@]}" get csd:probe 2>/dev/null | tr -d '[:space:]')"
[ "$v" = ok ] || { echo "GET returned '$v' (expected ok)"; exit 1; }
uid="$(docker exec "$C" cat /proc/1/status 2>/dev/null | awk '/^Uid:/{print $2}')"
[ "${uid:-0}" != 0 ] || { echo "redis running as ROOT (privilege drop failed)"; exit 1; }
echo "correct: PING + SET/GET (auth=$([ -n "$pw" ] && echo yes || echo no)), server uid=${uid} (non-root)"
