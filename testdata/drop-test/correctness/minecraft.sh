#!/usr/bin/env bash
# minecraft (itzg/minecraft-server) correctness (capabilities). The entrypoint runs
# as root and gosu-drops to the minecraft user (uid 1000) to run the server. The
# image ships /data owned by 1000, so a docker-managed volume inherits that
# ownership (no datadir chown needed). SETUID/SETGID (the gosu drop) are startup
# caps, invisible to runtime observation. This asserts the server actually accepts a
# status ping AND runs as the non-root minecraft uid — a health/liveness alone would
# pass while running as root.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS+150))
until docker exec "$C" mc-monitor status --host localhost --port 25565 >/dev/null 2>&1; do
  (( SECONDS >= deadline )) && { echo "minecraft server never became ready (mc-monitor status)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in *java) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "minecraft server (java) running as ROOT or not found (gosu drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: server responds to status ping, java uid=$uid (non-root)"
