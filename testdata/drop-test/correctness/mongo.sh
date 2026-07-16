#!/usr/bin/env bash
# mongo correctness (capabilities): default root invocation on fresh data
# volumes. The entrypoint starts as root, `find`-chowns /data/db +
# /data/configdb (a no-op on the image's pre-owned VOLUMEs), then re-execs
# itself as the mongodb user via gosu (SETUID/SETGID) — startup caps, invisible
# to runtime observation. This asserts a real mongosh write/read round-trip AND
# that mongod dropped to a non-root uid (the redis/mariadb sharp edge: a
# workload-only check passes while the server still runs as root).
#
# The round-trip mirrors the official docker-library mongo-basics test shape:
# insertOne + countDocuments + findOne read-back via mongosh.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

# Wait for mongod to accept mongosh commands.
deadline=$((SECONDS+60))
until docker exec "$C" mongosh --quiet --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; do
  (( SECONDS >= deadline )) && { echo "mongod never answered ping"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# Real round-trip: insert, count, read back.
out="$(docker exec "$C" mongosh --quiet csdprobe --eval '
  db.probe.insertOne({_id: "csd", v: 42});
  const n = db.probe.countDocuments();
  const v = db.probe.findOne({_id: "csd"}).v;
  db.probe.drop();
  print(n + ":" + v);' 2>&1 | tail -1)"
[ "$out" = "1:42" ] || { echo "workload round-trip failed (got: $out)"; exit 1; }

# Server dropped to a non-root uid (the gosu root->mongodb drop).
uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in mongod|*/mongod) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "mongod running as ROOT or not found (gosu drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: mongosh round-trip ok, mongod uid=$uid (non-root)"
