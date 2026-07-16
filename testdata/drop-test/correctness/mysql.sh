#!/usr/bin/env bash
# mysql correctness (capabilities): default root invocation on a FRESH datadir.
# The entrypoint starts as root, `find`-chowns the data dirs (a no-op on the
# image's pre-owned VOLUME), re-execs itself as the mysql user via gosu
# (SETUID/SETGID), then initializes the database as mysql. All startup caps,
# invisible to runtime observation — drop-test is the authoritative signal
# (same lesson as mariadb/postgres). This asserts a real app-user query
# round-trip AND that mysqld dropped to a non-root uid: a ping alone passes
# while the transient bootstrap server is still initializing.
#
# The round-trip mirrors the official docker-library mysql-basics test
# (CREATE/INSERT/SELECT/DROP as the configured app user).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

# Wait until the configured app user can connect — proves the real server is up
# and init created the user, not the bootstrap server that also answers pings.
# mysql 8.x first-boot init is slower than mariadb; allow 90s.
deadline=$((SECONDS+90))
until docker exec "$C" sh -c 'MYSQL_PWD=$MYSQL_PASSWORD mysql -u"$MYSQL_USER" -e "SELECT 1" >/dev/null 2>&1'; do
  (( SECONDS >= deadline )) && { echo "mysql never accepted an app-user connection"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# Real round-trip in the configured database.
out="$(docker exec "$C" sh -c 'MYSQL_PWD=$MYSQL_PASSWORD mysql -u"$MYSQL_USER" "$MYSQL_DATABASE" -N -e "CREATE TABLE IF NOT EXISTS csd_probe(id INT); INSERT INTO csd_probe VALUES(42); SELECT id FROM csd_probe LIMIT 1; DROP TABLE csd_probe;"' 2>&1)"
[ "$out" = 42 ] || { echo "workload round-trip failed (got: ${out##*$'\n'})"; exit 1; }

# Server dropped to a non-root uid (the gosu root->mysql drop).
uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in mysqld|*/mysqld) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "mysqld running as ROOT or not found (gosu drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: query round-trip ok, mysqld uid=$uid (non-root)"
