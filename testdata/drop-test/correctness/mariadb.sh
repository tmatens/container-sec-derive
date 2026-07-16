#!/usr/bin/env bash
# mariadb correctness (capabilities): default root invocation on a FRESH datadir.
# The entrypoint starts as root, `find`-chowns /var/lib/mysql to the mysql user
# (CHOWN), initializes the database (DAC_OVERRIDE for the ensuing writes), and
# re-execs the server as the mysql user via gosu (SETUID/SETGID). These are all
# startup caps, invisible to runtime observation — drop-test is the authoritative
# signal (same lesson as postgres). This asserts a real query round-trip AND that
# the server dropped to a non-root uid: a health/ping alone passes while the server
# is still root or mid-init.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

# Wait until the configured app user can connect (proves the real server is up and
# init created the user — not the transient bootstrap server that answers a ping).
# Probes exec as the mysql user, never root (a root probe's own needs would
# pollute the minimum — the rabbitmq lesson).
deadline=$((SECONDS+45))
until docker exec --user mysql "$C" sh -c 'MYSQL_PWD=$MARIADB_PASSWORD mariadb -u"$MARIADB_USER" -e "SELECT 1" >/dev/null 2>&1'; do
  (( SECONDS >= deadline )) && { echo "mariadb never accepted an app-user connection"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# Real round-trip in the configured database.
out="$(docker exec --user mysql "$C" sh -c 'MYSQL_PWD=$MARIADB_PASSWORD mariadb -u"$MARIADB_USER" "$MARIADB_DATABASE" -N -e "CREATE TABLE IF NOT EXISTS csd_probe(id INT); INSERT INTO csd_probe VALUES(42); SELECT id FROM csd_probe LIMIT 1; DROP TABLE csd_probe;"' 2>&1)"
[ "$out" = 42 ] || { echo "workload round-trip failed (got: ${out##*$'\n'})"; exit 1; }

# Server dropped to a non-root uid (the gosu root->mysql drop).
uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in *mariadbd) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "mariadbd running as ROOT or not found (gosu drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: query round-trip ok, mariadbd uid=$uid (non-root)"
