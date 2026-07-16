#!/usr/bin/env bash
# nextcloud correctness (capabilities): in-stack invocation against the `db`
# dep (mariadb). Real function = installed status via occ + a WebDAV PUT/GET
# round-trip as the auto-installed admin, plus the non-root apache worker uid
# assert (the httpd/wordpress sharp edge).
#
# Trial lifecycle (measured on nextcloud:32): the db dep persists across
# trials, and a fresh-docroot container CANNOT adopt an installed DB — it
# boots into a running-but-broken "installed: false" limbo. Recovery, per
# trial: reset the database (root exec in csd-dep-db — the harness's dep
# naming) and docker-restart the target; its entrypoint then performs a clean
# install under the trial's cap posture. The trial's first boot already
# rsync'd the sources into its fresh volume under that same posture.
#
# Probe hygiene: occ runs as --user www-data (never root — probe caps
# pollution); WebDAV goes through the curl sidecar; nothing is written inside
# the target by the probes (the payload lands in nextcloud's own data dir via
# WebDAV, which IS the workload).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

installed() {
  local s; s="$(docker exec --user www-data "$C" php occ status 2>/dev/null)"
  case "$s" in *"installed: true"*) return 0;; esac; return 1
}

# Phase 1: container up (first boot rsyncs ~700MB into the fresh volume).
deadline=$((SECONDS+150))
until docker exec "$C" test -f /var/www/html/version.php 2>/dev/null; do
  (( SECONDS >= deadline )) && { echo "sources never landed in the docroot"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 3
done

# Phase 2: installed? A persisted-DB limbo needs the reset + restart path.
if ! installed; then
  sleep 5   # let the first-boot install attempt settle before judging
  if ! installed; then
    docker exec csd-dep-db sh -c 'MYSQL_PWD=$MARIADB_ROOT_PASSWORD mariadb -uroot -e "DROP DATABASE IF EXISTS nextcloud; CREATE DATABASE nextcloud; GRANT ALL ON nextcloud.* TO nextcloud@\"%\";"' \
      || { echo "dep DB reset failed"; exit 1; }
    docker restart "$C" >/dev/null 2>&1 || { echo "target restart failed"; exit 1; }
    deadline=$((SECONDS+150))
    until installed; do
      (( SECONDS >= deadline )) && { echo "install never completed after DB reset: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
      [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited during install: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
      sleep 5
    done
  fi
fi

# Phase 3: WebDAV PUT/GET round-trip as the admin (capture-then-match — never
# pipe curl into grep -q under pipefail).
sidecar_curl -sf --max-time 15 -u csdadmin:CsdProbe-Pw-12345 -X PUT \
  --data-binary "csd-payload-42" \
  http://localhost:80/remote.php/dav/files/csdadmin/csd-probe.txt >/dev/null 2>&1 \
  || { echo "WebDAV PUT failed"; exit 1; }
got="$(sidecar_curl -s --max-time 15 -u csdadmin:CsdProbe-Pw-12345 \
  http://localhost:80/remote.php/dav/files/csdadmin/csd-probe.txt 2>/dev/null)"
[ "$got" = "csd-payload-42" ] || { echo "WebDAV GET mismatch (got: ${got:0:60})"; exit 1; }

# Phase 4: a worker (non-PID-1 apache2) runs NON-root — the www-data drop.
wuid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do pid=${p#/proc/}; [ "$pid" = 1 ] && continue; a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in apache2|*/apache2) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$wuid" ] && [ "$wuid" != 0 ] || { echo "apache workers running as ROOT or not found (drop failed): uid=${wuid:-none}"; exit 1; }

echo "correct: WebDAV PUT/GET round-trip ok, worker uid=$wuid (non-root)"
