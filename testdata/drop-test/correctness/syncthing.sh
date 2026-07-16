#!/usr/bin/env bash
# syncthing correctness (capabilities): default invocation. Real function =
# REST as the generated API key: system/status returns a device ID, a folder
# is added via the config API and read back. Probes exec as --user 1000 (the
# syncthing uid — probe hygiene) using the in-image curl; the non-root uid
# assert confirms the entrypoint's drop.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS+60))
until docker exec "$C" test -s /var/syncthing/config/config.xml 2>/dev/null; do
  (( SECONDS >= deadline )) && { echo "config.xml never appeared: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done
KEY="$(docker exec "$C" sh -c 'grep -oE "<apikey>[^<]*" /var/syncthing/config/config.xml | cut -d">" -f2')"
[ -n "$KEY" ] || { echo "no API key in config.xml"; exit 1; }

deadline=$((SECONDS+45))
while :; do
  st="$(docker exec --user 1000 "$C" curl -s --max-time 5 -H "X-API-Key: $KEY" http://localhost:8384/rest/system/status 2>/dev/null)"
  case "$st" in *'"myID"'*) break;; esac
  (( SECONDS >= deadline )) && { echo "system/status never answered (last: ${st:0:60})"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

code="$(docker exec --user 1000 "$C" curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{"id":"csd","label":"csd","path":"/var/syncthing/csd-folder"}' http://localhost:8384/rest/config/folders/csd 2>/dev/null)"
case "$code" in 2??) ;; *) echo "folder add failed: HTTP ${code:-none}"; exit 1;; esac
back="$(docker exec --user 1000 "$C" curl -s --max-time 5 -H "X-API-Key: $KEY" http://localhost:8384/rest/config/folders/csd 2>/dev/null)"
case "$back" in *'"id"'*csd*|*csd*'"id"'*) ;; *) echo "folder readback failed (got: ${back:0:60})"; exit 1;; esac

uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in */syncthing|syncthing) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "syncthing running as ROOT (drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: REST status + folder add/readback ok, syncthing uid=$uid (non-root)"
