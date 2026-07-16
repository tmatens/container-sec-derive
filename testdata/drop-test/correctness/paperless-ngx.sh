#!/usr/bin/env bash
# paperless-ngx correctness (capabilities): in-stack invocation against the
# `broker` redis dep. Real function = the full document lifecycle: token auth
# -> POST a document -> poll until consumed (web -> redis -> celery worker ->
# media write). A plain-text doc skips OCR so trials stay fast. Probed from
# the curl sidecar; capture-then-match; the non-root worker uid assert
# confirms the s6 drop.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

# Web tier up: /api/ answers (302 to login is "ready"). s6 provisioning +
# migrations take a while on first boot.
deadline=$((SECONDS+240))
until case "$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:8000/api/ 2>/dev/null)" in 200|30?|40?) true;; *) false;; esac; do
  (( SECONDS >= deadline )) && { echo "paperless web never answered: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 4
done

tok="$(sidecar_curl -s --max-time 10 -X POST -H 'Content-Type: application/json' -d '{"username":"csdadmin","password":"CsdProbe-Pw-12345"}' http://localhost:8000/api/token/ 2>/dev/null | grep -oE '"token":"[a-f0-9]+"' | cut -d'"' -f4)"
[ -n "$tok" ] || { echo "token auth failed"; exit 1; }

code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "Authorization: Token $tok" -F 'document=@/etc/hostname;filename=csd-probe.txt;type=text/plain' -F 'title=csdprobe' http://localhost:8000/api/documents/post_document/ 2>/dev/null)"
[ "$code" = 200 ] || { echo "document post failed: HTTP ${code:-none}"; exit 1; }

# Poll until the celery worker has consumed it into the document store.
deadline=$((SECONDS+90))
while :; do
  cnt="$(sidecar_curl -s --max-time 5 -H "Authorization: Token $tok" http://localhost:8000/api/documents/ 2>/dev/null | grep -oE '"count":[0-9]+' | cut -d: -f2)"
  [ "${cnt:-0}" -ge 1 ] && break
  (( SECONDS >= deadline )) && { echo "document never consumed (count stays 0)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 4
done

# A worker dropped to a non-root uid (the s6 PUID drop).
uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in *granian*|*celery*) while read k v _; do [ "$k" = Uid: ] && { echo "$v"; break; }; done < "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "paperless workers running as ROOT (s6 drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: document consumed via the full pipeline, worker uid=$uid (non-root)"
