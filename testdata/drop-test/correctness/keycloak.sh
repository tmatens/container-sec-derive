#!/usr/bin/env bash
# keycloak correctness (capabilities): start-dev invocation. Real IdP
# function: ready -> admin token via the OpenID password grant -> create a
# realm through the admin API -> read it back. Curl sidecar (no client tools
# in image); capture-then-match; USER 1000 image (non-root by construction,
# asserted anyway).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

deadline=$((SECONDS+120))
until [ "$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:8080/realms/master 2>/dev/null)" = 200 ]; do
  (( SECONDS >= deadline )) && { echo "keycloak never ready: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 3
done

tokresp="$(sidecar_curl -s --max-time 10 -d 'grant_type=password&client_id=admin-cli&username=csdadmin&password=CsdProbe-Pw-12345' http://localhost:8080/realms/master/protocol/openid-connect/token 2>/dev/null)"
tok="$(printf '%s' "$tokresp" | grep -oE '"access_token":"[^"]+' | cut -d'"' -f4)"
[ -n "$tok" ] || { echo "admin token failed (resp: ${tokresp:0:60})"; exit 1; }

code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{"realm":"csd","enabled":true}' http://localhost:8080/admin/realms 2>/dev/null)"
case "$code" in 201|409) ;; *) echo "realm create failed: HTTP ${code:-none}"; exit 1;; esac
back="$(sidecar_curl -s --max-time 10 -H "Authorization: Bearer $tok" http://localhost:8080/admin/realms/csd 2>/dev/null)"
case "$back" in *'"realm":"csd"'*) ;; *) echo "realm readback failed (got: ${back:0:60})"; exit 1;; esac

uid="$(docker exec "$C" sh -c 'while read k v _; do [ "$k" = Uid: ] && { echo "$v"; break; }; done < /proc/1/status' 2>/dev/null)"
[ "${uid:-0}" != 0 ] || { echo "keycloak running as ROOT"; exit 1; }

echo "correct: admin token + realm create/readback ok, keycloak uid=$uid (non-root)"
