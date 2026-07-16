#!/usr/bin/env bash
# jellyfin correctness (capabilities + filesystem): default invocation. Real
# function = the actual first-run flow: health, the setup wizard REST
# sequence, token auth as the created admin, and an authorized System/Info
# readback. Fresh /config volume per trial means the wizard runs every trial.
#
# Probes go through the curl sidecar (the image ships no curl/wget) and write
# nothing inside the container; responses are captured then matched (never
# `curl | grep -q` under pipefail). jellyfin serves as root by default (no
# drop to assert — hardening via user: is the criteria doc's story).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

deadline=$((SECONDS+120))
until [ "$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:8096/health 2>/dev/null)" = 200 ]; do
  (( SECONDS >= deadline )) && { echo "jellyfin never healthy"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 3
done

# Setup wizard REST sequence (each returns 2xx).
for step in \
  'POST /Startup/Configuration {"UICulture":"en-US","MetadataCountryCode":"US","PreferredMetadataLanguage":"en"}' \
  'GET /Startup/User -' \
  'POST /Startup/User {"Name":"csdadmin","Password":"CsdProbe-Pw-12345"}' \
  'POST /Startup/Complete -'; do
  m="${step%% *}"; rest="${step#* }"; path="${rest%% *}"; body="${rest#* }"
  args=(-s -o /dev/null -w '%{http_code}' --max-time 10 -X "$m")
  [ "$body" != "-" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  code="$(sidecar_curl "${args[@]}" "http://localhost:8096$path" 2>/dev/null)"
  case "$code" in 2??) ;; *) echo "wizard step $m $path failed: HTTP ${code:-none}"; exit 1;; esac
done

# Token auth as the created admin, then an authorized API readback.
auth="$(sidecar_curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
  -H 'Authorization: MediaBrowser Client="csd", Device="csd", DeviceId="csd", Version="1.0"' \
  -d '{"Username":"csdadmin","Pw":"CsdProbe-Pw-12345"}' \
  http://localhost:8096/Users/AuthenticateByName 2>/dev/null)"
tok="$(printf '%s' "$auth" | grep -oE '"AccessToken":"[a-f0-9]+"' | cut -d'"' -f4)"
[ -n "$tok" ] || { echo "admin auth failed (resp: ${auth:0:80})"; exit 1; }
info="$(sidecar_curl -s --max-time 10 -H "Authorization: MediaBrowser Token=\"$tok\"" \
  http://localhost:8096/System/Info 2>/dev/null)"
case "$info" in *'"Version":"'*) ;; *) echo "authorized System/Info failed (resp: ${info:0:80})"; exit 1;; esac

echo "correct: wizard + admin auth + authorized System/Info ok"
