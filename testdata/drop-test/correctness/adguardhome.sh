#!/usr/bin/env bash
# adguardhome correctness (capabilities, DNS-only): drive the REST
# install/configure (admin + DNS:53 + web:80 in one call — a real persistent
# config write), then assert real resolution: nslookup a name against
# 127.0.0.1:53 answered by AGH. The initial setup UI listens on :3000; after
# configure, DNS is on :53 and web on :80. Curl sidecar for the config POST;
# in-image nslookup for the resolution (AGH is root — no probe pollution
# concern, but keep the resolution in-container so it hits FTL/AGH directly).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

deadline=$((SECONDS+45))
while :; do
  code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:3000/ 2>/dev/null)"
  case "$code" in 200|30?) break;; esac
  (( SECONDS >= deadline )) && { echo "setup UI never came up (last: ${code:-none}): $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H 'Content-Type: application/json' \
  -d '{"web":{"ip":"0.0.0.0","port":80},"dns":{"ip":"0.0.0.0","port":53},"username":"csdadmin","password":"CsdProbe-Pw-12345"}' \
  http://localhost:3000/control/install/configure 2>/dev/null)"
[ "$code" = 200 ] || { echo "install/configure failed: HTTP ${code:-none}"; exit 1; }

# Add a LOCAL DNS rewrite (csd.test -> 127.0.0.1) so resolution is answered by
# AGH itself — no upstream reachability in the trial loop (the pihole lesson).
# The web API + DNS moved to :80 / :53 after configure.
rcode="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 10 -u csdadmin:CsdProbe-Pw-12345 \
  -X POST -H 'Content-Type: application/json' -d '{"domain":"csd.test","answer":"127.0.0.1"}' \
  http://localhost:80/control/rewrite/add 2>/dev/null)"
[ "$rcode" = 200 ] || { echo "rewrite add failed: HTTP ${rcode:-none}"; exit 1; }

# Real resolution against AGH on :53 — the rewrite answers locally with 127.0.0.1.
deadline=$((SECONDS+20))
# Match the ANSWER line ("Address: 127.0.0.1", no :port) not the server line
# ("Address: 127.0.0.1:53"). Capture-then-match via herestring — never
# `nslookup | grep -q` under pipefail (SIGPIPE false-negative once the body
# outgrows the pipe buffer).
until grep -qE "Address:[[:space:]]*127\.0\.0\.1$" <<<"$(docker exec "$C" nslookup csd.test 127.0.0.1 2>/dev/null)"; do
  (( SECONDS >= deadline )) && { echo "AGH never resolved the local rewrite csd.test"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

echo "correct: install/configure ok, AGH resolves local rewrite on :53"
