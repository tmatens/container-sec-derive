#!/usr/bin/env bash
# Workload exerciser for the caddy reference image.
#
# Exercises the default file server (GET) plus the admin API (POST to
# /load) plus a SIGUSR1-triggered config reload. Returns 0 if every step
# succeeded.
#
# Required env: CADDY_CONTAINER (target container name or id).
# The container must have published its :80 to host port 18080 and its
# :2019 (admin API) to host port 12019, both bound to 127.0.0.1.
set -euo pipefail

: "${CADDY_CONTAINER:?CADDY_CONTAINER must be set}"

HTTP_BASE="http://127.0.0.1:18080"
ADMIN_BASE="http://127.0.0.1:12019"

# Wait until the file server responds.
deadline=$((SECONDS + 30))
until curl -fsS -o /dev/null "${HTTP_BASE}/"; do
    if (( SECONDS >= deadline )); then
        echo "caddy did not become ready in 30s" >&2
        exit 1
    fi
    sleep 1
done

# GET — file server happy path.
curl -fsS "${HTTP_BASE}/" >/dev/null

# POST /load — admin API config replacement. Replaces the running config
# with one that returns "ok" on /healthz and continues serving the rest.
cat <<'JSON' | curl -fsS -X POST -H 'Content-Type: application/json' \
    --data-binary @- "${ADMIN_BASE}/load" >/dev/null
{
  "apps": {
    "http": {
      "servers": {
        "default": {
          "listen": [":80"],
          "routes": [
            {
              "match": [{"path": ["/healthz"]}],
              "handle": [{"handler": "static_response", "body": "ok", "status_code": 200}]
            },
            {
              "handle": [{"handler": "file_server", "root": "/usr/share/caddy"}]
            }
          ]
        }
      }
    }
  }
}
JSON

# Verify the new config is live.
test "$(curl -fsS "${HTTP_BASE}/healthz")" = "ok"
curl -fsS "${HTTP_BASE}/" >/dev/null

# SIGUSR1 — reload from Caddyfile (reverts the admin-API change).
docker kill --signal=SIGUSR1 "${CADDY_CONTAINER}"
sleep 1
curl -fsS "${HTTP_BASE}/" >/dev/null
