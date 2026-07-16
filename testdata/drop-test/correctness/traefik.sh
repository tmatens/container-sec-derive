#!/usr/bin/env bash
# traefik correctness (capabilities): reverse-proxy invocation, file provider.
# Real function = a request on entrypoint :80 routed through a traefik router
# to the in-stack `backend` dep (pinned caddy) and answered with the backend's
# content — entrypoint -> router -> service -> upstream, the full proxy path.
#
# The dynamic file-provider config cannot ride in the committed spec (run.mounts
# needs absolute host paths), so it is docker-cp'd into the fresh container each
# trial; the file provider is started with watch=true and hot-loads it. docker cp
# is a daemon-side write — it exercises no capability inside the target, so it
# cannot pollute the derived minimum. Probed from the curl sidecar
# (lib/sidecar.sh); traefik serves :80 as root with NO privilege drop, so there
# is no uid assert — the routed backend response is the pass signal.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

# Stage + inject the dynamic config (root of the container fs, matching
# --providers.file.directory=/tmp).
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/dynamic.yml" <<'EOF'
http:
  routers:
    csd:
      rule: PathPrefix(`/`)
      service: backend
  services:
    backend:
      loadBalancer:
        servers:
          - url: http://backend:80
EOF
docker cp "$tmp/dynamic.yml" "$C:/tmp/dynamic.yml" >/dev/null 2>&1 \
  || { echo "docker cp of dynamic.yml failed"; exit 1; }

# The routed response must come from the caddy backend (its default page).
deadline=$((SECONDS+45))
while :; do
  body="$(sidecar_curl -s --max-time 5 http://localhost:80/ 2>/dev/null)"
  case "$body" in *[Cc]addy*) break;; esac
  (( SECONDS >= deadline )) && { echo "no routed backend response (last: ${body:0:60})"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

echo "correct: :80 routed through traefik to the caddy backend"
