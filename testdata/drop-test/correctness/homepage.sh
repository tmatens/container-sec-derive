#!/usr/bin/env bash
# Correct iff homepage serves the dashboard AND can use its Next.js image-
# optimization cache. A bare dashboard GET serves even under --read-only, so the
# cache requirement only surfaces when image optimization runs: any /_next/image
# request makes Next.js mkdir /app/.next/cache first, which fails
# (unhandledRejection: ENOENT mkdir) when that path isn't writable. The correctness check
# fires an image request and asserts the container log is clean of the cache /
# read-only-fs write error. Uses docker exec (the image ships wget) — no host
# ports published.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
C="$DROP_TEST_CONTAINER"

# Readiness: the dashboard responds on :3000. Homepage cold-start is ~45s
# (the homelab deploy allows 120s), so give it generous margin — a too-tight
# deadline makes the baseline flaky.
deadline=$((SECONDS + 100))
until docker exec "$C" wget -qO- http://localhost:3000/ >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "homepage did not become ready in time"
    exit 1
  fi
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = "true" ] || { echo "homepage container exited"; exit 1; }
  sleep 2
done

# Trigger image optimization. The source url may 404, but Next.js mkdir's the
# cache dir before fetching the source, so this exercises the cache write.
docker exec "$C" wget -qO- "http://localhost:3000/_next/image?url=%2Ficon.png&w=64&q=75" >/dev/null 2>&1
sleep 2

if docker logs "$C" 2>&1 | grep -qiE "mkdir '/app/.next/cache'|EROFS|read-only file system"; then
  echo "homepage cannot write /app/.next/cache (read-only, no tmpfs)"
  exit 1
fi
echo "homepage serving + image-optimization cache writable"
