#!/usr/bin/env bash
# grafana correctness (filesystem). grafana runs under --read-only with
# /var/lib/grafana writable — that dir is a PERSISTENT volume in real deployments
# (its sqlite DB + any installed plugins must survive restarts, so it is NOT
# tmpfs; the drop-test supplies it as a writable stand-in via run.tmpfs and never
# counts it in the derived tmpfs minimum). This exercises real function, not
# liveness:
#   1. /api/health reports the database is "ok";
#   2. create a dashboard + read it back — a real sqlite write on the data volume;
#   3. a backend datasource plugin actually runs — add a Loki datasource and hit
#      its plugin health endpoint (a running go-plugin backend returns a JSON
#      verdict with a "status" field even when the target Loki is unreachable; a
#      backend that failed to start does not).
# NOTE ON SCOPE: grafana's core + prometheus/Loki datasource querying + DB work
# under read-only with NO /tmp. A writable /tmp is used only by grafana's runtime
# plugin *installation*, the elasticsearch datasource plugin, and image
# rendering / data export — none exercised here (see the criteria doc).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
B='http://admin:$GF_SECURITY_ADMIN_PASSWORD@localhost:3000'

# The curl|grep-q pipe here runs INSIDE `docker exec … sh -c`, a nested shell
# with no `pipefail`, so the inner pipeline's exit is grep's — a curl SIGPIPE
# cannot false-negative it (unlike an outer-level `curl | grep -q` under this
# script's `set -o pipefail`). Left as-is deliberately; do not "fix" it into a
# herestring, which the container's POSIX sh may not support.
deadline=$((SECONDS+45))
until docker exec "$C" sh -c "curl -sf \"$B/api/health\" 2>/dev/null | grep -q '\"database\": \"ok\"'"; do
  (( SECONDS >= deadline )) && { echo "grafana /api/health never reported database ok"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# real DB write on the data volume + read-back
uid="$(docker exec "$C" sh -c "curl -s -X POST -H 'Content-Type: application/json' -d '{\"dashboard\":{\"title\":\"csd-probe\",\"panels\":[]},\"overwrite\":true}' \"$B/api/dashboards/db\"" 2>/dev/null | sed -n 's/.*\"uid\":\"\([^\"]*\)\".*/\1/p' | head -1)"
[ -n "$uid" ] || { echo "dashboard create failed (DB write path broken)"; exit 1; }
docker exec "$C" sh -c "curl -sf -o /dev/null \"$B/api/dashboards/uid/$uid\"" 2>/dev/null || { echo "dashboard read-back failed"; exit 1; }

# a backend datasource plugin runs (Loki): its health endpoint returns a verdict
duid="$(docker exec "$C" sh -c "curl -s -X POST -H 'Content-Type: application/json' -d '{\"name\":\"csd-loki\",\"type\":\"loki\",\"access\":\"proxy\",\"url\":\"http://127.0.0.1:9\"}' \"$B/api/datasources\"" 2>/dev/null | sed -n 's/.*\"uid\":\"\([^\"]*\)\".*/\1/p' | head -1)"
body="$(docker exec "$C" sh -c "curl -s \"$B/api/datasources/uid/$duid/health\"" 2>/dev/null)"
grep -q '"status"' <<<"$body" || { echo "Loki datasource backend plugin not running: ${body:0:120}"; exit 1; }

echo "correct: /api/health db ok, dashboard write+read-back, backend datasource plugin running"
