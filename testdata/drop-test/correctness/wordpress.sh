#!/usr/bin/env bash
# wordpress correctness (capabilities): in-stack invocation against the `db`
# dep. Real function, both trial phases:
#   - fresh DB (first trial): drive the REAL HTTP install flow
#     (install.php?step=2) — creates the schema through php -> mysql — then
#     assert the homepage serves the configured blog title from the DB;
#   - installed DB (later trials): the fresh container generates wp-config
#     from env, apache workers drop to www-data, php reads the site from
#     mysql — assert the title-bearing homepage directly.
# Both paths cover entrypoint source-copy + worker drop + php->mysql. Probed
# from the curl sidecar; plus the non-root WORKER uid assert (the httpd
# sharp edge — with a broken drop apache serves anyway with root workers).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

TITLE="csdblog-e7a1"

# Apache answering at all (install redirect or the site) — entrypoint copies
# ~70MB of sources into the fresh volume first, so allow 90s.
deadline=$((SECONDS+90))
while :; do
  code="$(sidecar_curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:80/ 2>/dev/null)"
  case "$code" in 200|30?) break;; esac
  (( SECONDS >= deadline )) && { echo "wordpress never answered (last code: ${code:-none})"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

# capture-then-match, NEVER `curl | grep -q` here: under `set -o pipefail`,
# grep -q exits at the first match, curl takes SIGPIPE (141), and the pipeline
# reports FAILURE on a page that matched — a false negative that burned three
# derivation runs before diagnosis.
titled() { local b; b="$(sidecar_curl -sL --max-time 10 http://localhost:80/ 2>/dev/null)"; case "$b" in *"$TITLE"*) return 0;; esac; return 1; }

if ! titled; then
  # Fresh DB: run the real install flow. Retry the POST (the first request
  # after boot can land while php/mysql are still settling) and poll for the
  # titled homepage after each attempt.
  ok=""
  for attempt in 1 2 3; do
    resp="$(sidecar_curl -s --max-time 30 -X POST \
      --data-urlencode "weblog_title=$TITLE" \
      --data-urlencode "user_name=csdadmin" \
      --data-urlencode "admin_password=CsdProbe-Pw-12345-Strong" \
      --data-urlencode "admin_password2=CsdProbe-Pw-12345-Strong" \
      --data-urlencode "admin_email=csd@example.com" \
      --data-urlencode "blog_public=0" \
      'http://localhost:80/wp-admin/install.php?step=2' 2>/dev/null)"
    deadline2=$((SECONDS+45))
    until titled; do (( SECONDS >= deadline2 )) && break; sleep 3; done
    titled && { ok=1; break; }
    sleep 3
  done
  [ -n "$ok" ] || { echo "install flow did not produce the titled homepage (last install resp: $(printf '%s' "$resp" | grep -oiE '<h1[^>]*>[^<]*|error[^<]{0,60}' | head -2 | tr '\n' ' '); title-tag: $(sidecar_curl -sL --max-time 10 http://localhost:80/ 2>/dev/null | grep -oE '<title>[^<]*' | head -1); db-blogname: $(docker exec csd-dep-db sh -c 'MYSQL_PWD=$MYSQL_PASSWORD mysql -u$MYSQL_USER $MYSQL_DATABASE -N -e "SELECT option_value FROM wp_options WHERE option_name='"'"'blogname'"'"'"' 2>&1 | tail -1))"; exit 1; }
fi

# A worker (non-PID-1 apache2) must run NON-root — the www-data drop.
wuid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do pid=${p#/proc/}; [ "$pid" = 1 ] && continue; a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in apache2|*/apache2) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$wuid" ] && [ "$wuid" != 0 ] || { echo "apache workers running as ROOT or not found (drop failed): uid=${wuid:-none}"; exit 1; }

echo "correct: titled homepage served from DB, worker uid=$wuid (non-root)"
