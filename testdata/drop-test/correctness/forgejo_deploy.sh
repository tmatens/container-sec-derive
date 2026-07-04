#!/usr/bin/env bash
# forgejo correctness (capabilities). The container runs TWO root daemons under an
# s6 supervision tree, and a faithful cap minimum must keep BOTH working:
#   - `gitea web` — starts as root, chowns a fresh /data to the git user, then
#     drops root -> git (uid 1000) via su-exec.
#   - `sshd` — stays root, but OpenSSH forks a pre-auth privilege-separation child
#     (chroot + setuid to the sshd user) on every connection.
# So this check exercises the whole surface, not just liveness:
#   1. web/API up (/api/v1/version -> 200);
#   2. `gitea web` runs as a NON-root uid (the su-exec drop worked -> SETUID/SETGID);
#   3. a real DB + git write: create an admin user (sqlite write as the git user,
#      only possible if the fresh /data was chowned to git -> CHOWN), create a repo
#      via the API, then clone + commit + push over HTTP (the git backend, as git);
#   4. sshd REACHES authentication: an unauthenticated connection returns
#      "Permission denied (publickey)" only if the pre-auth privsep child forked
#      (chroot -> SYS_CHROOT). Without it OpenSSH resets the connection while the
#      web API still answers 200 — so git-over-SSH is silently dead. A web-only
#      check would ship a profile that breaks SSH; hence probe both.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

# Throwaway fixture credentials — created inside a fresh, ephemeral container that
# is destroyed at the end of the trial. Not a secret (cf. postgres's POSTGRES_PASSWORD).
U=csdprobe; P=csdprobe-pw-12345; E=csd@probe.local

# 1. web/API up
deadline=$((SECONDS+45))
until [ "$(docker exec "$C" curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/api/v1/version 2>/dev/null)" = 200 ]; do
  (( SECONDS >= deadline )) && { echo "forgejo API /api/v1/version never returned 200"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

# 2. gitea web dropped to a non-root uid (match argv[0] exactly, not this check's own shell)
guid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); [ "$a0" = /usr/local/bin/gitea ] && { awk "/^Uid:/{print \$2}" "$p/status"; break; }; done')"
[ -n "$guid" ] || { echo "no 'gitea web' process found"; exit 1; }
[ "$guid" != 0 ] || { echo "gitea web running as ROOT (su-exec privilege drop failed)"; exit 1; }

# 3. real DB + git write path (exercises CHOWN on the fresh /data + the git user's writes)
docker exec "$C" su-exec git /usr/local/bin/gitea admin user create \
  --username "$U" --password "$P" --email "$E" --admin --must-change-password=false >/dev/null 2>&1 \
  || { echo "admin user create failed (sqlite write path broken)"; exit 1; }
rc="$(docker exec "$C" curl -s -o /dev/null -w '%{http_code}' -u "$U:$P" \
  -H 'Content-Type: application/json' -d '{"name":"probe","auto_init":true}' \
  http://localhost:3000/api/v1/user/repos)"
[ "$rc" = 201 ] || { echo "repo create via API returned HTTP $rc (expected 201)"; exit 1; }
docker exec "$C" sh -c "set -e; export GIT_TERMINAL_PROMPT=0; cd /tmp && rm -rf p && \
  git clone -q http://$U:$P@localhost:3000/$U/probe.git p && cd p && \
  git -c user.email=$E -c user.name=$U commit --allow-empty -q -m probe && \
  git push -q http://$U:$P@localhost:3000/$U/probe.git" >/dev/null 2>&1 \
  || { echo "git-over-HTTP clone/commit/push failed (git backend broken)"; exit 1; }

# 4. sshd privilege separation (SYS_CHROOT): an unauth connection must REACH auth
sshout="$(docker exec "$C" ssh -p 22 -o StrictHostKeyChecking=no -o BatchMode=yes \
  -o ConnectTimeout=6 -o PreferredAuthentications=publickey git@localhost true 2>&1)"
grep -q 'Permission denied' <<<"$sshout" \
  || { echo "sshd never reached auth (privsep failed -> git-over-SSH dead): ${sshout##*$'\n'}"; exit 1; }

echo "correct: web+API up, gitea uid=$guid (non-root), admin+repo+git-push over HTTP, sshd reaches auth"
