#!/usr/bin/env bash
# Correctness for caddy under its REAL compose (a reverse proxy, not the default
# file server): correct iff caddy comes up and binds a privileged port (:80/:443).
#
# Binding a privileged port is exactly what CAP_NET_BIND_SERVICE gates — via the
# caddy binary's file capability (which makes even exec fail when the cap is
# dropped from the bounding set) and/or the port range. If caddy can't exec or
# can't bind, it never listens and this fails. We assert the LISTEN state rather
# than an HTTP GET on purpose: the real Caddyfile serves named vhosts, so a
# localhost GET matches no site — but binding the port is the cap-relevant fact,
# independent of certs or backend reachability.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
C="$DROP_TEST_CONTAINER"

# In /proc/net/tcp{,6} a listening socket has state 0A; ports are hex — 80=0050,
# 443=01BB. Any privileged listener proves the bind (and the exec) succeeded.
listening_priv() {
  # capture-then-match via herestring — never end an outer pipe in `grep -q`
  # under pipefail (grep -q's early exit SIGPIPEs the upstream awk/cat → a
  # matching result can false-negative once the output outgrows the pipe buffer).
  local ports
  ports="$(docker exec "$C" sh -c 'cat /proc/net/tcp /proc/net/tcp6 2>/dev/null' \
    | awk '$4=="0A"{split($2,a,":"); print a[2]}')"
  grep -qiE '^(0050|01BB)$' <<<"$ports"
}

deadline=$((SECONDS + 30))
while (( SECONDS < deadline )); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" != "true" ]; then
    echo "caddy container not running: $(docker logs "$C" 2>&1 | grep -v '^[[:space:]]*$' | tail -1)"
    exit 1
  fi
  if listening_priv; then echo "caddy listening on a privileged port (:80/:443)"; exit 0; fi
  sleep 1
done
echo "caddy did not bind :80/:443 within the deadline"
exit 1
