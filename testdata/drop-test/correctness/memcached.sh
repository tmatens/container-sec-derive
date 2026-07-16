#!/usr/bin/env bash
# memcached correctness (capabilities): default invocation. A real set/get
# round-trip (STORED + value read back), mirroring the official docker-library
# memcached-basics test, driven over the in-image bash /dev/tcp — the image
# ships bash but no client tool. docker exec inherits USER memcache
# (uid 11211), so the probe cannot pollute the derived minimum. The non-root
# uid assert confirms the serving process (there is no drop to perform — the
# image is non-root by construction).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS+20))
until docker exec "$C" bash -c 'exec 3<>/dev/tcp/127.0.0.1/11211' 2>/dev/null; do
  (( SECONDS >= deadline )) && { echo "memcached never accepted a connection"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 1
done

out="$(docker exec "$C" bash -c '
  exec 3<>/dev/tcp/127.0.0.1/11211
  printf "set csd 0 0 5\r\nhello\r\n" >&3
  IFS=$'"'"'\r'"'"' read -r stored <&3
  printf "get csd\r\n" >&3
  IFS=$'"'"'\r'"'"' read -r hdr <&3; IFS=$'"'"'\r'"'"' read -r val <&3; IFS=$'"'"'\r'"'"' read -r end <&3
  printf "quit\r\n" >&3
  echo "$stored|$hdr|$val|$end"')"
[ "$out" = "STORED|VALUE csd 0 5|hello|END" ] || { echo "set/get round-trip failed (got: $out)"; exit 1; }

uid="$(docker exec "$C" sh -c 'awk "/^Uid:/{print \$2}" /proc/1/status')"
[ "${uid:-0}" != 0 ] || { echo "memcached running as ROOT"; exit 1; }

echo "correct: set/get round-trip ok, memcached uid=$uid (non-root)"
