#!/usr/bin/env bash
# pihole correctness (capabilities, DNS-only scope): real DNS resolution with
# no external dependence — dig the `pi.hole` name, which pihole-FTL answers
# authoritatively itself, so the check is deterministic per trial and no
# upstream reachability sits in the loop. Probes exec as --user pihole using
# the in-image dig (probe-caps hygiene); plus the non-root uid assert on FTL
# (the drop is FTL's own — a broken drop must not pass while serving as root).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

deadline=$((SECONDS+90))
until grep -q "listening on .* port 53" <<<"$(docker logs "$C" 2>&1)"; do
  (( SECONDS >= deadline )) && { echo "FTL never listened on 53: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

# Real resolution round-trip: pi.hole is answered locally by FTL.
ans="$(docker exec --user pihole "$C" dig +short +time=3 +tries=2 @127.0.0.1 pi.hole 2>/dev/null)"
[ -n "$ans" ] || { echo "dig pi.hole returned no answer"; exit 1; }

# FTL dropped to its non-root user.
uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in *pihole-FTL*|*FTL*) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "pihole-FTL running as ROOT or not found (drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: pi.hole resolves locally (${ans}), FTL uid=$uid (non-root)"
