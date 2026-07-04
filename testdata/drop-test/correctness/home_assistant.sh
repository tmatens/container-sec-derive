#!/usr/bin/env bash
# Home Assistant correctness (capabilities). HA runs `python3 -m homeassistant`
# under s6 AS ROOT — there is no privilege drop and no chown in init, so (unlike
# forgejo/postgres) there is no SETUID/SETGID/CHOWN startup step to assert. The one
# capability HA core exercises comes from WHERE it writes: the config dir is a bind
# owned by the deploy user (non-root), and HA-as-root creating its DB / .storage /
# logs there needs DAC_OVERRIDE. The drop-test reproduces that with a fresh,
# non-root-owned /config (a ${VAR} mount), so this check exercises the real write
# path rather than mere liveness:
#   1. the onboarding API returns its JSON steps — HA only reaches this after it has
#      parsed config and written home-assistant_v2.db + .storage + logs into the
#      (non-root-owned) /config as root; without DAC_OVERRIDE those writes fail and
#      HA never comes up;
#   2. completing owner onboarding (create the first user) returns HTTP 200 with an
#      auth_code — a further real write to .storage/auth as root.
# NOTE ON SCOPE: this is HA *core* on a base config. Capabilities pulled in by
# specific integrations (e.g. NET_RAW for ICMP ping, device access for USB/BT) are
# not exercised here — see the criteria doc.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

READY='import urllib.request as u,json,sys; d=json.load(u.urlopen("http://127.0.0.1:8123/api/onboarding",timeout=3)); sys.exit(0 if isinstance(d,list) and d and "step" in d[0] else 1)'

deadline=$((SECONDS+60))
until docker exec "$C" python3 -c "$READY" 2>/dev/null; do
  (( SECONDS >= deadline )) && { echo "HA onboarding API never became ready (config write path broken?)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

# Complete owner onboarding — a real write to .storage/auth as root.
out="$(docker exec "$C" python3 -c 'import urllib.request as u,json; b=json.dumps({"client_id":"http://localhost:8123/","name":"csd","username":"csd","password":"csdprobe-pw-12345","language":"en"}).encode(); r=u.urlopen(u.Request("http://127.0.0.1:8123/api/onboarding/users",data=b,headers={"Content-Type":"application/json"}),timeout=15); d=json.load(r); print(r.status, "auth_code" in d)' 2>&1)"
[ "$out" = "200 True" ] || { echo "onboarding user-create failed (expected '200 True', got: ${out##*$'\n'})"; exit 1; }

echo "correct: HA up, config/DB/.storage written as root into a non-root /config, owner onboarding succeeded"
