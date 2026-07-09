#!/usr/bin/env bash
# Live drop-test smoke for the sysctl-posture fidelity class (csd#340 item 5).
# NET_BIND_SERVICE for a low-port bind hinges on
# net.ipv4.ip_unprivileged_port_start; docker defaults it to 0 (every port
# unprivileged), so the cap reads falsely-removable. The seed synthetic's bindlow
# op binds :80; two derivations vary ONLY the pinned sysctl:
#   ip_unprivileged_port_start=1024 (hardened) -> bind needs the cap -> NEEDED
#   ip_unprivileged_port_start=0    (loose)    -> :80 unprivileged   -> REMOVABLE
# This is caddy's "drop NET_BIND_SERVICE" caveat made faithful: run.sysctls pins
# the hardened posture so the verdict isn't silently loose.
#
# Needs docker + python3 (pyyaml) + jq. No BPF/ig — drop-test uses no eBPF.
#   make smoke-drop-netbind   |   ./scripts/smoke_drop_netbind.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-python3}"
IMAGE="csd-seed-fidelity:0.1"

command -v docker >/dev/null 2>&1 || { echo "smoke-drop-netbind: docker required" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-drop-netbind: jq required" >&2; exit 2; }

echo "smoke-drop-netbind: building synthetic image ${IMAGE}"
if ! docker build -t "${IMAGE}" "${REPO}/testdata/drop-test/synthetic-seed" >/dev/null; then
  echo "FAIL smoke-drop-netbind: synthetic image build failed" >&2
  exit 1
fi

run_min() {
  local spec="$1" out rc
  out="$(PY="${PY}" bash "${REPO}/scripts/drop_test.sh" "${spec}" 2>/dev/null)"; rc=$?
  if [ "${rc}" != 0 ]; then
    echo "smoke-drop-netbind: drop_test failed (exit ${rc}) on ${spec##*/}" >&2
    return 1
  fi
  printf '%s' "${out}" | jq -r '.minimum | join(" ")'
}

echo "smoke-drop-netbind: deriving HARDENED (ip_unprivileged_port_start=1024; expect NET_BIND_SERVICE needed)"
hardened_min="$(run_min "${REPO}/testdata/drop-test/netbind-hardened-caps.yaml")" || exit 1
echo "  hardened minimum: [${hardened_min}]"

echo "smoke-drop-netbind: deriving LOOSE control (ip_unprivileged_port_start=0; expect NET_BIND_SERVICE removable)"
loose_min="$(run_min "${REPO}/testdata/drop-test/netbind-loose-caps.yaml")" || exit 1
echo "  loose    minimum: [${loose_min}]"

rc=0
case " ${hardened_min} " in
  *" NET_BIND_SERVICE "*) echo "PASS: hardened posture derives NET_BIND_SERVICE needed (low-port bind gated)" ;;
  *) echo "FAIL: hardened did NOT derive NET_BIND_SERVICE — got [${hardened_min}]"; rc=1 ;;
esac
case " ${loose_min} " in
  *" NET_BIND_SERVICE "*) echo "FAIL: loose control WRONGLY derived NET_BIND_SERVICE — got [${loose_min}]"; rc=1 ;;
  *) echo "PASS: loose control omits NET_BIND_SERVICE (sysctl posture is the discriminator)" ;;
esac

if [ "${rc}" = 0 ]; then echo "smoke-drop-netbind: all PASS"; else echo "smoke-drop-netbind: FAILURES"; fi
exit "${rc}"
