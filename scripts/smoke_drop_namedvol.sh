#!/usr/bin/env bash
# Live drop-test smoke for named-volume initial-ownership fidelity (csd#340 item
# 4). Reuses the seed-fidelity synthetic in chown-repair mode: its root entrypoint
# repairs /data's ownership to the service uid (1000) on boot, but only when it is
# not already correct (the idempotent chown postgres/mariadb do). Two derivations
# vary ONLY the mount's initial ownership:
#   declared named volume (csdnv:/data) -> drop_test stages it worst-case foreign
#     (uid 9999) -> the repair fires -> CHOWN NEEDED
#   seed_mounts owner 1000 (correctly-owned) -> repair is a no-op -> CHOWN REMOVABLE
# A docker named volume inits root-owned-EMPTY; passing that through would
# under-derive the CHOWN a foreign-owned volume needs (the #337-class bug). This
# guards that declared named volumes are staged worst-case, not trusted.
#
# Needs docker + python3 (pyyaml) + jq. No BPF/ig — drop-test uses no eBPF.
#   make smoke-drop-namedvol   |   ./scripts/smoke_drop_namedvol.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-python3}"
IMAGE="csd-seed-fidelity:0.1"

command -v docker >/dev/null 2>&1 || { echo "smoke-drop-namedvol: docker required" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-drop-namedvol: jq required" >&2; exit 2; }

echo "smoke-drop-namedvol: building synthetic image ${IMAGE}"
if ! docker build -t "${IMAGE}" "${REPO}/testdata/drop-test/synthetic-seed" >/dev/null; then
  echo "FAIL smoke-drop-namedvol: synthetic image build failed" >&2
  exit 1
fi

run_min() {
  local spec="$1" out rc
  out="$(PY="${PY}" bash "${REPO}/scripts/drop_test.sh" "${spec}" 2>/dev/null)"; rc=$?
  if [ "${rc}" != 0 ]; then
    echo "smoke-drop-namedvol: drop_test failed (exit ${rc}) on ${spec##*/}" >&2
    return 1
  fi
  printf '%s' "${out}" | jq -r '.minimum | join(" ")'
}

echo "smoke-drop-namedvol: deriving NAMED VOLUME (expect CHOWN needed)"
namedvol_min="$(run_min "${REPO}/testdata/drop-test/seed-namedvol-caps.yaml")" || exit 1
echo "  named-volume minimum: [${namedvol_min}]"

echo "smoke-drop-namedvol: deriving CORRECTLY-OWNED control (expect CHOWN removable)"
owned_min="$(run_min "${REPO}/testdata/drop-test/seed-namedvol-owned-caps.yaml")" || exit 1
echo "  owned        minimum: [${owned_min}]"

rc=0
case " ${namedvol_min} " in
  *" CHOWN "*) echo "PASS: named volume derives CHOWN needed (staged worst-case foreign-owned)" ;;
  *) echo "FAIL: named volume did NOT derive CHOWN — got [${namedvol_min}]"; rc=1 ;;
esac
case " ${owned_min} " in
  *" CHOWN "*) echo "FAIL: correctly-owned control WRONGLY derived CHOWN — got [${owned_min}]"; rc=1 ;;
  *) echo "PASS: correctly-owned control omits CHOWN (ownership is the discriminator)" ;;
esac

if [ "${rc}" = 0 ]; then echo "smoke-drop-namedvol: all PASS"; else echo "smoke-drop-namedvol: FAILURES"; fi
exit "${rc}"
