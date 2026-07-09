#!/usr/bin/env bash
# Live drop-test smoke for the mount-MODE fidelity class (csd#340 item 3). Reuses
# the seed-fidelity synthetic image in WRITE mode: its root entrypoint creates a
# file inside /data. Two derivations hold the mount's foreign OWNERSHIP constant
# (uid 9999) and vary ONLY the dir permission mode:
#   restrictive dir_mode 0700 -> root write needs DAC_OVERRIDE -> NEEDED
#   permissive  dir_mode 0777 -> root write needs no cap        -> REMOVABLE
# The needed-vs-removable split with ownership fixed isolates MODE as the trigger,
# proving the harness reproduces the mount mode (#337 covered ownership only).
#
# Needs docker + python3 (pyyaml) + jq. No BPF/ig — drop-test uses no eBPF.
#   make smoke-drop-mode   |   ./scripts/smoke_drop_mode.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-python3}"
IMAGE="csd-seed-fidelity:0.1"

command -v docker >/dev/null 2>&1 || { echo "smoke-drop-mode: docker required" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-drop-mode: jq required" >&2; exit 2; }

echo "smoke-drop-mode: building synthetic image ${IMAGE}"
if ! docker build -t "${IMAGE}" "${REPO}/testdata/drop-test/synthetic-seed" >/dev/null; then
  echo "FAIL smoke-drop-mode: synthetic image build failed" >&2
  exit 1
fi

run_min() {
  local spec="$1" out rc
  out="$(PY="${PY}" bash "${REPO}/scripts/drop_test.sh" "${spec}" 2>/dev/null)"; rc=$?
  if [ "${rc}" != 0 ]; then
    echo "smoke-drop-mode: drop_test failed (exit ${rc}) on ${spec##*/}" >&2
    return 1
  fi
  printf '%s' "${out}" | jq -r '.minimum | join(" ")'
}

echo "smoke-drop-mode: deriving RESTRICTIVE 0700 (expect DAC_OVERRIDE needed)"
restrictive_min="$(run_min "${REPO}/testdata/drop-test/seed-mode-caps.yaml")" || exit 1
echo "  0700 minimum: [${restrictive_min}]"

echo "smoke-drop-mode: deriving PERMISSIVE 0777 control (expect DAC_OVERRIDE removable)"
permissive_min="$(run_min "${REPO}/testdata/drop-test/seed-mode-permissive-caps.yaml")" || exit 1
echo "  0777 minimum: [${permissive_min}]"

rc=0
case " ${restrictive_min} " in
  *" DAC_OVERRIDE "*) echo "PASS: 0700 derives DAC_OVERRIDE needed (restrictive mode caught)" ;;
  *) echo "FAIL: 0700 did NOT derive DAC_OVERRIDE — got [${restrictive_min}]"; rc=1 ;;
esac
case " ${permissive_min} " in
  *" DAC_OVERRIDE "*) echo "FAIL: 0777 control WRONGLY derived DAC_OVERRIDE — got [${permissive_min}]"; rc=1 ;;
  *) echo "PASS: 0777 control omits DAC_OVERRIDE (mode is the discriminator, ownership held constant)" ;;
esac

if [ "${rc}" = 0 ]; then echo "smoke-drop-mode: all PASS"; else echo "smoke-drop-mode: FAILURES"; fi
exit "${rc}"
