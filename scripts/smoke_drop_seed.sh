#!/usr/bin/env bash
# Live drop-test smoke for the pre-existing-foreign-owned-data fidelity class
# (csd#340 item 2). Builds a synthetic image whose entrypoint reads a mode-0600
# file owned by a foreign uid on /data; reading it AS ROOT requires
# CAP_DAC_OVERRIDE. Two derivations of the SAME image prove the seeding is
# load-bearing (and that the harness previously under-derived this class):
#   seeded (run.seed_mounts stages the foreign-owned file) -> DAC_OVERRIDE NEEDED
#   fresh  (no seed; the entrypoint's fresh branch)        -> DAC_OVERRIDE REMOVABLE
# A false "removable" on the seeded case is the #337-class bug (a cap that breaks
# prod derived droppable); this is its inverse guard.
#
# Needs docker + python3 (pyyaml) + jq. No BPF/ig — drop-test uses no eBPF.
#   make smoke-drop-seed   |   ./scripts/smoke_drop_seed.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-python3}"
IMAGE="csd-seed-fidelity:0.1"

command -v docker >/dev/null 2>&1 || { echo "smoke-drop-seed: docker required" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-drop-seed: jq required" >&2; exit 2; }

echo "smoke-drop-seed: building synthetic image ${IMAGE}"
if ! docker build -t "${IMAGE}" "${REPO}/testdata/drop-test/synthetic-seed" >/dev/null; then
  echo "FAIL smoke-drop-seed: synthetic image build failed" >&2
  exit 1
fi

# run_min <spec> -> echoes the derived minimum (space-separated), or fails loudly
# if drop_test itself errored (e.g. a non-representative baseline) rather than
# silently reporting an empty minimum.
run_min() {
  local spec="$1" out rc
  out="$(PY="${PY}" bash "${REPO}/scripts/drop_test.sh" "${spec}" 2>/dev/null)"; rc=$?
  if [ "${rc}" != 0 ]; then
    echo "smoke-drop-seed: drop_test failed (exit ${rc}) on ${spec##*/}" >&2
    return 1
  fi
  printf '%s' "${out}" | jq -r '.minimum | join(" ")'
}

echo "smoke-drop-seed: deriving SEEDED (expect DAC_OVERRIDE needed)"
seeded_min="$(run_min "${REPO}/testdata/drop-test/seed-fidelity-caps.yaml")" || exit 1
echo "  seeded minimum: [${seeded_min}]"

echo "smoke-drop-seed: deriving FRESH control (expect DAC_OVERRIDE removable)"
fresh_min="$(run_min "${REPO}/testdata/drop-test/seed-fidelity-fresh-caps.yaml")" || exit 1
echo "  fresh  minimum: [${fresh_min}]"

rc=0
case " ${seeded_min} " in
  *" DAC_OVERRIDE "*) echo "PASS: seeded derives DAC_OVERRIDE needed (pre-existing foreign content caught)" ;;
  *) echo "FAIL: seeded did NOT derive DAC_OVERRIDE — got [${seeded_min}]"; rc=1 ;;
esac
case " ${fresh_min} " in
  *" DAC_OVERRIDE "*) echo "FAIL: fresh control WRONGLY derived DAC_OVERRIDE — got [${fresh_min}]"; rc=1 ;;
  *) echo "PASS: fresh control omits DAC_OVERRIDE (the fresh-only bias the seed closes)" ;;
esac

if [ "${rc}" = 0 ]; then echo "smoke-drop-seed: all PASS"; else echo "smoke-drop-seed: FAILURES"; fi
exit "${rc}"
