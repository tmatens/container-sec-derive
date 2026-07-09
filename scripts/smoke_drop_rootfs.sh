#!/usr/bin/env bash
# Live drop-test smoke for the no-mount ROOTFS cold-start lock (csd#340 item 6).
# A service with NO external volume that mkdir+chowns a rootfs path on boot is
# already faithful — the rootfs is fresh on every trial (a new container) — but
# nothing proved it, and the confidence guard must not treat "no mounts" as
# "nothing to exercise". This locks the case:
#   rootfs mkdir + chown to uid 999 (a real owner change) -> CHOWN NEEDED
#   rootfs mkdir, CSD_ROOTFS_CHOWN_UID=0 (no-op)           -> CHOWN REMOVABLE
# No mounts, no seed — the pure no-mount rootfs path.
#
# Needs docker + python3 (pyyaml) + jq. No BPF/ig — drop-test uses no eBPF.
#   make smoke-drop-rootfs   |   ./scripts/smoke_drop_rootfs.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-python3}"
IMAGE="csd-seed-fidelity:0.1"

command -v docker >/dev/null 2>&1 || { echo "smoke-drop-rootfs: docker required" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-drop-rootfs: jq required" >&2; exit 2; }

echo "smoke-drop-rootfs: building synthetic image ${IMAGE}"
if ! docker build -t "${IMAGE}" "${REPO}/testdata/drop-test/synthetic-seed" >/dev/null; then
  echo "FAIL smoke-drop-rootfs: synthetic image build failed" >&2
  exit 1
fi

run_min() {
  local spec="$1" out rc
  out="$(PY="${PY}" bash "${REPO}/scripts/drop_test.sh" "${spec}" 2>/dev/null)"; rc=$?
  if [ "${rc}" != 0 ]; then
    echo "smoke-drop-rootfs: drop_test failed (exit ${rc}) on ${spec##*/}" >&2
    return 1
  fi
  printf '%s' "${out}" | jq -r '.minimum | join(" ")'
}

echo "smoke-drop-rootfs: deriving ROOTFS CHOWN (no mounts; expect CHOWN needed)"
chown_min="$(run_min "${REPO}/testdata/drop-test/rootfs-nomount-caps.yaml")" || exit 1
echo "  rootfs-chown minimum: [${chown_min}]"

echo "smoke-drop-rootfs: deriving NO-OP control (no mounts; expect CHOWN removable)"
noop_min="$(run_min "${REPO}/testdata/drop-test/rootfs-nomount-noop-caps.yaml")" || exit 1
echo "  no-op        minimum: [${noop_min}]"

rc=0
case " ${chown_min} " in
  *" CHOWN "*) echo "PASS: no-mount rootfs chown derives CHOWN needed (rootfs is fresh per trial — faithful)" ;;
  *) echo "FAIL: rootfs chown did NOT derive CHOWN — got [${chown_min}]"; rc=1 ;;
esac
case " ${noop_min} " in
  *" CHOWN "*) echo "FAIL: no-op control WRONGLY derived CHOWN — got [${noop_min}]"; rc=1 ;;
  *) echo "PASS: no-op control omits CHOWN (the ownership change is the discriminator)" ;;
esac

if [ "${rc}" = 0 ]; then echo "smoke-drop-rootfs: all PASS"; else echo "smoke-drop-rootfs: FAILURES"; fi
exit "${rc}"
