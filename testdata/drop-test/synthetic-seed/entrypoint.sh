#!/bin/sh
# Synthetic drop-test fidelity target (csd#340 item 2). Demonstrates the
# fresh-only staging bias: a capability exercised ONLY against pre-existing,
# foreign-owned content is invisible when the drop-test stages a fresh empty dir.
#
# Runs as root (uid 0). Reading another uid's mode-0600 file as root is DENIED
# unless CAP_DAC_OVERRIDE is held (root is subject to DAC without it). So:
#   - seeded mount (a foreign-owned 0600 file already present): the read REQUIRES
#     DAC_OVERRIDE  -> the drop-test derives it needed.
#   - fresh empty mount (no such file):        nothing requires it -> removable.
# The paired specs (seed-fidelity{,-fresh}-caps.yaml) drive exactly this contrast.
set -u
DATA="${CSD_SEED_DIR:-/data}"
F="${DATA}/secret"

# `[ -e ]` needs only search (x) on ${DATA}; the seed keeps ${DATA} 0755 so the
# probe is honest — it is the READ of the 0600 file that gates on DAC_OVERRIDE.
if [ -e "$F" ]; then
  if cat "$F" >/dev/null 2>&1; then
    echo "read pre-existing foreign-owned content OK (DAC_OVERRIDE present)"
  else
    echo "DENIED reading ${F} as root — need CAP_DAC_OVERRIDE"
    exit 1
  fi
else
  echo "no pre-existing content at ${F} (fresh mount) — nothing needs DAC_OVERRIDE"
fi

# Success marker the correctness check waits on, then stay up so the drop-test can
# probe liveness (a failed read exits above and the container never gets here).
: > /tmp/csd-ready
exec tail -f /dev/null
