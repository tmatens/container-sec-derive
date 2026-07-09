#!/bin/sh
# Synthetic drop-test fidelity target (csd#340 items 2 & 3). Demonstrates that a
# capability's necessity depends on the mounted dir's INITIAL STATE — content,
# ownership, AND permission mode — none of which the default fresh-empty-dir
# staging reproduces. Runs as root (uid 0), so DAC applies only when the relevant
# CAP is dropped.
#
# CSD_SEED_OP selects the probe (default: read):
#   read  (item 2): read ${DATA}/secret. When that file pre-exists owned by a
#     foreign uid at mode 0600, the read REQUIRES CAP_DAC_OVERRIDE; a fresh empty
#     mount has no such file, so nothing requires it.
#   write (item 3): create a file inside ${DATA}. When ${DATA} is a foreign-owned
#     dir at a restrictive MODE (0700), the write REQUIRES CAP_DAC_OVERRIDE; the
#     same foreign-owned dir at 0777 permits it — so MODE, not ownership, is the
#     discriminator (the paired specs hold ownership constant and vary only mode).
set -u
DATA="${CSD_SEED_DIR:-/data}"
OP="${CSD_SEED_OP:-read}"

case "$OP" in
  write)
    if (echo csd-probe > "${DATA}/csd-probe") 2>/dev/null; then
      echo "wrote into ${DATA} OK (dir mode permits, or DAC_OVERRIDE present)"
    else
      echo "DENIED writing into ${DATA} as root — need CAP_DAC_OVERRIDE (restrictive dir mode)"
      exit 1
    fi
    ;;
  *)
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
    ;;
esac

# Success marker the correctness check waits on, then stay up so the drop-test can
# probe liveness (a denied probe exits above and the container never gets here).
: > /tmp/csd-ready
exec tail -f /dev/null
