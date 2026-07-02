#!/usr/bin/env bash
#
# End-to-end test for the advise_capabilities gadget: proves the real eBPF
# signal path, not just the pure logic. Runs a container that deliberately
# exercises CAP_CHOWN (root chowning a file to another uid) and asserts the
# gadget's advice recommends CHOWN under a cap_drop: ALL baseline.
#
# ig loads eBPF and writes the OCI store under /var/lib/ig, so the ig calls need
# root. Either run the whole script as root:
#     sudo IG=/path/to/ig bash gadgets/advise_capabilities/test/e2e.sh
# or, with passwordless sudo scoped to the ig binary, run as your user and the
# script will sudo the ig calls itself.
set -euo pipefail

IG="${IG:-ig}"
GADGET_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="advise_capabilities:e2e"
CONTAINER="advise-caps-e2e"
DURATION="${DURATION:-8}" # ig --timeout is integer seconds, not a duration string

# ig needs root; docker uses the caller's group membership.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo -n"; fi

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== build gadget into the local store =="
$SUDO "$IG" image build "$GADGET_DIR" -t "$IMAGE"

echo "== start a container that exercises CAP_CHOWN in a loop =="
cleanup
docker run -d --name "$CONTAINER" --rm busybox:latest \
  sh -c 'touch /tmp/f; while true; do chown 1:1 /tmp/f; chown 0:0 /tmp/f; sleep 0.2; done' >/dev/null
sleep 1

echo "== run advise_capabilities for ${DURATION}s =="
# --verify-image=false: the locally built image is unsigned.
# --pull never: use the local store, do not reach the registry.
OUT="$($SUDO "$IG" run "$IMAGE" \
  --verify-image=false --pull never \
  --containername "$CONTAINER" --timeout "$DURATION" 2>/dev/null || true)"
echo "---- gadget output ----"
echo "$OUT"
echo "-----------------------"

echo "== assertions =="
fail=0
grep -q "cap_drop"      <<<"$OUT" || { echo "FAIL: no cap_drop baseline in output"; fail=1; }
grep -qw "ALL"          <<<"$OUT" || { echo "FAIL: cap_drop is not ALL"; fail=1; }
grep -qw "CHOWN"        <<<"$OUT" || { echo "FAIL: expected CHOWN (container exercised chown) not recommended"; fail=1; }
grep -qw "SYS_ADMIN"    <<<"$OUT" && { echo "FAIL: SYS_ADMIN recommended but never exercised (over-permission)"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "PASS: advise_capabilities recommended CHOWN (and only used caps) with a cap_drop: ALL baseline"
else
  echo "E2E FAILED"; exit 1
fi
