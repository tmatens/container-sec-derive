#!/usr/bin/env bash
#
# End-to-end test for the advise_capabilities gadget: proves the real eBPF
# signal path, not just the pure logic. Runs a container that deliberately
# exercises CAP_CHOWN (root chowning a file to another uid) and asserts the
# gadget's advice recommends CHOWN and applies a cap_drop: ALL baseline.
#
# Requires root (ig loads eBPF; the local OCI store lives under /var/lib/ig).
#   sudo bash gadgets/advise_capabilities/test/e2e.sh
set -euo pipefail

IG="${IG:-ig}"
GADGET_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="advise_capabilities:e2e"
CONTAINER="advise-caps-e2e"
DURATION="${DURATION:-12s}"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== ensure OCI store is writable =="
install -d /var/lib/ig

echo "== build gadget =="
"$IG" image build "$GADGET_DIR" -t "$IMAGE"

echo "== start a container that exercises CAP_CHOWN in a loop =="
cleanup
docker run -d --name "$CONTAINER" --rm busybox:latest \
  sh -c 'touch /tmp/f; while true; do chown 1:1 /tmp/f; chown 0:0 /tmp/f; sleep 0.2; done' >/dev/null
sleep 1

echo "== run advise_capabilities for $DURATION =="
OUT="$("$IG" run "$IMAGE" --containername "$CONTAINER" --timeout "$DURATION" 2>/dev/null || true)"
echo "---- gadget output ----"
echo "$OUT"
echo "-----------------------"

echo "== assertions =="
fail=0
grep -q "cap_drop" <<<"$OUT" || { echo "FAIL: no cap_drop baseline in output"; fail=1; }
grep -qw "ALL"      <<<"$OUT" || { echo "FAIL: cap_drop is not ALL"; fail=1; }
grep -qw "CHOWN"    <<<"$OUT" || { echo "FAIL: expected CHOWN (container exercised chown) not recommended"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "PASS: advise_capabilities recommended CHOWN with a cap_drop: ALL baseline"
else
  echo "E2E FAILED"; exit 1
fi
