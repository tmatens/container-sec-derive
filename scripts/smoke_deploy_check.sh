#!/usr/bin/env bash
# Live end-to-end smoke for the `csd deploy-check` subcommand (#355). Unlike the
# hermetic tests in internal/deploycheck (which stub the child script), this
# drives the REAL binary through the REAL pipeline: csd deploy-check ->
# compose_derive.sh -> compose_to_spec.py -> drop_test.sh (restarts real
# containers) -> compose_verdict.py, against a synthetic compose whose derived
# minimum is deterministically [CHOWN].
#
# It proves TWO things at once:
#   1. the pipeline VERDICT (read from the evidence JSON on stdout) is correct
#      for each declared cap_add — matches / over_permissioned / under_permissioned;
#   2. the wrapper's EXIT-CODE POLICY is correct — under_permissioned is always
#      non-zero (12), over_permissioned is advisory (0) by default and non-zero
#      (11) under --enforce.
#
# The three services in the fixture differ only in declared cap_add; the
# rootfs-chown op needs CAP_CHOWN with no seeded mount and no pinned sysctl, so
# the derivation is host-posture-independent.
#
# Needs docker + python3 (pyyaml) + jq + a built csd. No BPF/ig — drop-test uses
# no eBPF. Self-hosted-runner lane (restarts real containers).
#   CSD=./csd make smoke-deploy-check   |   CSD=./csd ./scripts/smoke_deploy_check.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-python3}"
CSD="${CSD:-$REPO/csd}"
IMAGE="csd-seed-fidelity:0.1"
COMPOSE="$REPO/testdata/drop-test/deploy-check-synthetic.yaml"

command -v docker >/dev/null 2>&1 || { echo "smoke-deploy-check: docker required" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-deploy-check: jq required" >&2; exit 2; }
[ -x "$CSD" ] || { echo "smoke-deploy-check: csd binary not found/executable at '$CSD' (build it or set CSD=)" >&2; exit 2; }

echo "smoke-deploy-check: building synthetic image ${IMAGE}"
if ! docker build -t "${IMAGE}" "${REPO}/testdata/drop-test/synthetic-seed" >/dev/null; then
  echo "FAIL smoke-deploy-check: synthetic image build failed" >&2
  exit 1
fi

rc=0
# check <service> <want_exit> <want_verdict> [--enforce]
# Runs csd deploy-check, captures stdout (evidence JSON) + exit code, and asserts
# both the exit code (wrapper policy) and the .deploy_check.verdict (pipeline).
check() {
  local svc="$1" want_rc="$2" want_verdict="$3"; shift 3
  local out got_rc got_verdict label="$svc${1:+ $1}"
  out="$(PY="$PY" "$CSD" deploy-check --compose "$COMPOSE" --service "$svc" \
          --script-dir "$REPO/scripts" "$@" 2>/dev/null)"; got_rc=$?
  got_verdict="$(printf '%s' "$out" | jq -r '.deploy_check.verdict // "MISSING"' 2>/dev/null || echo MISSING)"
  if [ "$got_rc" = "$want_rc" ] && [ "$got_verdict" = "$want_verdict" ]; then
    echo "PASS: ${label} -> verdict=${got_verdict} exit=${got_rc}"
  else
    echo "FAIL: ${label} -> verdict=${got_verdict} exit=${got_rc} (want verdict=${want_verdict} exit=${want_rc})"
    rc=1
  fi
}

echo "smoke-deploy-check: matches (declared [CHOWN] == derived [CHOWN])"
check deploy-check-matches 0 matches

echo "smoke-deploy-check: under_permissioned (CHOWN needed, undeclared) — always non-zero"
check deploy-check-under 12 under_permissioned

echo "smoke-deploy-check: over_permissioned (NET_RAW declared, unused) — advisory (exit 0) by default"
check deploy-check-over 0 over_permissioned

echo "smoke-deploy-check: over_permissioned under --enforce — escalates to non-zero (11)"
check deploy-check-over 11 over_permissioned --enforce

if [ "$rc" = 0 ]; then echo "smoke-deploy-check: all PASS"; else echo "smoke-deploy-check: FAILURES"; fi
exit "$rc"
