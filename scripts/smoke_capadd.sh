#!/usr/bin/env bash
# Live-BPF smoke for the v0.5 dangerous-cap_add validator (`--observe capadd`).
#
# capadd reuses the v0.1 trace_capabilities gadget, so its attach is already
# exercised by scripts/smoke_wsl2.sh; this script adds the two things NEW in v0.5
# that fixture replay cannot cover on a real trace_capabilities stream:
#   1. the per-cap syscall correlation (a held check is keyed to its syscall and
#      the validated cap is reported "used"), and
#   2. the unused -> removable classification when a cap in the granted set fires
#      no held check under the workload.
#
# Hardware-free, deterministic gate: the synthetic exerciser deterministically
# fires held cap_capable checks for CAP_CHOWN / CAP_SETUID / CAP_SETGID every
# cycle (testdata/synthetic/exerciser.c — the same exact ground-truth the cap
# smoke relies on). We pass those as the granted set together with SYS_MODULE,
# which the exerciser never invokes, so the run must classify CHOWN as used and
# SYS_MODULE as removable. Both gates are hard (an empty/ wrong result is a real
# csd bug, not a workload artifact). The container runs as root by default, so it
# holds the validated caps and the checks come back capable=true.
#
# Gate (hard):
#   capadd_validation.findings ∋ {cap: CHOWN,      used: true}
#   capadd_validation.findings ∋ {cap: SYS_MODULE, removable: true}
#
# Requires: docker, csd (built; pass CSD=/path to override), jq, the vendored ig
# binary on PATH (the IG version pin is enforced inside csd).
#
# Usage:
#   make smoke-capadd
#   ./scripts/smoke_capadd.sh
#
# Optional env:
#   CSD=/path/to/csd     binary under test (defaults to ./csd)
#   DURATION=30s         observation window
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
IMAGE="csd-synthetic-exerciser:0.1"
CAP_ADD="CHOWN,SETUID,SETGID,SYS_MODULE"

if [[ ! -x "${CSD}" ]]; then
    echo "smoke-capadd: csd binary not found or not executable at ${CSD}" >&2
    echo "smoke-capadd: run 'make build' first or pass CSD=/path/to/csd" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-capadd: jq is required" >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "smoke-capadd: docker is required" >&2
    exit 2
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "smoke-capadd: building synthetic exerciser image (one-time)"
    docker build -t "${IMAGE}" testdata/synthetic >/dev/null
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
WORKLOAD="$(pwd)/testdata/synthetic/workload.sh"

CONTAINER="csd-capadd-smoke"
SIDECAR="${WORKDIR}/capadd.json"
LOG="${WORKDIR}/capadd-csd.log"

docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if ! docker run -d --name "${CONTAINER}" "${IMAGE}" >/dev/null; then
    echo "FAIL capadd: docker run failed"
    exit 1
fi

(CONTAINER="${CONTAINER}" "${WORKLOAD}" >"${WORKDIR}/capadd-workload.log" 2>&1 || true) &
WPID=$!

rc=0
if ! "${CSD}" --observe capadd --cap-add "${CAP_ADD}" --container "${CONTAINER}" \
        --duration "${DURATION}" --workload "${WORKLOAD}" --out "${SIDECAR}" >"${LOG}" 2>&1; then
    rc=$?
    wait "${WPID}" 2>/dev/null || true
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    case ${rc} in
        30) echo "FAIL capadd: csd exited SchemaMismatch (30) — host ig differs from PinnedIGVersion" ;;
        31) echo "FAIL capadd: csd exited IGMissing (31) — install the pinned ig binary on PATH" ;;
        *)  echo "FAIL capadd: csd exited ${rc}; see ${LOG}" ;;
    esac
    exit 1
fi
wait "${WPID}" 2>/dev/null || true
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true

if [[ ! -s "${SIDECAR}" ]]; then
    echo "FAIL capadd: sidecar empty or missing at ${SIDECAR}"
    exit 1
fi

GATE='((.capadd_validation.findings // []) | any(.cap == "CHOWN" and .used == true)) and ((.capadd_validation.findings // []) | any(.cap == "SYS_MODULE" and .removable == true))'
if jq -e "${GATE}" "${SIDECAR}" >/dev/null; then
    recorded=$(jq -r '.trace_health.events_recorded // 0' "${SIDECAR}")
    rec=$(jq -rc '.capadd_validation.recommended_cap_add // []' "${SIDECAR}")
    echo "PASS capadd: CHOWN used + SYS_MODULE removable (events_recorded=${recorded}, recommended_cap_add=${rec})"
    echo "smoke-capadd: 1 passed, 0 failed"
else
    echo "FAIL capadd: gate not satisfied; got $(jq -c '.capadd_validation' "${SIDECAR}")"
    exit 1
fi
