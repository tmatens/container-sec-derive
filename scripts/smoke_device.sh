#!/usr/bin/env bash
# Live-BPF smoke for the v0.3 device-decomposition (`--observe devices`) and
# privileged-mode decomposition (`--observe privileged`) observers.
#
# The device observer reuses the v0.2 trace_open gadget, so its attach is
# already exercised by scripts/smoke_fs.sh; this script adds the two things that
# are NEW in v0.3 and that fixture replay cannot cover:
#   1. the device classifier on a real trace_open stream (a non-default /dev
#      node is recorded; the default device set is not), and
#   2. the privileged composition's CONCURRENT two-gadget live path
#      (trace_capabilities + trace_open running together in one window).
#
# Hardware-free, deterministic gate: the synthetic exerciser is run with
# `--device /dev/null:/dev/csd-exerciser-dev`, which gives the container a
# non-default device node backed by the host's /dev/null. The exerciser opens
# that node every cycle (testdata/synthetic/exerciser.c exercise_device), so
# trace_open fires a device open continuously post-attach — no GPU/tun/kvm
# hardware required on the runner. The reference images carry no non-default
# devices, so they are not part of this matrix (a device observation of nothing
# is the correct result for them, not a useful gate).
#
# Gates (both hard — an empty result is a real csd bug, not a workload artifact):
#   --observe devices:    device_paths ∋ /dev/csd-exerciser-dev
#   --observe privileged: privileged_decomposition.devices ∋ /dev/csd-exerciser-dev
#                         AND privileged_decomposition.cap_add is non-empty
#                         (proves BOTH concurrent gadget streams fired).
#
# Requires: docker, csd (built; pass CSD=/path to override), jq, the vendored ig
# binary on PATH (the IG version pin is enforced inside csd).
#
# Usage:
#   make smoke-device
#   ./scripts/smoke_device.sh
#
# Optional env:
#   CSD=/path/to/csd     binary under test (defaults to ./csd)
#   DURATION=30s         per-observer observation window
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
IMAGE="csd-synthetic-exerciser:0.1"
DEVNODE="/dev/csd-exerciser-dev"
DEVMAP="--device /dev/null:${DEVNODE}"

if [[ ! -x "${CSD}" ]]; then
    echo "smoke-device: csd binary not found or not executable at ${CSD}" >&2
    echo "smoke-device: run 'make build' first or pass CSD=/path/to/csd" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-device: jq is required" >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "smoke-device: docker is required" >&2
    exit 2
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "smoke-device: building synthetic exerciser image (one-time)"
    docker build -t "${IMAGE}" testdata/synthetic >/dev/null
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
WORKLOAD="$(pwd)/testdata/synthetic/workload.sh"

# run_observer <observer> <desc> <jq-gate>
#   Runs the synthetic exerciser with the mapped device node, observes it with
#   the given observer, and asserts the jq gate against the sidecar.
run_observer() {
    local observer="$1" desc="$2" gate="$3"
    local container="csd-dev-smoke-${observer}"
    local sidecar="${WORKDIR}/${observer}.json"
    local log="${WORKDIR}/${observer}-csd.log"
    local rc=0

    docker rm -f "${container}" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086 # word-splitting on DEVMAP is intentional
    if ! docker run -d --name "${container}" ${DEVMAP} "${IMAGE}" >/dev/null; then
        echo "FAIL ${observer}: docker run failed"
        return 1
    fi

    (CONTAINER="${container}" "${WORKLOAD}" >"${WORKDIR}/${observer}-workload.log" 2>&1 || true) &
    local wpid=$!

    # Capture csd's REAL exit code: `if ! cmd; then rc=$?` records the `!`
    # negation's status (0), not csd's, masking the 30/31 diagnostics below.
    "${CSD}" --observe "${observer}" --container "${container}" --duration "${DURATION}" \
        --workload "${WORKLOAD}" --out "${sidecar}" >"${log}" 2>&1 && rc=0 || rc=$?
    wait "${wpid}" 2>/dev/null || true
    docker rm -f "${container}" >/dev/null 2>&1 || true
    if [[ ${rc} -ne 0 ]]; then
        if [[ ${rc} -eq 30 ]]; then
            echo "FAIL ${observer}: csd exited SchemaMismatch (30) — host ig differs from PinnedIGVersion"
        elif [[ ${rc} -eq 31 ]]; then
            echo "FAIL ${observer}: csd exited IGMissing (31) — install the pinned ig binary on PATH"
        else
            echo "FAIL ${observer}: csd exited ${rc}; see ${log}"
        fi
        return 1
    fi

    if [[ ! -s "${sidecar}" ]]; then
        echo "FAIL ${observer}: sidecar empty or missing at ${sidecar}"
        return 1
    fi

    if jq -e "${gate}" "${sidecar}" >/dev/null; then
        local recorded
        recorded=$(jq -r '.trace_health.events_recorded // 0' "${sidecar}")
        echo "PASS ${observer}: ${desc} (events_recorded=${recorded})"
    else
        echo "FAIL ${observer}: ${desc} not satisfied; got $(jq -c '{device_paths:[(.device_paths//[])[].path],privileged_decomposition}' "${sidecar}")"
        return 1
    fi
}

FAIL=0

run_observer devices "device_paths ∋ ${DEVNODE}" \
    '(.device_paths // []) | any(.path == "/dev/csd-exerciser-dev")' || FAIL=1

run_observer privileged "privileged_decomposition devices ∋ ${DEVNODE} and cap_add non-empty (both gadget streams fired)" \
    '((.privileged_decomposition.devices // []) | any(. == "/dev/csd-exerciser-dev")) and ((.privileged_decomposition.cap_add // []) | length > 0)' || FAIL=1

if [[ ${FAIL} -eq 0 ]]; then
    echo "smoke-device: 2 passed, 0 failed"
else
    echo "smoke-device: failures above"
fi
[[ ${FAIL} -eq 0 ]]
