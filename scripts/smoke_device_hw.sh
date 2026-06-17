#!/usr/bin/env bash
# Hardware-ful device smoke for `--observe devices` — the real-hardware
# counterpart to scripts/smoke_device.sh (which is deliberately hardware-free,
# mapping /dev/null). This one validates that csd detects opens of REAL
# non-default device nodes at their real paths, which only a host with that
# hardware can exercise.
#
# It is host-adaptive: it tries a candidate set of real device nodes and tests
# each one that is PRESENT on the host, skipping the rest with an INFO line. So
# it does something useful whether the runner is a GPU desktop (/dev/dri), a
# virtualization host (/dev/kvm), or a plain server (/dev/net/tun, /dev/fuse).
# Intended for the self-hosted runner (see docs/self-hosted-runner.md); it is NOT
# part of the per-PR gate because the available hardware varies by host.
#
# For each present device DEV: run a stock container with `--device DEV:DEV`
# whose workload repeatedly OPENS DEV (an open, not a read — reads on /dev/net/tun
# block; the open is what trace_open records), observe with `--observe devices`,
# and assert `device_paths` contains DEV.
#
# Requires: docker, csd (built; pass CSD=/path), jq, the pinned ig on PATH, root.
#
# Usage:
#   make build && sudo env CSD=$PWD/csd ./scripts/smoke_device_hw.sh
#
# Optional env:
#   CSD=/path/to/csd     binary under test (defaults to ./csd)
#   DURATION=30s         observation window
#   DEVICES="a b c"      override the candidate device list
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
OPENER_IMAGE="${OPENER_IMAGE:-alpine:3.24}"
# Candidate real device nodes, most-commonly-present first. Render node before
# the primary DRM node (renderD128 opens without DRM-master). Override via DEVICES.
CANDIDATES="${DEVICES:-/dev/net/tun /dev/kvm /dev/fuse /dev/dri/renderD128 /dev/dri/card0 /dev/snd/timer}"

if [[ ! -x "${CSD}" ]]; then
    echo "smoke-device-hw: csd binary not found or not executable at ${CSD}" >&2
    echo "smoke-device-hw: run 'make build' first or pass CSD=/path/to/csd" >&2
    exit 2
fi
for tool in jq docker; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "smoke-device-hw: ${tool} is required" >&2; exit 2; }
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

# present_devices filters CANDIDATES to the nodes that actually exist on the host.
present=()
for d in ${CANDIDATES}; do
    [[ -e "${d}" ]] && present+=("${d}")
done
if [[ ${#present[@]} -eq 0 ]]; then
    echo "INFO smoke-device-hw: none of the candidate device nodes are present on this host (${CANDIDATES})"
    echo "INFO smoke-device-hw: nothing to test here — run on a host with real /dev nodes (GPU/tun/kvm/...)"
    echo "smoke-device-hw: 0 tested, 0 failed (no hardware present)"
    exit 0
fi
echo "INFO smoke-device-hw: testing present device(s): ${present[*]}"

# test_device <devpath> -> PASS/FAIL; asserts csd records an open of devpath.
test_device() {
    local dev="$1"
    local name="csd-hwdev-smoke-$(echo "${dev}" | tr '/' '-')"
    local sidecar="${WORKDIR}/$(basename "${dev}").json"
    local rc=0

    docker rm -f "${name}" >/dev/null 2>&1 || true
    # Open the device every cycle WITHOUT reading it (`: <dev` opens for the no-op
    # builtin then closes; reads on tun/snd would block). The open is the
    # trace_open event csd attributes.
    if ! docker run -d --name "${name}" --device "${dev}:${dev}" "${OPENER_IMAGE}" \
            sh -c 'while true; do ( : < '"${dev}"' ) 2>/dev/null; sleep 1; done' >/dev/null; then
        echo "FAIL ${dev}: docker run failed (device not grantable here?)"
        return 1
    fi

    if ! "${CSD}" --observe devices --container "${name}" --duration "${DURATION}" \
            --out "${sidecar}" >"${WORKDIR}/$(basename "${dev}")-csd.log" 2>&1; then
        rc=$?
        docker rm -f "${name}" >/dev/null 2>&1 || true
        case ${rc} in
            30) echo "FAIL ${dev}: csd exited SchemaMismatch (30) — host ig differs from PinnedIGVersion" ;;
            31) echo "FAIL ${dev}: csd exited IGMissing (31) — install the pinned ig on PATH" ;;
            *)  echo "FAIL ${dev}: csd exited ${rc}" ;;
        esac
        return 1
    fi
    docker rm -f "${name}" >/dev/null 2>&1 || true

    if jq -e --arg d "${dev}" '(.device_paths // []) | any(.path == $d)' "${sidecar}" >/dev/null; then
        local recorded
        recorded=$(jq -r '.trace_health.events_recorded // 0' "${sidecar}")
        echo "PASS ${dev}: device_paths contains it (events_recorded=${recorded})"
        return 0
    fi
    echo "FAIL ${dev}: not in device_paths; got $(jq -c '[(.device_paths//[])[].path]' "${sidecar}")"
    return 1
}

PASS=0
FAIL=0
for dev in "${present[@]}"; do
    if test_device "${dev}"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
done

echo "smoke-device-hw: ${PASS} passed, ${FAIL} failed (of ${#present[@]} present)"
[[ ${FAIL} -eq 0 ]]
