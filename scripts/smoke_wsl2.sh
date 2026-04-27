#!/usr/bin/env bash
# WSL2 smoke matrix for container-sec-derive.
#
# Runs `csd observe` against the v0.1 reference images on the local
# host and reports pass/fail per image. Designed to be run on a WSL2 +
# Docker Desktop install (PLAN.md §Platform support, v1 success
# criterion 504), but the script itself is host-agnostic — it does not
# refuse to run on native Linux. The point is to give a contributor on
# WSL2 a one-shot way to confirm `ig` + BPF + cap_capable actually
# attaches end-to-end on their kernel.
#
# Pass criteria per image:
#   postgres / caddy / tailscale: csd exits 0 AND the sidecar reports
#     events_recorded + init_window_suppressed > 0 (proves BPF attached;
#     observed cap set may be empty per docs/known-deltas.md).
#   synthetic: csd exits 0 AND derived cap set is a superset of
#     testdata/synthetic/expected.json's expected_caps_minimum (this is
#     the pipeline regression fixture; an empty observation here is a
#     real csd bug, not a workload-shape artifact).
#
# Per-image failures are printed and the script exits non-zero with a
# summary line; one failure does not abort the rest of the matrix.
#
# Requires: docker, csd (built; pass CSD=/path to override), jq, the
# vendored ig binary on PATH (the IG version pin is enforced inside csd
# and aborts with ExitSchemaMismatch on mismatch — that is itself a
# legitimate smoke result and the script reports it as such).
#
# Usage:
#   make smoke-wsl2
#   # or directly:
#   ./scripts/smoke_wsl2.sh
#
# Optional env:
#   CSD=/path/to/csd       binary under test (defaults to ./csd)
#   DURATION=30s           per-image observation window
#   ONLY=postgres,caddy    comma-separated subset of images to run
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
ONLY="${ONLY:-postgres,caddy,tailscale,synthetic}"

if [[ ! -x "${CSD}" ]]; then
    echo "smoke-wsl2: csd binary not found or not executable at ${CSD}" >&2
    echo "smoke-wsl2: run 'make build' first or pass CSD=/path/to/csd" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-wsl2: jq is required" >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "smoke-wsl2: docker is required" >&2
    exit 2
fi

if grep -qiE 'microsoft|wsl2' /proc/version 2>/dev/null; then
    echo "smoke-wsl2: WSL2 host detected ($(uname -r))"
else
    echo "smoke-wsl2: non-WSL2 host ($(uname -r)); running anyway as a portability check"
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

# run_one <image_label> <docker_image_ref> <run_args> <workload_script> <pass_predicate>
#   pass_predicate is one of: "any-events" | "synthetic-superset"
run_one() {
    local label="$1" image_ref="$2" run_args="$3" workload="$4" predicate="$5"
    local container="csd-smoke-${label}"
    local sidecar="${WORKDIR}/${label}.json"
    local csd_log="${WORKDIR}/${label}-csd.log"
    local rc=0

    docker rm -f "${container}" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086 # word-splitting on run_args is intentional
    if ! docker run -d --name "${container}" ${run_args} "${image_ref}" >/dev/null; then
        echo "FAIL ${label}: docker run failed"
        return 1
    fi

    # Kick the workload in the background; csd observes for DURATION.
    # The workload is responsible for waiting until the container is
    # ready (each reference workload polls). If the workload errors we
    # still want the observation to complete — fall back to no-op.
    (PGCONTAINER="${container}" CADDY_CONTAINER="${container}" \
     TAILSCALE_CONTAINER="${container}" SYN_CONTAINER="${container}" \
     "${workload}" >"${WORKDIR}/${label}-workload.log" 2>&1 || true) &
    local wpid=$!

    if ! "${CSD}" --container "${container}" --duration "${DURATION}" \
            --workload "${workload}" --out "${sidecar}" \
            >"${csd_log}" 2>&1; then
        rc=$?
        wait "${wpid}" 2>/dev/null || true
        docker rm -f "${container}" >/dev/null 2>&1 || true
        if [[ ${rc} -eq 30 ]]; then
            echo "FAIL ${label}: csd exited SchemaMismatch (30) — host ig version differs from PinnedIGVersion"
        elif [[ ${rc} -eq 31 ]]; then
            echo "FAIL ${label}: csd exited IGMissing (31) — install the pinned ig binary on PATH"
        else
            echo "FAIL ${label}: csd exited ${rc}; see ${csd_log}"
        fi
        return 1
    fi
    wait "${wpid}" 2>/dev/null || true
    docker rm -f "${container}" >/dev/null 2>&1 || true

    if [[ ! -s "${sidecar}" ]]; then
        echo "FAIL ${label}: sidecar empty or missing at ${sidecar}"
        return 1
    fi

    case "${predicate}" in
        any-events)
            local recorded suppressed
            recorded=$(jq -r '.trace_health.events_recorded // 0' "${sidecar}")
            suppressed=$(jq -r '.target.init_window_suppressed // 0' "${sidecar}")
            if (( recorded + suppressed == 0 )); then
                echo "FAIL ${label}: BPF did not attach (recorded=${recorded}, init_window_suppressed=${suppressed}); check kernel BTF / WSL2 version"
                return 1
            fi
            local caps
            caps=$(jq -r '.target.observed_caps | join(",")' "${sidecar}")
            echo "PASS ${label}: events=${recorded}, init_suppressed=${suppressed}, observed_caps=[${caps}]"
            ;;
        synthetic-superset)
            local missing
            missing=$(jq -r --slurpfile e testdata/synthetic/expected.json \
                '($e[0].expected_caps_minimum - .target.observed_caps) | join(",")' \
                "${sidecar}")
            if [[ -n "${missing}" ]]; then
                echo "FAIL ${label}: missing required caps [${missing}]; observed_caps=$(jq -r '.target.observed_caps | join(",")' "${sidecar}")"
                return 1
            fi
            echo "PASS ${label}: superset check satisfied; observed_caps=$(jq -r '.target.observed_caps | join(",")' "${sidecar}")"
            ;;
        *)
            echo "FAIL ${label}: unknown predicate ${predicate}"
            return 1
            ;;
    esac
}

PASS=0
FAIL=0
SKIP=0

want() {
    [[ ",${ONLY}," == *",$1,"* ]]
}

# Each block below mirrors the runtime args from the
# make ground-truth-<image> targets so the smoke matches what bisection
# already validated against.
if want postgres; then
    if run_one postgres "postgres:16" "-e POSTGRES_PASSWORD=postgres" \
            "$(pwd)/testdata/postgres/workload.sh" any-events; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
else
    SKIP=$((SKIP+1))
fi

if want caddy; then
    if run_one caddy "caddy:2" \
            "-e CADDY_ADMIN=0.0.0.0:2019 -p 127.0.0.1:18080:80 -p 127.0.0.1:12019:2019" \
            "$(pwd)/testdata/caddy/workload.sh" any-events; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
else
    SKIP=$((SKIP+1))
fi

if want tailscale; then
    if run_one tailscale "tailscale/tailscale:stable" "-e TS_USERSPACE=true" \
            "$(pwd)/testdata/tailscale/workload.sh" any-events; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
else
    SKIP=$((SKIP+1))
fi

if want synthetic; then
    if ! docker image inspect csd-synthetic-exerciser:0.1 >/dev/null 2>&1; then
        echo "smoke-wsl2: building synthetic exerciser image (one-time)"
        docker build -t csd-synthetic-exerciser:0.1 testdata/synthetic >/dev/null
    fi
    if run_one synthetic "csd-synthetic-exerciser:0.1" \
            "--sysctl net.ipv4.ip_unprivileged_port_start=1024" \
            "$(pwd)/testdata/synthetic/workload.sh" synthetic-superset; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
else
    SKIP=$((SKIP+1))
fi

echo "smoke-wsl2: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
[[ ${FAIL} -eq 0 ]]
