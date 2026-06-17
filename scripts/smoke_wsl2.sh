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
#   postgres / caddy / tailscale (informational): reported but never fail
#     the build. All three can legitimately observe ZERO post-attach cap
#     events — their privileged ops happen at/around container init
#     (gosu user-switch, caddy bind(:80)) and their workloads fire no
#     further capable() checks, per docs/known-deltas.md. Zero events is
#     indistinguishable from non-attach by event count, so none of them is
#     a reliable attach gate (postgres was observed firing 748 events one
#     run and 0 the next on the same runner).
#   synthetic (hard gate): csd exits 0 AND derived cap set is a superset
#     of testdata/synthetic/expected.json's expected_caps_minimum. This is
#     the sole deterministic gate: the fixture fires a known cap set
#     continuously post-attach, so it reliably proves BOTH that BPF
#     attached and that csd's pipeline records what it should. An empty
#     observation here is a real csd bug, not a workload-shape artifact.
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
#   pass_predicate is one of:
#     "any-events"         hard gate: BPF must have attached (events recorded).
#                          (Retained for callers that want it; none of the
#                          reference images use it — see below.)
#     "any-events-info"    informational: report event counts but never fail the
#                          build. Used for postgres/caddy/tailscale, whose
#                          privileged ops happen at/around init (gosu user-switch,
#                          caddy bind(:80)) and whose workloads fire no further
#                          post-attach capable() checks — a legitimate zero-events
#                          result per docs/known-deltas.md, indistinguishable from
#                          non-attach by event count alone, so none of them is a
#                          reliable gate. synthetic is the sole hard gate.
#     "synthetic-superset" hard gate: derived caps ⊇ expected_caps_minimum.
#
# Derived caps live at top-level .capabilities[].name (NOT .target.observed_caps,
# which is not a schema field); reads are null-guarded with (.capabilities // []).
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

    # Capture csd's REAL exit code. `if ! "${CSD}" ...; then rc=$?` records the
    # status of the `!` negation (always 0), NOT csd's — masking 30/31 and the
    # artifact-with-caveat codes and mislabelling failures "csd exited 0".
    "${CSD}" --container "${container}" --duration "${DURATION}" \
        --workload "${workload}" --out "${sidecar}" >"${csd_log}" 2>&1 && rc=0 || rc=$?
    wait "${wpid}" 2>/dev/null || true
    docker rm -f "${container}" >/dev/null 2>&1 || true
    if [[ ${rc} -ne 0 ]]; then
        # 30/31 are environment-wide (wrong/missing ig) — fatal for every image.
        if [[ ${rc} -eq 30 ]]; then
            echo "FAIL ${label}: csd exited SchemaMismatch (30) — host ig version differs from PinnedIGVersion"
            return 1
        fi
        if [[ ${rc} -eq 31 ]]; then
            echo "FAIL ${label}: csd exited IGMissing (31) — install the pinned ig binary on PATH"
            return 1
        fi
        # Other codes are artifact-with-caveat (20 target-exited-early, 21
        # drop-rate). Informational reference images (predicate *-info) tolerate
        # them — their post-attach behavior is timing-dependent (docs/known-deltas.md);
        # the synthetic hard gate does not.
        if [[ "${predicate}" == *-info ]]; then
            echo "INFO ${label}: csd exited ${rc} (artifact-with-caveat); informational image, not a failure (see ${csd_log})"
            return 0
        fi
        echo "FAIL ${label}: csd exited ${rc}; see ${csd_log}"
        return 1
    fi

    if [[ ! -s "${sidecar}" ]]; then
        echo "FAIL ${label}: sidecar empty or missing at ${sidecar}"
        return 1
    fi

    local recorded suppressed caps
    recorded=$(jq -r '.trace_health.events_recorded // 0' "${sidecar}")
    suppressed=$(jq -r '.target.init_window_suppressed // 0' "${sidecar}")
    caps=$(jq -r '[(.capabilities // [])[].name] | join(",")' "${sidecar}")

    case "${predicate}" in
        any-events)
            if (( recorded + suppressed == 0 )); then
                echo "FAIL ${label}: BPF did not attach (recorded=${recorded}, init_window_suppressed=${suppressed}); check kernel BTF / WSL2 version"
                return 1
            fi
            echo "PASS ${label}: events=${recorded}, init_suppressed=${suppressed}, observed_caps=[${caps}]"
            ;;
        any-events-info)
            # Informational only — never fails the build. Zero events here is a
            # documented, expected outcome (see the predicate comment above and
            # docs/known-deltas.md), not a csd failure. The synthetic fixture is
            # the sole hard gate (both attach proof and pipeline regression).
            if (( recorded + suppressed == 0 )); then
                echo "INFO ${label}: zero events post-attach — expected per docs/known-deltas.md (pre-attach/silent workload), not a failure"
            else
                echo "PASS ${label}: events=${recorded}, init_suppressed=${suppressed}, observed_caps=[${caps}] (informational)"
            fi
            ;;
        synthetic-superset)
            local missing
            missing=$(jq -r --slurpfile e testdata/synthetic/expected.json \
                '($e[0].expected_caps_minimum - [(.capabilities // [])[].name]) | join(",")' \
                "${sidecar}")
            if [[ -n "${missing}" ]]; then
                echo "FAIL ${label}: missing required caps [${missing}]; observed_caps=[${caps}]"
                return 1
            fi
            echo "PASS ${label}: superset check satisfied; observed_caps=[${caps}]"
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
            "$(pwd)/testdata/postgres/workload.sh" any-events-info; then
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
            "$(pwd)/testdata/caddy/workload.sh" any-events-info; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
else
    SKIP=$((SKIP+1))
fi

if want tailscale; then
    if run_one tailscale "tailscale/tailscale:stable" "-e TS_USERSPACE=true" \
            "$(pwd)/testdata/tailscale/workload.sh" any-events-info; then
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
