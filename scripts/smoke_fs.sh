#!/usr/bin/env bash
# Live-BPF smoke matrix for the v0.2 read-only-filesystem observer.
#
# The fs analog of scripts/smoke_wsl2.sh: runs `csd --observe fs` against the
# reference images on the local host and reports pass/fail per image. It is the
# first end-to-end exercise of the trace_open signal path (ig run trace_open
# --paths → write-intent filter → mount correlation → recommendation), which
# the fixture-replay unit tests cannot cover.
#
# Pass criteria per image:
#   postgres / caddy / tailscale (informational): reported, never fail the
#     build. Like the cap smoke, their writes happen largely at container /
#     entrypoint init (before ig attaches), so a sparse or empty post-attach
#     write set is a legitimate workload-shape outcome (docs/known-deltas.md),
#     not a csd bug — and is indistinguishable from non-attach by count alone.
#   synthetic (hard gate): csd exits 0 AND the derived writable_paths include
#     /csd-exerciser-target. The exerciser opens that path O_CREAT|O_WRONLY|
#     O_TRUNC every cycle (testdata/synthetic/exerciser.c), so trace_open fires
#     a write-intent open continuously post-attach. This is the sole
#     deterministic fs gate: it proves BOTH that the trace_open gadget attached
#     and that csd's fs pipeline records what it should. An empty observation
#     here is a real csd bug, not a workload-shape artifact.
#
# Per-image failures are printed and the script exits non-zero with a summary
# line; one failure does not abort the rest of the matrix.
#
# Requires: docker, csd (built; pass CSD=/path to override), jq, the vendored
# ig binary on PATH (the IG version pin is enforced inside csd and aborts with
# ExitSchemaMismatch on mismatch — itself a legitimate smoke result).
#
# Usage:
#   make smoke-fs
#   ./scripts/smoke_fs.sh
#
# Optional env:
#   CSD=/path/to/csd       binary under test (defaults to ./csd)
#   DURATION=30s           per-image observation window
#   ONLY=postgres,synthetic   comma-separated subset of images to run
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
ONLY="${ONLY:-postgres,caddy,tailscale,synthetic}"

if [[ ! -x "${CSD}" ]]; then
    echo "smoke-fs: csd binary not found or not executable at ${CSD}" >&2
    echo "smoke-fs: run 'make build' first or pass CSD=/path/to/csd" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-fs: jq is required" >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "smoke-fs: docker is required" >&2
    exit 2
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

# run_one <label> <image_ref> <run_args> <workload> <predicate>
#   predicate: "any-writes-info"  informational; never fails the build.
#              "synthetic-fs"      hard gate: writable_paths ∋ the expected path.
run_one() {
    local label="$1" image_ref="$2" run_args="$3" workload="$4" predicate="$5"
    local container="csd-fs-smoke-${label}"
    local sidecar="${WORKDIR}/${label}.json"
    local csd_log="${WORKDIR}/${label}-csd.log"
    local rc=0

    docker rm -f "${container}" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086 # word-splitting on run_args is intentional
    if ! docker run -d --name "${container}" ${run_args} "${image_ref}" >/dev/null; then
        echo "FAIL ${label}: docker run failed"
        return 1
    fi

    (PGCONTAINER="${container}" CADDY_CONTAINER="${container}" \
     TAILSCALE_CONTAINER="${container}" SYN_CONTAINER="${container}" \
     "${workload}" >"${WORKDIR}/${label}-workload.log" 2>&1 || true) &
    local wpid=$!

    # Capture csd's REAL exit code. `if ! "${CSD}" ...; then rc=$?` records the
    # status of the `!` negation (always 0), NOT csd's — masking 30/31 and the
    # artifact-with-caveat codes and mislabelling failures "csd exited 0".
    "${CSD}" --observe fs --container "${container}" --duration "${DURATION}" \
        --out "${sidecar}" >"${csd_log}" 2>&1 && rc=0 || rc=$?
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

    local recorded npaths readonly tmpfs
    recorded=$(jq -r '.trace_health.events_recorded // 0' "${sidecar}")
    npaths=$(jq -r '(.writable_paths // []) | length' "${sidecar}")
    readonly=$(jq -r '.fs_recommendation.read_only // false' "${sidecar}")
    tmpfs=$(jq -r '[(.fs_recommendation.tmpfs_paths // [])[]] | join(",")' "${sidecar}")

    case "${predicate}" in
        any-writes-info)
            if (( recorded == 0 )); then
                echo "INFO ${label}: zero write events post-attach — expected per docs/known-deltas.md (pre-attach/silent workload), not a failure"
            else
                echo "PASS ${label}: write_events=${recorded}, writable_paths=${npaths}, read_only=${readonly}, tmpfs=[${tmpfs}] (informational)"
            fi
            ;;
        synthetic-fs)
            if jq -e '(.writable_paths // []) | any(.path == "/csd-exerciser-target")' "${sidecar}" >/dev/null; then
                echo "PASS ${label}: observed /csd-exerciser-target (write_events=${recorded}, read_only=${readonly}, tmpfs=[${tmpfs}])"
            else
                local seen
                seen=$(jq -r '[(.writable_paths // [])[].path] | join(",")' "${sidecar}")
                echo "FAIL ${label}: expected writable path /csd-exerciser-target not observed; writable_paths=[${seen}]"
                return 1
            fi
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
want() { [[ ",${ONLY}," == *",$1,"* ]]; }

# Run args mirror scripts/smoke_wsl2.sh so the fs smoke exercises the same
# container shapes the cap smoke and bisection already validated.
if want postgres; then
    if run_one postgres "postgres:16" "-e POSTGRES_PASSWORD=postgres" \
            "$(pwd)/testdata/postgres/workload.sh" any-writes-info; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
else SKIP=$((SKIP+1)); fi

if want caddy; then
    if run_one caddy "caddy:2" \
            "-e CADDY_ADMIN=0.0.0.0:2019 -p 127.0.0.1:18080:80 -p 127.0.0.1:12019:2019" \
            "$(pwd)/testdata/caddy/workload.sh" any-writes-info; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
else SKIP=$((SKIP+1)); fi

if want tailscale; then
    if run_one tailscale "tailscale/tailscale:stable" "-e TS_USERSPACE=true" \
            "$(pwd)/testdata/tailscale/workload.sh" any-writes-info; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
else SKIP=$((SKIP+1)); fi

if want synthetic; then
    if ! docker image inspect csd-synthetic-exerciser:0.1 >/dev/null 2>&1; then
        echo "smoke-fs: building synthetic exerciser image (one-time)"
        docker build -t csd-synthetic-exerciser:0.1 testdata/synthetic >/dev/null
    fi
    # No --sysctl needed for the fs observer: the write fires regardless.
    if run_one synthetic "csd-synthetic-exerciser:0.1" "" \
            "$(pwd)/testdata/synthetic/workload.sh" synthetic-fs; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
else SKIP=$((SKIP+1)); fi

echo "smoke-fs: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
[[ ${FAIL} -eq 0 ]]
