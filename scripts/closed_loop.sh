#!/usr/bin/env bash
# Closed-loop "meets intent" test: prove a DERIVED config actually works.
#
# Every other test proves csd's pipeline is internally consistent (the right
# transform of a given event stream). This is the only test that proves the
# OUTPUT is correct — that the config csd derives is both sufficient (the
# container still works under it) and necessary (removing it breaks the
# container). It is `csd verify`'s self-consistency idea taken all the way:
# derive -> APPLY -> re-run -> assert.
#
# Three phases against the synthetic exerciser (the deterministic gate — it
# fires a known cap stream post-attach, unlike the reference images):
#   1. DERIVE      — `csd --observe caps` observes the exerciser loop and emits
#                    the minimum cap set. An empty set here is a real attach /
#                    observe regression (hard fail), not a workload artifact.
#   2. SUFFICIENCY — re-run the exerciser (counting mode) with EXACTLY the
#                    derived caps and --cap-drop ALL; the cap-gated syscalls
#                    (chown/setuid/bind) must SUCCEED. Proves the derived config
#                    runs the workload.
#   3. NECESSITY   — re-run with --cap-drop ALL and NO caps; the same syscalls
#                    must FAIL. Proves the derived caps were actually required,
#                    not superfluous (the over-permissioning csd exists to avoid).
#
# The harness is GENERIC: phases 2-3 apply whatever phase 1 derived, so it tests
# csd's own output, not a hard-coded expectation. Hardware-free; the derive phase
# needs ig+BPF+root (like the other smokes), phases 2-3 need only docker.
#
# Requires: docker, csd (built; pass CSD=/path), jq, the pinned ig on PATH.
#
# Usage:
#   make closed-loop
#   ./scripts/closed_loop.sh
#
# Optional env:
#   CSD=/path/to/csd     binary under test (defaults to ./csd)
#   DURATION=30s         derive-phase observation window
#   ITERS=50             counting-mode iterations for phases 2-3
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
ITERS="${ITERS:-50}"
IMAGE="csd-synthetic-exerciser:0.1"

if [[ ! -x "${CSD}" ]]; then
    echo "closed-loop: csd binary not found or not executable at ${CSD}" >&2
    echo "closed-loop: run 'make build' first or pass CSD=/path/to/csd" >&2
    exit 2
fi
for tool in jq docker; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "closed-loop: ${tool} is required" >&2
        exit 2
    fi
done

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "closed-loop: building synthetic exerciser image (one-time)"
    docker build -t "${IMAGE}" testdata/synthetic >/dev/null
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
WORKLOAD="$(pwd)/testdata/synthetic/workload.sh"

# --- Phase 1: DERIVE -------------------------------------------------------
CONTAINER="csd-closed-loop-derive"
SIDECAR="${WORKDIR}/derived.json"
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if ! docker run -d --name "${CONTAINER}" "${IMAGE}" >/dev/null; then
    echo "FAIL derive: docker run failed"
    exit 1
fi
(CONTAINER="${CONTAINER}" "${WORKLOAD}" >"${WORKDIR}/workload.log" 2>&1 || true) &
WPID=$!

rc=0
"${CSD}" --observe caps --container "${CONTAINER}" --duration "${DURATION}" \
    --workload "${WORKLOAD}" --out "${SIDECAR}" >"${WORKDIR}/csd.log" 2>&1 || rc=$?
wait "${WPID}" 2>/dev/null || true
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if [[ ${rc} -ne 0 ]]; then
    case ${rc} in
        30) echo "FAIL derive: csd exited SchemaMismatch (30) — host ig differs from PinnedIGVersion" ;;
        31) echo "FAIL derive: csd exited IGMissing (31) — install the pinned ig binary on PATH" ;;
        *)  echo "FAIL derive: csd exited ${rc}; see ${WORKDIR}/csd.log" ;;
    esac
    exit 1
fi
if [[ ! -s "${SIDECAR}" ]]; then
    echo "FAIL derive: sidecar empty or missing at ${SIDECAR}"
    exit 1
fi

DERIVED="$(jq -r '[.capabilities[].name] | join(",")' "${SIDECAR}")"
if [[ -z "${DERIVED}" ]]; then
    echo "FAIL derive: csd derived an EMPTY cap set. The synthetic exerciser is the"
    echo "  deterministic gate (it fires cap events post-attach), so empty means a real"
    echo "  attach/observe regression, not a workload artifact."
    exit 1
fi
echo "INFO derive: csd derived caps = [${DERIVED}]"

CAPFLAGS=()
IFS=',' read -ra _caps <<< "${DERIVED}"
for c in "${_caps[@]}"; do
    [[ -n "${c}" ]] && CAPFLAGS+=("--cap-add" "${c}")
done

# run_counting <extra docker args...> -> echoes the single "TALLY ..." line
run_counting() {
    docker run --rm "$@" -e ITERS="${ITERS}" "${IMAGE}" 2>/dev/null | grep '^TALLY ' | head -1
}
# tally_field <tally-line> <name> -> the integer value (0 if absent)
tally_field() {
    local v
    v="$(printf '%s\n' "$1" | tr ' ' '\n' | grep "^$2=" | cut -d= -f2)"
    printf '%s' "${v:-0}"
}

FAIL=0

# --- Phase 2: SUFFICIENCY (derived caps must WORK) -------------------------
SUF="$(run_counting --cap-drop ALL "${CAPFLAGS[@]}")"
if [[ -z "${SUF}" ]]; then
    echo "FAIL sufficiency: no TALLY from the derived-caps run"
    FAIL=1
else
    s_chown="$(tally_field "${SUF}" chown)"
    s_setuid="$(tally_field "${SUF}" setuid)"
    s_bind="$(tally_field "${SUF}" bind)"
    if [[ "${s_chown}" -gt 0 && "${s_setuid}" -gt 0 && "${s_bind}" -gt 0 ]]; then
        echo "PASS sufficiency: workload succeeds under the derived caps (${SUF})"
    else
        echo "FAIL sufficiency: derived caps did NOT satisfy the workload (${SUF})"
        FAIL=1
    fi
fi

# --- Phase 3: NECESSITY (no caps must BREAK it) ---------------------------
NEC="$(run_counting --cap-drop ALL)"
if [[ -z "${NEC}" ]]; then
    echo "FAIL necessity: no TALLY from the no-caps run"
    FAIL=1
else
    n_chown="$(tally_field "${NEC}" chown)"
    n_setuid="$(tally_field "${NEC}" setuid)"
    n_bind="$(tally_field "${NEC}" bind)"
    if [[ "${n_chown}" -eq 0 && "${n_setuid}" -eq 0 && "${n_bind}" -eq 0 ]]; then
        echo "PASS necessity: dropping all caps breaks the workload (${NEC})"
    else
        echo "FAIL necessity: workload still succeeded without caps — derived caps may be superfluous (${NEC})"
        FAIL=1
    fi
fi

if [[ ${FAIL} -eq 0 ]]; then
    echo "closed-loop: derive -> apply -> verify PASSED (derived caps are sufficient AND necessary)"
else
    echo "closed-loop: failures above"
fi
[[ ${FAIL} -eq 0 ]]
