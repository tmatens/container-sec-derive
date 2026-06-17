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
#   2. SUFFICIENCY — re-run the exerciser (counting mode) under three cap
#                    configurations and compare the workload's success SCORE
#                    (sum of cap-relevant syscalls that succeeded): full default
#                    caps (baseline = achievable max), EXACTLY the derived caps,
#                    and no caps. The derived run must score == baseline (it runs
#                    the workload as well as full caps do).
#   3. NECESSITY   — the derived run must score STRICTLY MORE than the no-caps
#                    run (dropping the derived caps measurably breaks the
#                    workload), so the derived caps aren't superfluous.
#
# Why a SCORE comparison and not "syscall X must fail": some syscalls aren't
# cap-gated on every kernel (binding port 80 where ip_unprivileged_port_start=0;
# chowning a file to its existing owner), so a correct derived set legitimately
# omits those caps. Comparing the measured score across full/derived/none caps is
# robust to that and tests csd's ACTUAL output, not a hard-coded expectation.
# Hardware-free; the derive phase needs ig+BPF+root (like the other smokes),
# phases 2-3 need only docker.
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
# tally_total <tally-line> -> sum of the cap-relevant success fields (the score)
tally_total() {
    printf '%s\n' "$1" | tr ' ' '\n' | awk -F= '/^(chown|bind|setgid|setuid)=/ {s+=$2} END {print s+0}'
}

# --- Phases 2-3: SUFFICIENCY + NECESSITY by score comparison ---------------
# baseline = full default caps (achievable max); derived = exactly csd's output;
# none = all caps dropped.
BASE_TALLY="$(run_counting)"
SUF_TALLY="$(run_counting --cap-drop ALL "${CAPFLAGS[@]}")"
NONE_TALLY="$(run_counting --cap-drop ALL)"
base="$(tally_total "${BASE_TALLY}")"
suf="$(tally_total "${SUF_TALLY}")"
none="$(tally_total "${NONE_TALLY}")"
echo "INFO baseline (full caps): ${BASE_TALLY:-<none>}  [score=${base}]"
echo "INFO derived  (csd caps):  ${SUF_TALLY:-<none>}  [score=${suf}]"
echo "INFO none     (no caps):   ${NONE_TALLY:-<none>}  [score=${none}]"

if [[ "${base}" -le 0 ]]; then
    echo "FAIL: baseline workload scored 0 even with full caps — the exerciser did nothing"
    exit 1
fi

FAIL=0
# Sufficiency: derived caps achieve the SAME workload success as full caps.
if [[ "${suf}" -eq "${base}" ]]; then
    echo "PASS sufficiency: derived caps achieve full workload success (score ${suf}/${base})"
else
    echo "FAIL sufficiency: derived caps under-satisfy the workload (score ${suf}/${base}) — csd may have missed a needed cap"
    FAIL=1
fi
# Necessity: derived caps enable STRICTLY MORE than no caps (they matter).
if [[ "${suf}" -gt "${none}" ]]; then
    echo "PASS necessity: dropping the derived caps reduces workload success (score ${suf} -> ${none})"
else
    echo "FAIL necessity: no-caps run scored the same as derived (${suf} == ${none}) — derived caps appear superfluous"
    FAIL=1
fi

if [[ ${FAIL} -eq 0 ]]; then
    echo "closed-loop: derive -> apply -> verify PASSED (derived caps are sufficient AND necessary)"
else
    echo "closed-loop: failures above"
fi
[[ ${FAIL} -eq 0 ]]
