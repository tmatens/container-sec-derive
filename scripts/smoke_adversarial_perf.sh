#!/usr/bin/env bash
# Adversarial capadd smoke (#349 scenario 6): csd SOUNDLY narrows SYS_ADMIN when the
# observed syscall proves a finer capability suffices. SYS_ADMIN is the kitchen-sink
# cap, but observed ONLY via perf_event_open it is safely replaceable by CAP_PERFMON
# — the capadd KB maps perf_event_open->PERFMON. This is the POSITIVE complement to
# scenario 5's conservative negative control (DAC_OVERRIDE stays un-narrowed): csd
# narrows when the syscall proves it, refuses when it can't.
#
# The synthetic exerciser (CSD_EXERCISE_PERF=1) does a system-wide perf_event_open
# every cycle — which needs CAP_PERFMON/CAP_SYS_ADMIN. We grant CAP_SYS_ADMIN (so the
# check comes back capable=true keyed to SYS_ADMIN) and validate it: the finding
# must be used=true, observed via perf_event_open, with finer_caps == [PERFMON].
#
# NOTE (live-signal caveat): exactly which cap a system-wide perf_event_open reports
# via cap_capable is kernel-dependent (perfmon_capable checks CAP_PERFMON then
# CAP_SYS_ADMIN). If the runner's kernel reports the check under a different cap, the
# gate prints the RAW SYS_ADMIN/PERFMON findings so the true shape is visible in one
# run (this smoke is authored against the pinned-ig fixture shape: SYS_ADMIN +
# syscall=perf_event_open).
#
# Requires: docker, csd (built; pass CSD=/path), jq, the pinned ig on PATH, and a
# host that permits CAP_SYS_ADMIN + perf_event_open (the self-hosted BPF runner).
#   make smoke-adversarial-perf   |   ./scripts/smoke_adversarial_perf.sh
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
IMAGE="csd-synthetic-exerciser:0.1"
CONTAINER="csd-adv-perf-smoke"

[[ -x "${CSD}" ]] || { echo "smoke-adversarial-perf: csd not found/executable at ${CSD}" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-adversarial-perf: jq required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "smoke-adversarial-perf: docker required" >&2; exit 2; }

# ALWAYS rebuild — do NOT skip-if-exists. The shared csd-synthetic-exerciser:0.1
# tag persists across jobs on a non-ephemeral self-hosted runner, so a skip-if-
# exists guard would run this test against a STALE image lacking the CSD_EXERCISE_PERF
# probe (the same latent bug scenario 5 hit). The exerciser source changed → rebuild.
echo "smoke-adversarial-perf: (re)building synthetic exerciser image from current source"
docker build -t "${IMAGE}" testdata/synthetic >/dev/null || { echo "FAIL: image build" >&2; exit 1; }

WORKDIR="$(mktemp -d)"; trap 'rm -rf "${WORKDIR}"' EXIT
WORKLOAD="$(pwd)/testdata/synthetic/workload.sh"
SIDECAR="${WORKDIR}/perf.json"; LOG="${WORKDIR}/perf-csd.log"

docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
# CAP_SYS_ADMIN is NOT a docker default — grant it so the system-wide
# perf_event_open succeeds and the check is recorded capable=true under SYS_ADMIN.
if ! docker run -d --name "${CONTAINER}" --cap-add SYS_ADMIN -e CSD_EXERCISE_PERF=1 "${IMAGE}" >/dev/null; then
    echo "FAIL adversarial-perf: docker run failed"; exit 1
fi

(CONTAINER="${CONTAINER}" "${WORKLOAD}" >"${WORKDIR}/workload.log" 2>&1 || true) &
WPID=$!
rc=0
"${CSD}" --observe capadd --cap-add SYS_ADMIN --container "${CONTAINER}" \
    --duration "${DURATION}" --workload "${WORKLOAD}" --out "${SIDECAR}" >"${LOG}" 2>&1 && rc=0 || rc=$?
wait "${WPID}" 2>/dev/null || true
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if [[ ${rc} -ne 0 ]]; then
    case ${rc} in
        30) echo "FAIL adversarial-perf: SchemaMismatch (30) — host ig != PinnedIGVersion" ;;
        31) echo "FAIL adversarial-perf: IGMissing (31) — install the pinned ig" ;;
        *)  echo "FAIL adversarial-perf: csd exited ${rc}; see ${LOG}" ;;
    esac
    exit 1
fi
[[ -s "${SIDECAR}" ]] || { echo "FAIL adversarial-perf: sidecar empty at ${SIDECAR}"; exit 1; }

dump_findings() {
    echo "  --- SYS_ADMIN/PERFMON findings (raw) ---"
    jq -c '(.capadd_validation.findings // [])[] | select(.cap=="SYS_ADMIN" or .cap=="PERFMON")' "${SIDECAR}" || true
    echo "  --- all observed caps ---"
    jq -c '[(.capadd_validation.findings // [])[].cap]' "${SIDECAR}" || true
}

USED='(.capadd_validation.findings // []) | any(.cap=="SYS_ADMIN" and .used==true)'
VIA_PERF='(.capadd_validation.findings // []) | any(.cap=="SYS_ADMIN" and ((.syscalls // [])[].name | test("perf_event_open")))'
FINER='(.capadd_validation.findings // []) | any(.cap=="SYS_ADMIN" and ((.finer_caps // []) | index("PERFMON")))'

if ! jq -e "${USED}" "${SIDECAR}" >/dev/null; then
    echo "FAIL adversarial-perf: SYS_ADMIN not observed used (perf_event_open didn't fire capable=true under SYS_ADMIN on this kernel)"
    dump_findings; exit 1
fi
if ! jq -e "${VIA_PERF}" "${SIDECAR}" >/dev/null; then
    echo "FAIL adversarial-perf: SYS_ADMIN used but not via perf_event_open"
    dump_findings; exit 1
fi
if ! jq -e "${FINER}" "${SIDECAR}" >/dev/null; then
    echo "FAIL adversarial-perf: SYS_ADMIN via perf_event_open NOT narrowed to PERFMON (finer_caps missing PERFMON)"
    dump_findings; exit 1
fi

echo "PASS adversarial-perf: SYS_ADMIN used via perf_event_open, soundly narrowed to PERFMON (finer_caps ∋ PERFMON)"
echo "smoke-adversarial-perf: 1 passed, 0 failed"
