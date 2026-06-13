#!/usr/bin/env bash
# kretprobe miss-rate (capture-deficit) measurement for container-sec-derive.
#
# Closes the v1 Correctness criterion: "kretprobe miss rate on the
# reference-image workloads must be < 0.1% (measured, not assumed)."
#
# Method. The synthetic exerciser (testdata/synthetic) in counting mode
# (ITERS>0) issues an EXACT, self-reported number of cap-invoking syscalls
# from a stable non-runc comm, after a warmup that lets csd attach first.
# Each SUCCESSFUL syscall means the kernel invoked capable() for that cap
# and it was held -> exactly one capable=true event. csd records a per-cap
# event_count in the sidecar. The capture deficit
#
#     deficit = (issued - recorded) / issued
#
# is an UPPER BOUND on the kretprobe miss rate: it also folds in ringbuf
# drops (asserted ~0 below) and any userspace filtering (the counted ops
# use comm "exerciser" and run well past the 500ms init window, so neither
# the runc-comm nor the time-window filter touches them). With drops ~0
# and no filtering, the residual is dominated by kprobe/kretprobe pairing
# loss — which is what the criterion is about.
#
# 1:1 syscall -> cap mapping used as ground truth:
#   CHOWN            <- chown() to a changed owner   (2 per cycle)
#   NET_BIND_SERVICE <- bind() to :80                (1 per cycle)
#   SETGID           <- child setgid(65534)          (1 per cycle)
#   SETUID           <- child setuid(65534)          (1 per cycle)
# A per-cap SURPLUS (recorded > issued) means the mapping is not 1:1 for
# that cap on this kernel; it is reported but does not count as a miss.
#
# Requires: docker, ig (pinned), a built csd, jq. Run as root (BPF).
# Output lines are prefixed MISSRATE / PASS / FAIL so a CI report step can
# allowlist them without leaking anything else.
#
# Env:
#   CSD=./csd            binary under test
#   ITERS=20000          counted cycles (CHOWN events = 2*ITERS, others = ITERS)
#   WARMUP_MS=8000       pre-count sleep so csd attaches before any counted op
#   DURATION=180s        csd observation window (must exceed warmup + run)
#   THRESHOLD=0.1        max allowed deficit %, per cap and overall
#   IMG=csd-synthetic-exerciser:0.1
set -uo pipefail

CSD="${CSD:-./csd}"
ITERS="${ITERS:-20000}"
WARMUP_MS="${WARMUP_MS:-12000}"
# CYCLE_US throttles the exerciser so the cap-event rate stays under the BPF
# ringbuf drain rate (a tight loop overflows it -> csd exit 21, drops >=10%,
# and the deficit would measure ringbuf loss, not kretprobe misses).
CYCLE_US="${CYCLE_US:-2000}"
DURATION="${DURATION:-240s}"
THRESHOLD="${THRESHOLD:-0.1}"
IMG="${IMG:-csd-synthetic-exerciser:0.1}"
CONTAINER="csd-missrate"

if [[ ! -x "${CSD}" ]]; then echo "missrate: csd not found/executable at ${CSD}" >&2; exit 2; fi
for t in docker jq; do command -v "$t" >/dev/null 2>&1 || { echo "missrate: $t is required" >&2; exit 2; }; done

# The synthetic image carries the counting-mode exerciser; build if absent.
if ! docker image inspect "${IMG}" >/dev/null 2>&1; then
    echo "missrate: building ${IMG}"
    docker build -t "${IMG}" testdata/synthetic >/dev/null || { echo "missrate: image build failed" >&2; exit 2; }
fi

# Pre-pull the trace_capabilities gadget so csd's attach during the warmup
# is not racing a cold ghcr pull (which would miss early counted events and
# inflate the deficit). The ref tracks PinnedIGVersion, same source as the
# image build. Best-effort: if it fails, the warmup is the fallback.
if command -v ig >/dev/null 2>&1; then
    ig_ver="$(awk -F'"' '/^[[:space:]]+PinnedIGVersion[[:space:]]+=/ {print $2; exit}' main.go 2>/dev/null || true)"
    if [[ -n "${ig_ver}" ]]; then
        gadget="ghcr.io/inspektor-gadget/gadget/trace_capabilities:${ig_ver}"
        echo "missrate: pre-pulling ${gadget}"
        ig image pull "${gadget}" >/dev/null 2>&1 || echo "missrate: gadget pre-pull skipped (relying on ${WARMUP_MS}ms warmup)"
    fi
fi

WORKDIR="$(mktemp -d)"
trap 'docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true; rm -rf "${WORKDIR}"' EXIT
SIDE="${WORKDIR}/sidecar.json"

docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if ! docker run -d --name "${CONTAINER}" \
        --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
        -e ITERS="${ITERS}" -e WARMUP_MS="${WARMUP_MS}" -e CYCLE_US="${CYCLE_US}" \
        "${IMG}" >/dev/null; then
    echo "FAIL missrate: docker run failed"; exit 1
fi

# csd attaches during the warmup, then observes the counted run.
# --init-window-ms 0 disables the init-noise time filter: the counted ops
# start ~WARMUP_MS in (long past any container-init noise), so the filter
# can only do harm here by suppressing genuine early counted events. The
# runc-comm filter still drops container-init cap checks regardless.
"${CSD}" --container "${CONTAINER}" --duration "${DURATION}" --init-window-ms 0 \
    --out "${SIDE}" >"${WORKDIR}/csd.log" 2>&1
rc=$?
# Exit 20 (target exited early) is expected: the exerciser finishes its
# ITERS and exits inside the window. Exit 21 (drop rate >=10%) still writes
# the sidecar; let the drop_rate check below report it with actionable
# guidance rather than a bare "csd exited 21". Anything else is fatal.
if [[ ${rc} -ne 0 && ${rc} -ne 20 && ${rc} -ne 21 ]]; then
    echo "FAIL missrate: csd exited ${rc}"
    sed -n '1,30p' "${WORKDIR}/csd.log" >&2 || true
    exit 1
fi

tally="$(docker logs "${CONTAINER}" 2>&1 | grep -E '^TALLY ' | tail -1 || true)"
if [[ -z "${tally}" ]]; then
    echo "FAIL missrate: exerciser printed no TALLY (run unfinished in ${DURATION}; lower ITERS or raise DURATION)"
    exit 1
fi
getn() { printf '%s\n' "${tally}" | sed -nE "s/.*[[:space:]]$1=([0-9]+).*/\1/p"; }
i_chown="$(getn chown)"; i_bind="$(getn bind)"; i_setgid="$(getn setgid)"; i_setuid="$(getn setuid)"

if [[ ! -s "${SIDE}" ]]; then echo "FAIL missrate: no sidecar written"; exit 1; fi

rec() { jq -r --arg c "$1" '[.capabilities[]? | select(.name==$c) | .event_count] | add // 0' "${SIDE}"; }
r_chown="$(rec CHOWN)"; r_bind="$(rec NET_BIND_SERVICE)"; r_setgid="$(rec SETGID)"; r_setuid="$(rec SETUID)"
drop_rate="$(jq -r '.trace_health.drop_rate // 0' "${SIDE}")"
dropped="$(jq -r '.trace_health.events_dropped // 0' "${SIDE}")"

echo "MISSRATE config iters=${ITERS} warmup_ms=${WARMUP_MS} duration=${DURATION} threshold=${THRESHOLD}%"
echo "MISSRATE trace_health dropped=${dropped} drop_rate=${drop_rate}"

# Ringbuf drops are a separate loss channel; a non-trivial rate invalidates
# the deficit as a kretprobe-miss proxy. Require near-zero.
if awk -v d="${drop_rate}" 'BEGIN{exit !(d>0.0001)}'; then
    echo "FAIL missrate: drop_rate ${drop_rate} too high for a valid measurement (lower ITERS to ease ringbuf pressure)"
    exit 1
fi

fail=0; sum_i=0; sum_r=0
check() {
    local cap="$1" iss="$2" recd="$3"
    if [[ -z "${iss}" ]]; then echo "MISSRATE ${cap} no issued count parsed"; fail=1; return; fi
    recd="${recd:-0}"
    sum_i=$((sum_i + iss)); sum_r=$((sum_r + recd))
    if ! awk -v cap="${cap}" -v i="${iss}" -v r="${recd}" -v th="${THRESHOLD}" 'BEGIN{
            if (i==0) { printf "MISSRATE %s issued=0 (skipped)\n", cap; exit 0 }
            def=(i-r)/i*100;
            status=(def>th)?"FAIL":((def<0)?"SURPLUS":"ok");
            printf "MISSRATE %s issued=%d recorded=%d deficit=%.4f%% [%s]\n", cap, i, r, def, status;
            exit (def>th)?1:0
        }'; then fail=1; fi
}
check CHOWN            "${i_chown}"  "${r_chown}"
check NET_BIND_SERVICE "${i_bind}"   "${r_bind}"
check SETGID           "${i_setgid}" "${r_setgid}"
check SETUID           "${i_setuid}" "${r_setuid}"

if ! awk -v i="${sum_i}" -v r="${sum_r}" -v th="${THRESHOLD}" 'BEGIN{
        if (i==0) { print "FAIL missrate: zero events issued"; exit 1 }
        def=(i-r)/i*100;
        printf "MISSRATE overall issued=%d recorded=%d deficit=%.4f%% (threshold %.4f%%)\n", i, r, def, th;
        exit (def>th)?1:0
    }'; then fail=1; fi

if [[ ${fail} -ne 0 ]]; then
    echo "FAIL missrate: capture deficit exceeds ${THRESHOLD}% (see per-cap lines)"
    exit 1
fi
echo "PASS missrate: capture deficit within ${THRESHOLD}% — kretprobe miss rate bounded below threshold"
