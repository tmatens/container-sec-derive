#!/usr/bin/env bash
# Live podman smoke for the --runtime podman path (issue #164).
#
# Validates the only Docker-coupled touchpoints under PODMAN, end-to-end, which
# fixture replay cannot cover:
#   1. ig attaches + attributes PODMAN containers (runtime auto-detection) — the
#      synthetic exerciser's known signal must be observed.
#   2. `podman inspect`/`podman history` (caps entrypoint cross-check) parse — a
#      parse failure would surface in cross_check_status.
#   3. `podman inspect --format '{{json .Mounts}}'` (fs mount correlation) parses
#      — a parse failure makes mountDestinations error and fails the fs run, so a
#      clean fs run against a container WITH a volume proves the .Mounts parse.
#
# Deterministic + hardware-free: the synthetic exerciser (testdata/synthetic)
# fires a known cap stream (CHOWN/SETGID/SETUID, plus NET_BIND_SERVICE with the
# unprivileged-port sysctl) and a write to /csd-exerciser-target every cycle, so
# both gates are hard gates — an empty observation is a real csd/podman bug.
#
# Scheduled-only (every-3-days), not per-PR: podman is the experimental runtime,
# and this is the heavier cross-runtime check (see .github/workflows/integration.yml).
#
# Requires: podman, csd (built; pass CSD=/path), jq, the vendored ig on PATH (the
# IG version pin is enforced inside csd). Runs under sudo in CI for CAP_BPF.
#
# Usage:  make smoke-podman   |   ./scripts/smoke_podman.sh
# Optional env: CSD=/path, DURATION=10s
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-10s}"
IMAGE="csd-synthetic-exerciser:0.1"
CONTAINER="csd-podman-smoke"
VOLUME="csd-podman-smoke-vol"

for tool in podman jq; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "smoke-podman: ${tool} is required" >&2; exit 2; }
done
if [[ ! -x "${CSD}" ]]; then
    echo "smoke-podman: csd not found/executable at ${CSD}; run 'make build' or pass CSD=" >&2
    exit 2
fi

WORKDIR="$(mktemp -d)"
cleanup() {
    podman rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    podman volume rm -f "${VOLUME}" >/dev/null 2>&1 || true
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

if ! podman image exists "${IMAGE}" 2>/dev/null; then
    echo "smoke-podman: building synthetic exerciser image under podman (one-time)"
    podman build -t "${IMAGE}" testdata/synthetic >/dev/null || { echo "FAIL podman: image build failed"; echo "smoke-podman: 0 passed, 1 failed"; exit 1; }
fi

# A named volume at /podman-vol gives the container a real mount so the fs run
# exercises `podman inspect .Mounts`. The sysctl restores the 1024 port boundary
# so the exerciser's bind(:80) actually invokes CAP_NET_BIND_SERVICE.
podman rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if ! podman run -d --name "${CONTAINER}" \
        --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
        -v "${VOLUME}:/podman-vol" "${IMAGE}" >/dev/null; then
    echo "FAIL podman: podman run failed"
    echo "smoke-podman: 0 passed, 1 failed"
    exit 1
fi

fail=0

run_csd() { # <observe> <out>
    local observe="$1" out="$2" rc=0
    "${CSD}" --observe "${observe}" --runtime podman --container "${CONTAINER}" \
        --duration "${DURATION}" --out "${out}" --format json >"${WORKDIR}/${observe}.log" 2>&1 && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        case ${rc} in
            30) echo "FAIL podman(${observe}): csd SchemaMismatch (30) — host ig != PinnedIGVersion" ;;
            31) echo "FAIL podman(${observe}): csd IGMissing (31) — install pinned ig on PATH" ;;
            *)  echo "FAIL podman(${observe}): csd exited ${rc}; log:"; sed -n '1,30p' "${WORKDIR}/${observe}.log" ;;
        esac
        return 1
    fi
    [[ -s "${out}" ]] || { echo "FAIL podman(${observe}): sidecar empty at ${out}"; return 1; }
    return 0
}

# --- caps: ig trace_capabilities under podman + podman inspect/history parse ---
if run_csd caps "${WORKDIR}/caps.json"; then
    if jq -e '
        ([(.capabilities // [])[] | (.name // .)] ) as $caps
        | (["CHOWN","SETGID","SETUID"] - $caps) | length == 0
    ' "${WORKDIR}/caps.json" >/dev/null; then
        echo "INFO podman(caps): cross_check_status=$(jq -rc '.cross_check_status // "(clean)"' "${WORKDIR}/caps.json")"
        echo "PASS podman(caps): observed_caps ⊇ [CHOWN,SETGID,SETUID] under podman (ig attach + attribution OK)"
    else
        echo "FAIL podman(caps): expected caps not observed; got $(jq -rc '[(.capabilities//[])[]|(.name // .)]' "${WORKDIR}/caps.json")"
        fail=1
    fi
else
    fail=1
fi

# --- fs: ig trace_open under podman + podman inspect .Mounts parse ---
if run_csd fs "${WORKDIR}/fs.json"; then
    if jq -e '(.writable_paths // []) | any(.path == "/csd-exerciser-target")' "${WORKDIR}/fs.json" >/dev/null; then
        echo "PASS podman(fs): writable_paths ∋ /csd-exerciser-target under podman (trace_open + podman inspect .Mounts parse OK)"
    else
        echo "FAIL podman(fs): /csd-exerciser-target not in writable_paths; got $(jq -rc '[(.writable_paths//[])[].path]' "${WORKDIR}/fs.json")"
        fail=1
    fi
else
    fail=1
fi

if [[ ${fail} -eq 0 ]]; then
    echo "smoke-podman: 2 passed, 0 failed"
else
    echo "smoke-podman: $((2 - fail)) passed, ${fail} failed"
    exit 1
fi
