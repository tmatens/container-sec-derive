#!/usr/bin/env bash
# Bisect the minimum capability set sufficient to run a workload against
# an image, using the kernel as validator.
#
# Algorithm: start from the Docker default capability set and remove one
# capability at a time. Re-run init + workload after each removal; if the
# workload passes, the cap is unneeded and stays out, otherwise it is
# restored. The remaining set is the minimum sufficient cap set.
#
# This is bisection-by-elimination: it reports a cap as required only if
# the workload fails without it. Capabilities outside the Docker default
# starting set are not considered (a workload that needs e.g. NET_ADMIN
# would not be a v0.1 reference image).
#
# Usage:
#   IMAGE=postgres:16 \
#   IMAGE_NAME=postgres \
#   WORKLOAD=testdata/postgres/workload.sh \
#   RUN_ARGS='-e POSTGRES_PASSWORD=postgres' \
#   READY_TIMEOUT=60 \
#   ./scripts/bisect_caps.sh
#
# RUN_ARGS is shell-evaluated and passed to docker run (env, volumes, etc).
# The container name used is csd-bisect-<image_name>; it is removed before
# every iteration. Output: ground_truth.json on stdout.
set -euo pipefail

: "${IMAGE:?IMAGE must be set}"
: "${IMAGE_NAME:?IMAGE_NAME must be set (used for container name)}"
: "${WORKLOAD:?WORKLOAD must be set}"
: "${RUN_ARGS:=}"
: "${READY_TIMEOUT:=60}"

CONTAINER="csd-bisect-${IMAGE_NAME}"

# Docker default capability set as of 24.0+ (see moby/moby).
DEFAULT_CAPS=(
    CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP
    NET_BIND_SERVICE NET_RAW SYS_CHROOT MKNOD AUDIT_WRITE SETFCAP
)

cleanup() {
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# run_with_caps <cap1> <cap2> ... — start container with cap_drop=ALL plus
# the listed caps as cap_add, run the workload, return 0 on success.
run_with_caps() {
    cleanup
    local cap_args=()
    local c
    for c in "$@"; do
        cap_args+=(--cap-add "${c}")
    done
    # shellcheck disable=SC2086
    docker run -d --name "${CONTAINER}" \
        --cap-drop=ALL \
        ${RUN_ARGS} \
        "${cap_args[@]}" \
        "${IMAGE}" >/dev/null
    PGCONTAINER="${CONTAINER}" \
        TS_CONTAINER="${CONTAINER}" \
        CADDY_CONTAINER="${CONTAINER}" \
        timeout "$((READY_TIMEOUT + 60))" "${WORKLOAD}" >&2
}

CANDIDATES=("${DEFAULT_CAPS[@]}")
REQUIRED=()
LOG=()

# Sanity check: workload must pass with the full default set.
echo "==> sanity: full default cap set" >&2
if ! run_with_caps "${CANDIDATES[@]}"; then
    echo "workload failed even with default caps; cannot bisect" >&2
    exit 2
fi
LOG+=("baseline default-caps run: pass")

KEEP=("${CANDIDATES[@]}")
for cap in "${CANDIDATES[@]}"; do
    TRIAL=()
    for k in "${KEEP[@]}"; do
        if [[ "${k}" != "${cap}" ]]; then
            TRIAL+=("${k}")
        fi
    done
    echo "==> trial without ${cap}" >&2
    if run_with_caps "${TRIAL[@]}"; then
        echo "    drop ${cap}" >&2
        KEEP=("${TRIAL[@]}")
        LOG+=("drop ${cap}: workload still passes — unneeded")
    else
        echo "    keep ${cap}" >&2
        REQUIRED+=("${cap}")
        LOG+=("drop ${cap}: workload fails — required")
    fi
done

cleanup

DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${IMAGE}" 2>/dev/null | awk -F@ '{print $2}')"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# json_str — minimal JSON string escaper (handles backslash, double-quote,
# and the bisection_log's printable ASCII; the only field that needs more
# than that is bisection_log, which we control).
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '"%s"' "${s}"
}

# Emit ground_truth.json.
{
    printf '{\n'
    printf '  "image": %s,\n' "$(json_str "${IMAGE}")"
    printf '  "image_digest": %s,\n' "$(json_str "${DIGEST}")"
    # Normalise WORKLOAD to repo-relative if it lives under PWD.
    workload_rel="${WORKLOAD}"
    if [[ "${workload_rel}" == "${PWD}/"* ]]; then
        workload_rel="${workload_rel#${PWD}/}"
    fi
    printf '  "workload": %s,\n' "$(json_str "${workload_rel}")"
    printf '  "caps": ['
    first=1
    for c in "${KEEP[@]}"; do
        if (( first )); then first=0; else printf ', '; fi
        printf '%s' "$(json_str "${c}")"
    done
    printf '],\n'
    printf '  "bisected_at": %s,\n' "$(json_str "${NOW}")"
    printf '  "bisection_log": [\n'
    first=1
    for line in "${LOG[@]}"; do
        if (( first )); then first=0; else printf ',\n'; fi
        printf '    %s' "$(json_str "${line}")"
    done
    printf '\n  ]\n'
    printf '}\n'
}
