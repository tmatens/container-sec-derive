#!/usr/bin/env bash
# Bisect the minimum capability set sufficient to run a workload against
# an image, using the kernel as validator.
#
# Algorithm (see issue #32 for the analysis):
#   1. Start from the Docker default capability set (sufficient by assumption).
#   2. GREEDY pass — remove one cap at a time in order; if the workload still
#      passes, the cap stays out, else it is restored.
#   3. STABILIZATION fixpoint — re-test every cap still kept against the *current*
#      (smaller) keep set, repeating until a full pass drops nothing. This catches
#      a cap that was locked in early (tested while the keep set was larger) but
#      is no longer needed once other caps were dropped — the order-dependence
#      greedy alone misses. The result is robustly **1-minimal**: no single cap
#      can be removed without the workload failing.
#
# 1-minimal is not always GLOBALLY minimum-sized. The two diverge only under
# cap *substitutability* (the workload exercises a path satisfied by either of
# two caps) or genuinely cap-dependent behavior. True globally-minimum requires
# searching subsets beyond the kept set — exponential in the 14-cap default
# (2^14 trials), infeasible against a ~minutes-per-trial container driver. Two
# bounded, opt-in tools approximate it:
#   - ORDERS=N         run the minimizer from N shuffled orders; divergent results
#                      (same size, different identity) reveal substitutability and
#                      the smallest result is kept. Logged on the sidecar.
#   - VERIFY_MINIMAL=1 after minimizing, exhaustively test every proper subset of
#                      the (small) kept set to PROVE 1-minimality and to flag a
#                      non-monotone workload (a passing proper subset means caps
#                      change the workload's behavior — the "minimum" is then
#                      ambiguous and is reported, not silently trusted).
#
# This is bisection-by-elimination: it reports a cap as required only if the
# workload fails without it. Capabilities outside the Docker default starting
# set are not considered (a workload that needs e.g. NET_ADMIN would not be a
# v0.1 reference image).
#
# Usage:
#   IMAGE=postgres:16 \
#   IMAGE_NAME=postgres \
#   WORKLOAD=testdata/postgres/workload.sh \
#   RUN_ARGS='-e POSTGRES_PASSWORD=postgres' \
#   READY_TIMEOUT=60 \
#   ORDERS=3 VERIFY_MINIMAL=1 \
#   ./scripts/bisect_caps.sh
#
# RUN_ARGS is shell-evaluated and passed to docker run (env, volumes, etc).
# The container name used is csd-bisect-<image_name>; it is removed before
# every iteration. Output: ground_truth.json on stdout. Captured fields:
# image, image_digest, workload, caps, bisected_at, host_context (kernel,
# arch, os, docker_server_version, cgroup_driver), bisection_log.
#
# The capability-set search is oracle-driven: the predicate "does the workload
# pass with this cap set?" is `run_with_caps` here, but is overridable via
# CSD_BISECT_ORACLE (a function name) so scripts/bisect_caps_selftest.sh can
# exercise the minimizer hermetically with synthetic oracles (no Docker).
set -euo pipefail

# Docker default capability set as of 24.0+ (see moby/moby).
DEFAULT_CAPS=(
    CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP
    NET_BIND_SERVICE NET_RAW SYS_CHROOT MKNOD AUDIT_WRITE SETFCAP
)

# ---- capability-set helpers (a "set" is a normalised, space-separated list) ----

# _has <cap> <set> — 0 if cap is in the set.
_has() { case " $2 " in *" $1 "*) return 0;; *) return 1;; esac; }

# _remove <cap> <set> — echo the set without cap.
_remove() {
    local out=() w
    for w in $2; do [[ "$w" == "$1" ]] || out+=("$w"); done
    echo "${out[*]:-}"
}

# _count <set> — echo the cardinality.
_count() { local n=0 w; for w in $1; do n=$((n + 1)); done; echo "$n"; }

# _sort <set> — echo the set sorted (stable, canonical identity for comparison).
_sort() { local w; for w in $1; do echo "$w"; done | sort | tr '\n' ' ' | xargs || true; }

# oracle <set> — 0 if the workload passes with exactly these caps. The set is a
# single space-separated string argument. Indirection point: CSD_BISECT_ORACLE
# overrides the default container-driven predicate (run_with_caps) with a
# synthetic one for the hermetic self-test.
oracle() { "${CSD_BISECT_ORACLE:-run_with_caps}" "$1"; }

# ---- the real (container) oracle ----

CONTAINER="csd-bisect-${IMAGE_NAME:-unset}"

cleanup() { docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true; }

# run_with_caps <set> — start container with cap_drop=ALL plus the caps in the
# (space-separated) set as cap_add, run the workload, return 0 on success.
run_with_caps() {
    cleanup
    local cap_args=() c
    for c in $1; do cap_args+=(--cap-add "${c}"); done
    # shellcheck disable=SC2086
    docker run -d --name "${CONTAINER}" \
        --cap-drop=ALL \
        ${RUN_ARGS:-} \
        "${cap_args[@]}" \
        "${IMAGE}" >/dev/null
    PGCONTAINER="${CONTAINER}" \
        TS_CONTAINER="${CONTAINER}" \
        CADDY_CONTAINER="${CONTAINER}" \
        timeout "$((${READY_TIMEOUT:-60} + 60))" "${WORKLOAD}" >&2
}

# ---- the minimizer ----

# greedy_minimize <ordered-set> — greedy elimination in the given order followed
# by a stabilization fixpoint. Sets GM_RESULT to the 1-minimal set (sorted) and
# appends reasoning to MIN_LOG. Uses globals (not stdout) so callers invoke it
# directly — command substitution would run it in a subshell and lose MIN_LOG.
# Assumes the input set is sufficient.
MIN_LOG=()
GM_RESULT=""
greedy_minimize() {
    local keep="$1" cap trial
    # Greedy pass.
    for cap in $1; do
        _has "$cap" "$keep" || continue
        trial="$(_remove "$cap" "$keep")"
        if oracle "$trial"; then
            keep="$trial"
            MIN_LOG+=("greedy: drop ${cap} — workload still passes")
        else
            MIN_LOG+=("greedy: keep ${cap} — workload fails without it")
        fi
    done
    # Stabilization fixpoint: re-test every kept cap against the current keep.
    local changed=1 pass=0
    while ((changed)); do
        changed=0
        pass=$((pass + 1))
        for cap in $keep; do
            trial="$(_remove "$cap" "$keep")"
            if oracle "$trial"; then
                keep="$trial"
                changed=1
                MIN_LOG+=("stabilize[pass ${pass}]: drop ${cap} — unneeded in the reduced set (#32)")
            fi
        done
    done
    GM_RESULT="$(_sort "$keep")"
}

# multi_order_minimize <set> — run greedy_minimize from the natural order plus
# (ORDERS-1) shuffled orders; set MOM_RESULT to the smallest result. Sets
# SUBSTITUTABLE=1 and logs when results diverge (cap substitutability /
# order-dependence). Uses globals (see greedy_minimize).
SUBSTITUTABLE=0
MOM_RESULT=""
multi_order_minimize() {
    local base="$1" n="${ORDERS:-1}" best="" best_n=99 i order rn
    local -A seen=()
    for ((i = 0; i < n; i++)); do
        if ((i == 0)); then
            order="$base"
        else
            order="$(tr ' ' '\n' <<<"$base" | shuf | tr '\n' ' ' | xargs)"
        fi
        greedy_minimize "$order"
        seen["$GM_RESULT"]=1
        rn="$(_count "$GM_RESULT")"
        if ((rn < best_n)); then best="$GM_RESULT"; best_n="$rn"; fi
    done
    if ((${#seen[@]} > 1)); then
        SUBSTITUTABLE=1
        MIN_LOG+=("multi-order: ${#seen[@]} distinct minimal sets across ${n} orders — substitutability or order-dependence; smallest kept: [${best}]")
    fi
    MOM_RESULT="$best"
}

# verify_minimal <set> — exhaustively test every PROPER subset of the (small)
# set. Echoes nothing and returns 0 if none passes (the set is truly 1-minimal).
# If a proper subset passes, the workload is non-monotone (cap-dependent
# behavior): echoes the passing subset and returns 1 (caller flags it).
verify_minimal() {
    local set_arr=() w
    for w in $1; do set_arr+=("$w"); done
    local n=${#set_arr[@]} mask sub i
    # All subsets except the full set (mask = (1<<n)-1) and skip is unnecessary;
    # the full set trivially passes. n is small (a 1-minimal cap set), so 2^n is
    # a handful of trials.
    for ((mask = 0; mask < (1 << n) - 1; mask++)); do
        sub=()
        for ((i = 0; i < n; i++)); do
            (((mask >> i) & 1)) && sub+=("${set_arr[$i]}")
        done
        if oracle "${sub[*]:-}"; then
            echo "${sub[*]:-}"
            return 1
        fi
    done
    return 0
}

# ---- JSON emit ----

# json_str — minimal JSON string escaper (handles backslash, double-quote,
# and the bisection_log's printable ASCII; the only field that needs more
# than that is bisection_log, which we control).
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '"%s"' "${s}"
}

main() {
    : "${IMAGE:?IMAGE must be set}"
    : "${IMAGE_NAME:?IMAGE_NAME must be set (used for container name)}"
    : "${WORKLOAD:?WORKLOAD must be set}"
    : "${RUN_ARGS:=}"
    : "${READY_TIMEOUT:=60}"

    trap cleanup EXIT

    local start; start="$(echo "${DEFAULT_CAPS[*]}")"
    local LOG=()

    # Sanity: workload must pass with the full default set.
    echo "==> sanity: full default cap set" >&2
    if ! oracle "$start"; then
        echo "workload failed even with default caps; cannot bisect" >&2
        exit 2
    fi
    LOG+=("baseline default-caps run: pass")

    echo "==> minimizing (greedy + stabilization; ORDERS=${ORDERS:-1})" >&2
    multi_order_minimize "$start"
    local KEEP="$MOM_RESULT"
    local k; for k in "${MIN_LOG[@]}"; do LOG+=("$k"); echo "    $k" >&2; done

    if [[ "${VERIFY_MINIMAL:-0}" == "1" ]]; then
        echo "==> verify-minimal: testing proper subsets of [${KEEP}]" >&2
        local smaller
        if smaller="$(verify_minimal "$KEEP")"; then
            LOG+=("verify-minimal: confirmed — no proper subset of the kept set passes (truly 1-minimal)")
            echo "    confirmed 1-minimal" >&2
        else
            LOG+=("verify-minimal: WARNING — proper subset [${smaller}] also passes; workload is non-monotone (cap-dependent behavior), 'minimum' is ambiguous")
            echo "    WARNING: subset [${smaller}] also passes — non-monotone workload" >&2
        fi
    fi

    cleanup

    local DIGEST NOW KERNEL ARCH OS_NAME DOCKER_VER CGROUP_DRIVER
    DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${IMAGE}" 2>/dev/null | awk -F@ '{print $2}')"
    NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    KERNEL="$(uname -r 2>/dev/null || echo unknown)"
    ARCH="$(uname -m 2>/dev/null || echo unknown)"
    OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
    DOCKER_VER="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
    CGROUP_DRIVER="$(docker info --format '{{.CgroupDriver}}' 2>/dev/null || echo unknown)"

    local workload_rel="${WORKLOAD}"
    [[ "${workload_rel}" == "${PWD}/"* ]] && workload_rel="${workload_rel#"${PWD}"/}"

    {
        printf '{\n'
        printf '  "image": %s,\n' "$(json_str "${IMAGE}")"
        printf '  "image_digest": %s,\n' "$(json_str "${DIGEST}")"
        printf '  "workload": %s,\n' "$(json_str "${workload_rel}")"
        printf '  "caps": ['
        local first=1 c
        for c in ${KEEP}; do
            if ((first)); then first=0; else printf ', '; fi
            printf '%s' "$(json_str "${c}")"
        done
        printf '],\n'
        printf '  "substitutable": %s,\n' "$([[ ${SUBSTITUTABLE} -eq 1 ]] && echo true || echo false)"
        printf '  "bisected_at": %s,\n' "$(json_str "${NOW}")"
        printf '  "host_context": {\n'
        printf '    "kernel": %s,\n' "$(json_str "${KERNEL}")"
        printf '    "arch": %s,\n' "$(json_str "${ARCH}")"
        printf '    "os": %s,\n' "$(json_str "${OS_NAME}")"
        printf '    "docker_server_version": %s,\n' "$(json_str "${DOCKER_VER}")"
        printf '    "cgroup_driver": %s\n' "$(json_str "${CGROUP_DRIVER}")"
        printf '  },\n'
        printf '  "bisection_log": [\n'
        first=1
        local line
        for line in "${LOG[@]}"; do
            if ((first)); then first=0; else printf ',\n'; fi
            printf '    %s' "$(json_str "${line}")"
        done
        printf '\n  ]\n'
        printf '}\n'
    }
}

# Run main only when executed directly, so the self-test can source this file
# to drive greedy_minimize/verify_minimal with a synthetic oracle.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
