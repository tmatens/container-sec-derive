#!/usr/bin/env bash
# Live-BPF smoke for the v0.8 network-egress observer (`--observe egress`).
#
# This is the increment fixture replay cannot cover: it validates that the
# trace_tcp attach + the tcpEvent parser handle a REAL ig trace_tcp stream — an
# outbound connect() with the dst l4endpoint and container attribution — not
# just a hand-rolled fixture. (If the pinned ig's trace_tcp JSON field names
# ever drift from what egressevent.go parses, this gate fails.)
#
# Hardware-free, deterministic, no external network: a stock alpine container
# repeatedly TCP-connects to its OWN docker bridge gateway on a fixed port. The
# connect() syscall fires whether or not the port is listening (the gateway need
# not accept it), so trace_tcp records a connect event to <gateway>:<port> every
# cycle. The gateway IP is read back from `docker inspect`, giving the exact
# (addr, port) the egress observation must contain.
#
# Gate (hard — an empty allowlist is a real csd bug here, not a workload
# artifact): egress_destinations ∋ <gateway>:<port>.
#
# Requires: docker, csd (built; pass CSD=/path to override), jq, the vendored ig
# binary on PATH (the IG version pin is enforced inside csd).
#
# Usage:
#   make smoke-egress
#   ./scripts/smoke_egress.sh
#
# Optional env:
#   CSD=/path/to/csd     binary under test (defaults to ./csd)
#   DURATION=30s         observation window
#   EGRESS_PORT=9        destination port to dial (discard; need not listen)
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
IMAGE="${OPENER_IMAGE:-alpine:3.24}"
PORT="${EGRESS_PORT:-9}"
CONTAINER="csd-egress-smoke"

if [[ ! -x "${CSD}" ]]; then
    echo "smoke-egress: csd binary not found or not executable at ${CSD}" >&2
    echo "smoke-egress: run 'make build' first or pass CSD=/path/to/csd" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-egress: jq is required" >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "smoke-egress: docker is required" >&2
    exit 2
fi

docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"; docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true' EXIT

# An idle container just to claim a bridge IP + gateway; the connect loop is
# started via docker exec once the gateway is known, so no in-container gateway
# computation is needed.
if ! docker run -d --name "${CONTAINER}" "${IMAGE}" sleep 3600 >/dev/null; then
    echo "FAIL egress: docker run failed"
    echo "smoke-egress: 0 passed, 1 failed"
    exit 1
fi

GW="$(docker inspect -f '{{.NetworkSettings.Gateway}}' "${CONTAINER}" 2>/dev/null)"
if [[ -z "${GW}" ]]; then
    GW="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "${CONTAINER}" 2>/dev/null)"
fi
if [[ -z "${GW}" ]]; then
    echo "FAIL egress: could not determine the container's gateway IP"
    echo "smoke-egress: 0 passed, 1 failed"
    exit 1
fi

# Tight outbound-connect loop to <gateway>:<port>. The port need not listen — the
# connect() (and trace_tcp's tcp_connect hook) fire regardless.
docker exec -d "${CONTAINER}" sh -c \
    "while true; do nc -w1 ${GW} ${PORT} </dev/null >/dev/null 2>&1 || true; sleep 0.2; done"

sidecar="${WORKDIR}/egress.json"
log="${WORKDIR}/csd.log"
rc=0
"${CSD}" --observe egress --container "${CONTAINER}" --duration "${DURATION}" \
    --out "${sidecar}" --format json >"${log}" 2>&1 && rc=0 || rc=$?
if [[ ${rc} -ne 0 ]]; then
    case ${rc} in
        30) echo "FAIL egress: csd exited SchemaMismatch (30) — host ig differs from PinnedIGVersion" ;;
        31) echo "FAIL egress: csd exited IGMissing (31) — install the pinned ig binary on PATH" ;;
        *) echo "FAIL egress: csd exited ${rc}; see below"; sed -n '1,40p' "${log}" ;;
    esac
    echo "smoke-egress: 0 passed, 1 failed"
    exit 1
fi
if [[ ! -s "${sidecar}" ]]; then
    echo "FAIL egress: sidecar empty or missing at ${sidecar}"
    echo "smoke-egress: 0 passed, 1 failed"
    exit 1
fi

if jq -e --arg gw "${GW}" --argjson port "${PORT}" \
    '(.egress_destinations // []) | any(.addr == $gw and .port == $port)' "${sidecar}" >/dev/null; then
    recorded="$(jq -r '.trace_health.events_recorded // 0' "${sidecar}")"
    echo "PASS egress: egress_destinations ∋ ${GW}:${PORT} (events_recorded=${recorded})"
    echo "smoke-egress: 1 passed, 0 failed"
else
    echo "FAIL egress: ${GW}:${PORT} not in egress_destinations; got $(jq -c '[(.egress_destinations//[])[] | "\(.addr):\(.port)"]' "${sidecar}")"
    echo "smoke-egress: 0 passed, 1 failed"
    exit 1
fi
