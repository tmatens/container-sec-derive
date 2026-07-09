#!/usr/bin/env bash
# Diagnostic (not a gate): capture the REAL ig v0.51.0 field naming — cap names and
# syscall names — as the live gadget emits them, so the committed fixtures can be
# reconciled against ground truth (#349 follow-up: fixtures used idealized lowercase
# bare syscall names like "perf_event_open"/"openat", but live ig emits SYS_-prefixed
# uppercase "SYS_PERF_EVENT_OPEN"/"SYS_OPEN"). Runs the synthetic exerciser with ALL
# ops enabled and dumps unique (cap, syscall, capable) triples from trace_capabilities
# plus unique (syscall) from trace_open.
#
# Self-hosted only (needs ig + docker + sudo). Prints clearly-delimited blocks.
set -uo pipefail

IG="${IG:-ig}"
IMAGE="csd-synthetic-exerciser:0.1"
C="csd-ig-naming-capture"
PIN="$(awk -F'"' '/^[[:space:]]+PinnedIGVersion[[:space:]]+=/ {print $2; exit}' internal/ig/ig.go)"
CAPS_GADGET="ghcr.io/inspektor-gadget/gadget/trace_capabilities:${PIN}"
OPEN_GADGET="ghcr.io/inspektor-gadget/gadget/trace_open:${PIN}"

command -v docker >/dev/null 2>&1 || { echo "capture: docker required" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "capture: jq required" >&2; exit 2; }
"${IG}" version >/dev/null 2>&1 || { echo "capture: ig not on PATH" >&2; exit 2; }

echo "capture: (re)building synthetic image"
docker build -t "${IMAGE}" testdata/synthetic >/dev/null || { echo "capture: build failed" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'docker rm -f "$C" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

# All ops on: chown/chmod/open/bind/setgid/setuid (default) + DAC read + perf.
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --cap-add SYS_ADMIN \
    -e CSD_EXERCISE_DAC=1 -e CSD_EXERCISE_PERF=1 "${IMAGE}" >/dev/null \
    || { echo "capture: docker run failed" >&2; exit 1; }
sleep 1

echo "capture: recording trace_capabilities for 8s…"
timeout 8 "${IG}" run "${CAPS_GADGET}" --output json > "$WORK/caps.ndjson" 2>/dev/null || true
echo "capture: recording trace_open for 5s…"
timeout 5 "${IG}" run "${OPEN_GADGET}" --paths --output json > "$WORK/open.ndjson" 2>/dev/null || true

echo ""
echo "===== REAL ig ${PIN} trace_capabilities (cap, syscall, capable) — exerciser only ====="
jq -rc 'select(.proc.comm=="exerciser") | [.cap, .syscall, .capable] | @tsv' "$WORK/caps.ndjson" 2>/dev/null \
    | sort -u || echo "(no events / parse error)"

echo ""
echo "===== REAL ig ${PIN} trace_open (syscall) — exerciser only ====="
jq -rc 'select(.proc.comm=="exerciser") | .syscall' "$WORK/open.ndjson" 2>/dev/null \
    | sort -u || echo "(no events / parse error)"

echo ""
echo "===== sample raw trace_capabilities event (field shapes) ====="
jq -c 'select(.proc.comm=="exerciser")' "$WORK/caps.ndjson" 2>/dev/null | head -1 || echo "(none)"
echo "capture: done"
