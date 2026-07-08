#!/usr/bin/env bash
# Re-derive a service's minimum capabilities from its ACTUAL compose config, and
# compare that minimum to what the service declares — a deploy-time check.
#
# This is the "re-derive at deploy" path: rather than loose-matching a generic
# catalog entry to a service by image name — which is blind to the invocation and
# so can be silently wrong (a service run with `user:` set needs none of the
# startup caps a default-invocation profile lists) — derive the profile against
# the exact way THIS service runs, then diff the derived minimum against the
# service's declared cap_add/cap_drop to say what to drop and what's missing.
#
# The correctness check stays per-service (a container can be "healthy" and
# wrong — the netdata trap): supply one with CORRECTNESS, or the built-in generic
# check verifies the container stays running (weaker — see docs).
#
#   CORRECTNESS=testdata/drop-test/correctness/<svc>.sh \
#     scripts/compose_derive.sh <compose.yml> <service>
#
# Emits the drop_test.sh evidence JSON (with run_config) plus a deploy_check
# block {recommended, declared, verdict, drop, add}; prints a one-line verdict to
# stderr. Exit code is the gate signal: 0 matches, 10 not-minimized,
# 11 over-permissioned, 12 under-permissioned (missing caps — would break).
set -uo pipefail

COMPOSE="${1:?usage: compose_derive.sh <compose.yml> <service>}"
SERVICE="${2:?usage: compose_derive.sh <compose.yml> <service>}"
PY="${PY:-python3}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CORRECTNESS="${CORRECTNESS:-testdata/drop-test/correctness/compose_generic.sh}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# --- extract the service's run config into a drop-test spec -----------------
# Candidates = the declared cap_add UNION the Docker default set, so the derived
# minimum can reveal both over-grants (declared, not needed) and missing caps
# (needed, not declared). Declared caps are written to declared.json for the
# post-derivation comparison.
"$PY" "$REPO/scripts/compose_to_spec.py" \
  "$COMPOSE" "$SERVICE" "$CORRECTNESS" "$WORK/declared.json" "$WORK/build.json" \
  > "$WORK/spec.yaml" || { cat "$WORK/spec.yaml" >&2; exit 1; }

# If the service builds its image (compose `build:`), build it now so drop_test
# (no_pull) finds it locally, deriving against the ACTUAL deployed image.
BUILD_CTX="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("context",""))' "$WORK/build.json" 2>/dev/null || true)"
if [ -n "$BUILD_CTX" ]; then
  BUILD_DF="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("dockerfile",""))' "$WORK/build.json")"
  BUILD_IMG="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("image",""))' "$WORK/build.json")"
  echo "compose_derive: ${SERVICE} builds a custom image; docker build ${BUILD_CTX} -> ${BUILD_IMG}" >&2
  bargs=(build -t "$BUILD_IMG")
  [ -n "$BUILD_DF" ] && bargs+=(-f "${BUILD_CTX}/${BUILD_DF}")
  bargs+=("$BUILD_CTX")
  if ! docker "${bargs[@]}" > "$WORK/build.log" 2>&1; then
    tail -5 "$WORK/build.log" >&2; echo "compose_derive: docker build failed for ${SERVICE}" >&2; exit 3
  fi
fi

echo "compose_derive: ${SERVICE} -> ${COMPOSE}; drop-testing under its own invocation" >&2
if ! PY="$PY" bash "$REPO/scripts/drop_test.sh" "$WORK/spec.yaml" > "$WORK/result.json" 2>"$WORK/dt.err"; then
    tail -3 "$WORK/dt.err" >&2; exit 3
fi

# --- compare the derived minimum to what the service declares ---------------
"$PY" - "$WORK/result.json" "$WORK/declared.json" <<'PYEOF'
import sys, json
result = json.load(open(sys.argv[1]))
declared = json.load(open(sys.argv[2]))
minimum = set(result.get("minimum") or [])
cap_add = set(declared.get("cap_add") or [])
drops_all = "ALL" in {c.upper() for c in declared.get("cap_drop") or []}

recommended = {"cap_drop": ["ALL"], "cap_add": sorted(minimum)}
if drops_all:
    over = sorted(cap_add - minimum)      # granted but not needed -> drop
    add = sorted(minimum - cap_add)       # needed but not granted -> would break
    verdict = ("under_permissioned" if add
               else "over_permissioned" if over
               else "matches")
else:
    over = sorted(cap_add)                # everything, since we recommend cap_drop: ALL
    add = sorted(minimum - cap_add)
    verdict = "not_minimized"

result["deploy_check"] = {
    "recommended": recommended,
    "declared": {"cap_drop": sorted(declared.get("cap_drop") or []),
                 "cap_add": sorted(cap_add)},
    "verdict": verdict,
    "drop": over,
    "add": add,
}
print(json.dumps(result, indent=2))

msg = {
    "matches": "declared cap_add matches the derived minimum",
    "over_permissioned": f"over-permissioned: drop {over} (declared, not needed)",
    "under_permissioned": f"UNDER-permissioned: missing {add} (needed — would break); also drop {over}",
    "not_minimized": f"no cap_drop: ALL — recommend cap_drop:[ALL] + cap_add:{sorted(minimum)}",
}[verdict]
print(f"compose_derive: {verdict} — {msg}", file=sys.stderr)

# Exit codes make it a gate (mirrors csd verify): 0 matches, 10 not-minimized,
# 11 over-permissioned, 12 under-permissioned (missing caps — would break, the
# hard failure). A caller picks its threshold (e.g. fail >=12, warn on 10/11).
sys.exit({"matches": 0, "not_minimized": 10,
          "over_permissioned": 11, "under_permissioned": 12}[verdict])
PYEOF
