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
"$PY" - "$COMPOSE" "$SERVICE" "$CORRECTNESS" "$WORK/declared.json" > "$WORK/spec.yaml" <<'PYEOF'
import os, sys, json, yaml

compose, service, correctness, declared_out = sys.argv[1:5]
compose_dir = os.path.dirname(os.path.abspath(compose))

def resolve_mount(v):
    # A compose volume is "source:target[:opts]". Compose resolves a relative
    # bind source (./x, ../x) against the compose file's directory before calling
    # docker; docker itself does not, so do it here. Named volumes (a bare name)
    # and absolute paths pass through untouched.
    parts = v.split(":")
    src = parts[0]
    if src.startswith("./") or src.startswith("../"):
        parts[0] = os.path.normpath(os.path.join(compose_dir, src))
    return ":".join(parts)
doc = yaml.safe_load(open(compose)) or {}
svc = (doc.get("services") or {}).get(service)
if svc is None:
    sys.exit(f"compose_derive: service {service!r} not found in {compose}")

image = svc.get("image")
if not image:
    sys.exit(f"compose_derive: service {service!r} has no image:")
name, _, tag = image.partition(":")
tag = tag or "latest"

env = svc.get("environment") or []
if isinstance(env, dict):
    env = [f"{k}={v}" for k, v in env.items()]

def as_list(v):
    return [] if not v else (v if isinstance(v, list) else [v])

DOCKER_DEFAULT_CAPS = [
    "CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID",
    "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL",
    "AUDIT_WRITE",
]
cap_add = [str(c).upper() for c in (svc.get("cap_add") or [])]
cap_drop = [str(c).upper() for c in (svc.get("cap_drop") or [])]
candidates = sorted(set(cap_add) | set(DOCKER_DEFAULT_CAPS))

# A bind mount whose source doesn't exist on THIS derive host can't be
# reproduced (a target-host-specific config/binary like /usr/bin/msmtp or
# /home/user/svc/config). Such mounts don't gate capabilities, so skip them with
# a caveat rather than fail — and if one were actually load-bearing, the baseline
# correctness check fails and the run reports that (never a wrong minimum). Named
# volumes (a bare name, no `/`) are docker-managed and kept (created empty).
mounts, skipped = [], []
for v in (svc.get("volumes") or []):
    if not isinstance(v, str):
        continue
    rv = resolve_mount(str(v))
    src = rv.split(":")[0]
    if "/" not in src or os.path.exists(src):
        mounts.append(rv)
    else:
        skipped.append(rv)
if skipped:
    print(f"compose_derive: skipped {len(skipped)} bind mount(s) with no source on "
          f"this derive host (not cap-relevant): {skipped}", file=sys.stderr)

run = {
    "user": str(svc.get("user", "") or ""),
    "command": as_list(svc.get("command")),
    "entrypoint": (svc.get("entrypoint") if isinstance(svc.get("entrypoint"), str) else ""),
    "network": str(svc.get("network_mode", "") or ""),
    "pid": str(svc.get("pid", "") or ""),
    "security_opt": [str(s) for s in (svc.get("security_opt") or [])],
    "mounts": mounts,
    "env": env,
}
json.dump({"cap_add": cap_add, "cap_drop": cap_drop}, open(declared_out, "w"))
spec = {
    "image": name, "tag": tag, "dimension": "capabilities",
    "fixed": [], "candidates": candidates, "run": run, "correctness": correctness,
}
print(yaml.safe_dump(spec, sort_keys=False))
PYEOF
[ $? -eq 0 ] || { cat "$WORK/spec.yaml" >&2; exit 1; }

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
