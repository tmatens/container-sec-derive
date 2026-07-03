#!/usr/bin/env bash
# Re-derive a service's minimum capabilities from its ACTUAL compose config.
#
# This is the "re-derive at deploy" path: rather than loose-matching a generic
# catalog entry to a service by image name — which is blind to the invocation and
# so can be silently wrong (a service run with `user:` set needs none of the
# startup caps a default-invocation profile lists) — derive the profile against
# the exact way THIS service runs. It reads the service out of a compose file,
# extracts its run config (image, user, command, network/pid mode, security_opt,
# mounts, env, and the granted cap set), generates a drop-test spec, and runs it.
#
# The correctness predicate stays per-service (a container can be "healthy" and
# wrong — the netdata trap): supply one with PREDICATE, or the built-in generic
# predicate checks the container stays running (weaker — see docs).
#
#   PREDICATE=testdata/drop-test/predicates/<svc>.sh \
#     scripts/compose_derive.sh <compose.yml> <service>
#
# Emits the same evidence JSON as scripts/drop_test.sh (with run_config).
set -uo pipefail

COMPOSE="${1:?usage: compose_derive.sh <compose.yml> <service>}"
SERVICE="${2:?usage: compose_derive.sh <compose.yml> <service>}"
PY="${PY:-python3}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PREDICATE="${PREDICATE:-testdata/drop-test/predicates/compose_generic.sh}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# --- extract the service's run config into a drop-test spec -----------------
"$PY" - "$COMPOSE" "$SERVICE" "$PREDICATE" > "$WORK/spec.yaml" <<'PYEOF'
import sys, yaml

compose, service, predicate = sys.argv[1], sys.argv[2], sys.argv[3]
doc = yaml.safe_load(open(compose)) or {}
svc = (doc.get("services") or {}).get(service)
if svc is None:
    sys.exit(f"compose_derive: service {service!r} not found in {compose}")

image = svc.get("image")
if not image:
    sys.exit(f"compose_derive: service {service!r} has no image:")
name, _, tag = image.partition(":")
tag = tag or "latest"

# environment: compose allows a list [K=V] or a map {K: V}; drop-test wants K=V.
env = svc.get("environment") or []
if isinstance(env, dict):
    env = [f"{k}={v}" for k, v in env.items()]

# command / entrypoint may be a string or a list.
def as_list(v):
    if not v:
        return []
    return v if isinstance(v, list) else [v]

# The granted cap set is what we validate: cap_add if the service declares one,
# else the Docker default set (what an unconfigured container carries).
DOCKER_DEFAULT_CAPS = [
    "CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID",
    "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL",
    "AUDIT_WRITE",
]
cap_add = [str(c).upper() for c in (svc.get("cap_add") or [])]
candidates = cap_add or DOCKER_DEFAULT_CAPS

run = {
    "user": str(svc.get("user", "") or ""),
    "command": as_list(svc.get("command")),
    "entrypoint": (svc.get("entrypoint") if isinstance(svc.get("entrypoint"), str) else ""),
    "network": str(svc.get("network_mode", "") or ""),
    "pid": str(svc.get("pid", "") or ""),
    "security_opt": [str(s) for s in (svc.get("security_opt") or [])],
    "mounts": [str(v) for v in (svc.get("volumes") or []) if isinstance(v, str)],
    "env": env,
}
spec = {
    "image": name, "tag": tag, "dimension": "capabilities",
    "fixed": [], "candidates": candidates, "run": run, "predicate": predicate,
}
print(yaml.safe_dump(spec, sort_keys=False))
PYEOF
rc=$?
[ $rc -eq 0 ] || { cat "$WORK/spec.yaml" >&2; exit "$rc"; }

echo "compose_derive: ${SERVICE} -> ${COMPOSE}; drop-testing its granted caps under its own invocation" >&2
PY="$PY" bash "$REPO/scripts/drop_test.sh" "$WORK/spec.yaml"
