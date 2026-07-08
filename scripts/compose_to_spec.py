#!/usr/bin/env python3
# Extract a compose service's run config into a drop_test.sh spec (YAML on stdout)
# and write its declared caps + build info to the given files. Pure transform (no
# docker), so it is unit-testable hermetically — see scripts/compose_derive_selftest.sh.
#
#   compose_to_spec.py <compose.yml> <service> <correctness> <declared_out> <build_out>
#
# Split out of compose_derive.sh so the compose->spec mapping — including the
# mount/tmpfs fidelity that decides whether cold-start caps (CHOWN/FOWNER/...) are
# exercised — is covered by a test, not just by live runs (#337).
import os, sys, json, re, yaml

compose, service, correctness, declared_out, build_out = sys.argv[1:6]
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

# The image to derive against. A service can pull an `image:` or `build:` a custom
# one (or both). When it builds, we build the ACTUAL deployed image and derive
# against that — it can differ from any base tag in security-relevant ways (e.g.
# a `COPY` that drops the base binary's file capabilities), which loose matching
# would miss. compose_derive.sh (bash) does the build; here we just resolve the
# context and hand back a local tag + no_pull.
image = svc.get("image")
build = svc.get("build")
no_pull = False
build_info = {}
if build is not None:
    no_pull = True
    if isinstance(build, str):
        ctx, dockerfile = os.path.normpath(os.path.join(compose_dir, build)), ""
    else:
        b = build or {}
        ctx = os.path.normpath(os.path.join(compose_dir, str(b.get("context", "."))))
        dockerfile = str(b.get("dockerfile", "") or "")
    if image:
        name, _, tag = image.partition(":"); tag = tag or "latest"
    else:
        name, tag = "csd-deploy-check-" + re.sub(r"[^a-z0-9_.-]", "-", service.lower()), "local"
    build_info = {"context": ctx, "dockerfile": dockerfile, "image": f"{name}:{tag}"}
elif image:
    name, _, tag = image.partition(":"); tag = tag or "latest"
else:
    sys.exit(f"compose_derive: service {service!r} has neither image: nor build:")
json.dump(build_info, open(build_out, "w"))

# An env value that is an unresolved compose variable reference (${VAR}, $VAR) is a
# secret/config the derive host deliberately does NOT have — replace it with a
# synthetic placeholder so config that validates the field can still load (Caddy,
# for one, refuses to start on a literal ${...}). Capability needs come from a
# service's STRUCTURE (listeners, mounts, user), not a token's value, so a
# placeholder doesn't change the derived minimum; a secret never touches the host.
PLACEHOLDER = "csdPlaceholder" + "0" * 26  # 40 chars, format-plausible for token-like fields
def sub_placeholders(s):
    return re.sub(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*", PLACEHOLDER, s)
env = svc.get("environment") or []
if isinstance(env, dict):
    env = [f"{k}={v}" for k, v in env.items()]
env = [f"{e.split('=',1)[0]}={sub_placeholders(e.split('=',1)[1])}" if "=" in e else e
       for e in map(str, env)]

def as_list(v):
    return [] if not v else (v if isinstance(v, list) else [v])

def tmpfs_targets(v):
    # compose `tmpfs:` is a path, a list of paths (short form), or a list of
    # {target: ...} mounts (long form). Return the target paths.
    out = []
    for t in as_list(v):
        if isinstance(t, str):
            out.append(t.split(":")[0])          # "/data" (drop any :size=... opts)
        elif isinstance(t, dict) and t.get("target"):
            out.append(str(t["target"]))
    return out

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
# volumes (a bare name, no `/`) are docker-managed and kept (created empty). A
# source with an unresolved ${VAR}/$VAR (e.g. immich's ${DB_DATA_LOCATION} data
# dir, absent from .env on the derive host) is KEPT: drop_test.sh turns it into a
# fresh, foreign-owned ephemeral dir per trial, so a service that chowns/chmods its
# data dir on first boot (postgres) exercises those startup caps as it would on a
# real first deploy — instead of falling back to the image's pre-owned dir and
# under-deriving CHOWN/FOWNER.
mounts, skipped = [], []
for v in (svc.get("volumes") or []):
    if not isinstance(v, str):
        continue
    rv = resolve_mount(str(v))
    src = rv.split(":")[0]
    if "$" in src or "/" not in src or os.path.exists(src):
        mounts.append(rv)
    else:
        skipped.append(rv)
if skipped:
    print(f"compose_derive: skipped {len(skipped)} bind mount(s) with no source on "
          f"this derive host (not cap-relevant): {skipped}", file=sys.stderr)

# tmpfs + read_only are load-bearing for cap fidelity (#337): a `tmpfs:` mount
# replaces a path the image may pre-own with a FRESH, root-owned dir, so a service
# that chowns its data dir on boot (valkey /data) actually exercises CHOWN — the
# same reason an unresolved-${VAR} bind is staged fresh above. Dropping them (as
# this script used to) let /data fall back to the image's pre-owned dir, chown
# became a no-op, and CHOWN derived falsely-removable.
run = {
    "user": str(svc.get("user", "") or ""),
    "command": as_list(svc.get("command")),
    "entrypoint": (svc.get("entrypoint") if isinstance(svc.get("entrypoint"), str) else ""),
    "network": str(svc.get("network_mode", "") or ""),
    "pid": str(svc.get("pid", "") or ""),
    "security_opt": [str(s) for s in (svc.get("security_opt") or [])],
    "mounts": mounts,
    "tmpfs": tmpfs_targets(svc.get("tmpfs")),
    "read_only": bool(svc.get("read_only", False)),
    "env": env,
}
json.dump({"cap_add": cap_add, "cap_drop": cap_drop}, open(declared_out, "w"))
spec = {
    "image": name, "tag": tag, "dimension": "capabilities",
    "fixed": [], "candidates": candidates, "run": run, "correctness": correctness,
}
if no_pull:
    spec["no_pull"] = True
print(yaml.safe_dump(spec, sort_keys=False))
