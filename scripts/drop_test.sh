#!/usr/bin/env bash
# csd drop-test producer (compose-lint#360): derive a *required* minimum by
# drop-and-restart, and emit structured evidence.
#
# This is csd's EXPERIMENT layer, complementary to its OBSERVATION layer (the ig
# gadgets). It is not a gadget and uses no eBPF of its own: for each candidate it
# launches the container WITHOUT that element, restarts, and runs a per-image
# correctness check. Observation answers "was it exercised"; drop-test answers
# "is it required" — the only way to catch startup-time requirements (a root->user
# privilege drop's SETUID/SETGID, a socket dir's tmpfs) that attach-window
# observation is blind to.
#
# Emits JSON to stdout:
#   {image, tag, digest, dimension, minimum:[...],
#    run_config:{user,command,entrypoint,network,pid,devices,security_opt,mounts,env},
#    checks:[{removed,required,observed}]}
# where `minimum` = every candidate found required (a non-empty `fixed` is
# rejected — see below), and
# `run_config` is the invocation the minimum was derived under — the orthogonal
# run context a consumer diffs a target service against (a divergent `user:` or
# mount can change the minimum, so the profile is only valid for this context).
#
# candidate vs fixed — EVERYTHING the container is granted is a `candidate`
# (drop-tested for necessity). A non-empty `fixed` is REJECTED (exit 5): under
# leave-one-out a truly-required element is always provable as a candidate (it is
# present during every other element's trial; its own trial removes it and breaks
# correctness), so `fixed` never buys test validity — it only means "granted,
# emitted in the minimum, but NEVER tested." We have found no case that couldn't be
# handled honestly instead, and `fixed` hides two failures at once: an over-grant
# (netdata's SYS_ADMIN was removable) AND a too-weak correctness check (a candidate
# you can't prove needed is the check telling you it can't see the breakage —
# `fixed` silences that). The two honest valves when the drop-test can't prove an
# element needed:
#   1. STRENGTHEN THE CORRECTNESS CHECK so it becomes a testable candidate. "Observed
#      used" is not a reason to keep a cap: observation sees a syscall fire, not that
#      the cap gated it (a setuid-root helper like netdata's apps.plugin makes the
#      syscall as root regardless). "Collects data" must mean NON-ZERO, not merely
#      non-null: a denied collector reports 0 (see the netdata correctness check).
#      And the check must exercise real FUNCTION, never a /health|/healthz|liveness
#      endpoint — those stay green while the process is up (homepage's
#      /api/healthcheck returns 200 while / 500s on an unwritable config). A
#      readiness endpoint is fine only as a wait-gate before a real
#      request/uid/data assertion, not as the assertion itself.
#   2. If it genuinely can't be exercised in the observation window (workload
#      coverage), that's a CRITERIA-DOC caveat + low confidence, NOT an untested
#      entry laundered into the derived minimum.
# NOTE: this is the caps/paths `fixed` LIST. The invocation + sibling-dimension
# context you derive UNDER — `run.read_only`/`run.tmpfs`/`run.user`/`run.mounts` —
# IS legitimately held constant; that's expressed via `run.*`, not `fixed`.
#
# IN-STACK (dependent-tier) derivation — `deps:`. A target's capability minimum is
# intrinsic to its OWN init/privilege-drop/bind syscalls (composition-independent),
# but VERIFYING it needs the target to actually function — and a dependent tier
# (mc-backup needs minecraft's RCON; an app needs its DB) cannot function in
# isolation, so a standalone correctness check can't distinguish a real requirement
# from a dependency-down failure. A `deps:` list brings the target's dependencies up
# ONCE on a shared network (reachable by their `name`), holds them up across every
# trial, and tears them down at the end; only the TARGET is recreated per trial with
# the candidate dropped. The correctness check then drives the target's REAL,
# stack-backed function. `run.volumes_from: [<dep>]` shares a dep's volume with the
# target (e.g. a backup sidecar reading the app's data dir). A spec with no `deps:`
# is a leaf and runs exactly as before.
#   deps:
#     - name: minecraft            # the hostname the target reaches it by
#       image: itzg/minecraft-server
#       tag: latest
#       env: [EULA=TRUE, ...]
#       ready: mc-monitor status --host localhost --port 25565   # exec'd in the dep
#
#   sudo? no — needs only docker; the correctness check may need more.
#   PY=python3 scripts/drop_test.sh <spec.yaml>
#
# STAGING FIDELITY (csd#340). A cap's necessity is only as truthful as the mount
# STATE each trial reproduces. By default a mount whose source is absent here (a
# `${VAR}` data dir) is staged FRESH + EMPTY — faithful to a first deploy (a
# chown/chmod of the empty dir fires), but it UNDER-derives any cap exercised only
# against PRE-EXISTING, foreign-owned content (a migration's `chown -R` over a
# populated volume, a backup reader over another service's files) — that cap reads
# removable and a "safe to drop" breaks prod. `run.seed_mounts` closes that class:
# it stages a mount with pre-existing content owned by a foreign uid (+ a
# restrictive file mode) before each trial, so the populated-data cap
# (CHOWN/FOWNER/DAC_OVERRIDE) derives needed. Until a service uses seed_mounts,
# fresh-only staging under-derives this class for it. seed_mounts also reproduces
# the mount's permission MODE (dir_mode/file_mode), not just ownership (csd#340
# item 3): a cap driven by a restrictive mode — root writing into a foreign-owned
# 0700 dir needs DAC_OVERRIDE, where 0777 needs nothing — is otherwise missed too,
# since a fresh dir is created at the host umask, not the prod mode.
# A declared NAMED-VOLUME mount (a run.mounts source that is neither a path nor a
# ${VAR}) is passed through to docker's root-owned-EMPTY init by default, which
# UNDER-derives the CHOWN/DAC_OVERRIDE needed against a foreign-owned volume from a
# prior deploy (csd#340 item 4). Set run.worst_case_named_volumes: true to stage
# such mounts worst-case foreign-owned instead — OPT-IN, because defaulting it on
# would over-derive real root/self-owned named volumes into a false
# under_permissioned (deferred to the #340 confidence guard). Or pin the exact
# ownership/mode with run.seed_mounts when known.
# By contrast a service with NO mounts that mkdir+chowns a path on its own ROOTFS
# is inherently FAITHFUL (csd#340 item 6): the rootfs is fresh on every trial (a
# new container), so a real owner change fires and CHOWN derives correctly. The
# confidence guard must therefore NOT treat "no mounts" as "nothing to exercise" —
# a no-mount rootfs cold-start is high-confidence, not low.
# Beyond mount state, a cap can hinge on the KERNEL SYSCTL POSTURE (csd#340 item 5):
# NET_BIND_SERVICE for a low-port bind is needed only when
# net.ipv4.ip_unprivileged_port_start >= the port, but docker defaults it to 0 (all
# ports unprivileged), so the cap reads falsely-removable. run.sysctls pins the
# hardened posture (e.g. ip_unprivileged_port_start=1024) for the trial, and the
# posture is recorded in run_config so the profile is known to be valid only under it.
# CONFIDENCE GUARD (csd#340 capstone): the result carries a `fidelity` block
# ({guaranteed, unguaranteed_mounts}) for the capabilities dimension. It is false
# when a mount's worst-case initial state could NOT be reproduced — a ${VAR}
# fresh-vol (foreign-owned but EMPTY, no pre-existing foreign content) or a
# passed-through named volume (root-owned-empty). compose_verdict.py then SUPPRESSES
# a chown-class (CHOWN/FOWNER/DAC_OVERRIDE/DAC_READ_SEARCH/FSETID) drop for such a
# run — keeping the cap, low-confidence — rather than recommend a drop it cannot
# prove. Guaranteed cases (real/staged binds, seed_mounts, tmpfs, no-mount rootfs)
# are unaffected; the guard only ever makes a verdict MORE conservative.
#   run:
#     seed_mounts:
#       - target: /data          # mount point in the container
#         owner: "9999:9999"     # foreign uid:gid the seeded content is chowned to
#         file: secret           # optional pre-existing file created inside
#         content: "..."         # its contents (default a marker string)
#         dir_mode: "0755"       # optional; mount dir mode (default 0755)
#         file_mode: "0600"      # optional; seeded file mode (default 0600)
#         read_only: true        # optional; mount the fixture :ro (default false)
#         from_image: true       # optional; seed a WRITABLE COPY of the image's
#                                # existing content at `target` (default false)
#
# from_image seed_mounts are the primitive for a filesystem derivation of a
# service that REWRITES FILES IN ITS OWN MULTI-FILE CONFIG/LIB DIR at startup
# (forgejo's s6 scandir /etc/s6, rabbitmq's /etc/rabbitmq/conf.d, keycloak's
# quarkus lib): a plain tmpfs there SHADOWS the shipped content and a single
# seeded `file` can't preserve a tree, so a writable COPY of the image dir (with
# `owner` set to the service user) is the only faithful way. The derived tmpfs
# entry names the dir; the criteria doc notes it needs a writable copy, not an
# empty tmpfs.
#
# read_only seed_mounts double as a READ-ONLY CONFIG FIXTURE: seed the config
# file (file:/content:) at the path the service reads, mount it :ro, and the
# service runs off it without writing. This is what a filesystem derivation of a
# config-file-driven proxy needs — traefik/haproxy would otherwise have their
# config docker-cp'd or entrypoint-written into a writable /tmp, which under
# --read-only falsely derives a /tmp tmpfs a production read-only config mount
# would not need.
set -uo pipefail

SPEC="${1:?usage: drop_test.sh <spec.yaml>}"
PY="${PY:-python3}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
C="csd-drop-test-run"
WORK="$(mktemp -d)"
STAGED_ANY=""   # set when a fresh ephemeral volume was created (see run_and_test)
# In-stack (dependent-tier) derivation state: a target that depends on other
# services (a `deps:` list in the spec) needs them up to be exercised. They come up
# ONCE on a shared network, stay up across all trials, and are torn down here. A
# spec with no `deps:` sets neither and behaves exactly as before.
DEP_NET=""
declare -a DEP_NAMES=()
cleanup() {
  docker rm -f -v "$C" >/dev/null 2>&1   # -v: also drop the container's anonymous volumes
  # A fresh ephemeral volume can be chowned to the container's user (e.g. postgres
  # 999) during a run, leaving files under $WORK this host user can't remove.
  # Reclaim them via a root-in-container helper before rm.
  if [ -n "$STAGED_ANY" ] && [ -n "${IMAGE:-}" ]; then
    docker run --rm --user 0:0 -v "$WORK:/w" --entrypoint chown "${IMAGE}:${TAG}" \
      -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  fi
  local dn
  for dn in "${DEP_NAMES[@]:-}"; do [ -n "$dn" ] && docker rm -f -v "$dn" >/dev/null 2>&1; done
  [ -n "$DEP_NET" ] && docker network rm "$DEP_NET" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- parse spec (TSV; arrays are space/newline-joined, safe for caps/paths) ----
declare -A F
while IFS=$'\t' read -r k v; do F["$k"]="$v"; done < <("$PY" - "$SPEC" <<'PYEOF'
import sys, yaml, base64, json
s = yaml.safe_load(open(sys.argv[1])) or {}
run = s.get("run", {}) or {}
def line(k, v): print(f"{k}\t{v}")
line("IMAGE", s["image"]); line("TAG", s["tag"]); line("DIM", s["dimension"])
line("CORRECTNESS", s["correctness"]); line("BASE_FS", s.get("base_fs", ""))
# health_port: a host-networked service (network: host) pins a fixed host port;
# declare it so the harness can refuse to run when a foreign instance already
# holds it (it would answer the correctness check and silently corrupt the drop-test).
line("HEALTH_PORT", str(s.get("health_port", "") or ""))
# no_pull: the image is already present locally (e.g. a compose `build:` image
# compose_derive.sh built for us) and has no registry counterpart, so skip the
# pull and take the digest from the local image id.
line("NO_PULL", "true" if s.get("no_pull") else "")
line("RUN_PID", run.get("pid", "")); line("RUN_NET", run.get("network", ""))
line("RUN_USER", run.get("user", ""))
line("RUN_ENTRYPOINT", run.get("entrypoint", ""))
line("FIXED", " ".join(map(str, s.get("fixed", []))))
line("CANDIDATES", " ".join(map(str, s.get("candidates", []))))
line("ENV", "\v".join(run.get("env", [])))
# run.sysctls: kernel sysctls (`key=value`) the trial container is pinned under, so
# a cap whose necessity depends on the host posture derives faithfully instead of
# under docker's loose default (csd#340 item 5: NET_BIND_SERVICE hinges on
# net.ipv4.ip_unprivileged_port_start, which docker defaults to 0 → any port
# unprivileged → the cap reads falsely-removable). Recorded in run_config so the
# derived profile carries the posture it is valid under.
line("SYSCTLS", "\v".join(run.get("sysctls", [])))
line("MOUNTS", "\v".join(run.get("mounts", [])))
line("SECOPT", "\v".join(run.get("security_opt", [])))
line("DEVICES", "\v".join(run.get("devices", [])))
# Sibling-dimension context: a non-fs dimension (e.g. capabilities) is derived
# under the filesystem dimension's RECOMMENDED values, since the profile is
# applied as a unit. run.read_only + run.tmpfs carry those, applied for any
# dimension (postgres caps need CHOWN only because the read_only+tmpfs socket dir
# must be chowned — invisible when caps are derived on a writable fs).
line("RUN_READONLY", "true" if run.get("read_only") else "")
line("RUN_TMPFS", "\v".join(run.get("tmpfs", [])))
# Sibling-dimension context, capabilities direction: run.cap_add derives a
# NON-caps dimension under the capabilities dimension's RECOMMENDATION
# (cap_drop: ALL + exactly these cap_adds) — the caps mirror of
# run.read_only/run.tmpfs. netdata's fs derivation is the motivating case: its
# correctness check requires per-process metrics, which require SYS_PTRACE
# granted; under docker's default cap set the fs minimum would be derived under
# a grant the profile itself does not recommend. Rejected for
# dimension=capabilities (a caps trial owns its cap set via candidates).
line("RUN_CAPADD", "\v".join(run.get("cap_add", [])))
# features: the per-dimension feature LEDGER (#206 slice 3b; compose-lint profile
# schema 1.6 / ADR-017 §13) — which privilege-relevant features the workload did
# (driven: true + evidence) and did not (driven: false + the honest reason)
# drive. Human-authored in the spec; passed through VERBATIM into the evidence
# JSON (the catalog's pinned contract is the validation gate). base64-JSON over
# the TSV protocol so free-text `why` strings survive.
line("FEATURES_B64", base64.b64encode(json.dumps(s.get("features", []) or []).encode()).decode())
# command may be a YAML list or a bare string (compose accepts both).
cmd = run.get("command", [])
line("CMD", "\v".join(cmd if isinstance(cmd, list) else [cmd]))
# In-stack: share a dependency's volumes with the target (e.g. a backup sidecar
# reading the app's data dir). Values are dep NAMEs (mapped to csd-dep-<name>).
line("VOLUMES_FROM", "\v".join(run.get("volumes_from", [])))
# seed_mounts (csd#340 item 2): stage a mount with PRE-EXISTING, foreign-owned
# content before each trial, so a cap exercised only against pre-existing data (a
# chown -R / read over a populated volume) derives faithfully instead of being
# masked by the fresh-empty-dir staging. Emit each field on its OWN key (like
# deps) so an empty field can't shift the record under bash `read`.
# worst_case_named_volumes (csd#340 item 4): OPT-IN. When true, a declared
# named-volume mount (a run.mounts source that is neither a path nor a ${VAR}) is
# staged worst-case foreign-owned instead of passed through to docker's
# root-owned-empty init. Default OFF: real services can legitimately run root/
# self-owned named volumes, and defaulting this on would over-derive them into a
# false under_permissioned — so it stays opt-in until the #340 confidence guard can
# mark a fidelity-unguaranteed drop low-confidence rather than red a deploy-check.
line("WCNV", "true" if run.get("worst_case_named_volumes") else "")
seeds = run.get("seed_mounts", []) or []
line("SEED_COUNT", str(len(seeds)))
for i, sd in enumerate(seeds):
    line(f"SEED_{i}_TARGET", sd["target"])
    line(f"SEED_{i}_OWNER", str(sd.get("owner", "9999:9999")))
    line(f"SEED_{i}_DIRMODE", str(sd.get("dir_mode", "0755")))
    line(f"SEED_{i}_FILE", str(sd.get("file", "")))
    line(f"SEED_{i}_FILEMODE", str(sd.get("file_mode", "0600")))
    # base64 so multi-line content (a seeded CONFIG file) survives the TSV
    # line protocol — a raw newline would be mis-read as a new key.
    line(f"SEED_{i}_CONTENT_B64",
         base64.b64encode(str(sd.get("content", "csd-preexisting-foreign-owned")).encode()).decode())
    # read_only: mount the staged fixture :ro. Turns seed_mounts into a read-only
    # CONFIG-fixture mechanism (a config file injected at a path the service reads
    # but never writes) as well as its original foreign-owned-content role — so a
    # filesystem derivation of a config-file-driven service (traefik/haproxy) does
    # not have to write the config to a writable /tmp, which would falsely require
    # a /tmp tmpfs a read-only config mount in production would not.
    line(f"SEED_{i}_RO", "true" if sd.get("read_only") else "")
    # from_image: seed the staging with a WRITABLE COPY of the image's existing
    # content at `target` (all files, preserving structure), then mount it
    # writable. This is the primitive for filesystem derivation of a service that
    # REWRITES FILES IN ITS OWN MULTI-FILE CONFIG/LIB DIR at startup (forgejo's
    # s6 scandir /etc/s6, rabbitmq's /etc/rabbitmq/conf.d, keycloak's quarkus
    # lib): a plain tmpfs there SHADOWS the shipped content (breaking the service)
    # and a single seeded `file` cannot preserve a multi-file tree, so read-only
    # was previously infeasible. A from_image seed gives the service a writable
    # copy of its own config dir with the content intact.
    line(f"SEED_{i}_FROMIMAGE", "true" if sd.get("from_image") else "")
# Dependencies to bring up before the drop-test. Emit each field on its OWN key
# (DEP_<i>_*), not one packed record: bash `read` treats \v as whitespace and would
# collapse an empty field (e.g. no command override), shifting every later field.
deps = s.get("deps", []) or []
line("DEP_COUNT", str(len(deps)))
for i, d in enumerate(deps):
    dcmd = d.get("command", "")
    if isinstance(dcmd, list): dcmd = " ".join(map(str, dcmd))
    line(f"DEP_{i}_NAME", d["name"]); line(f"DEP_{i}_IMAGE", d["image"])
    line(f"DEP_{i}_TAG", d.get("tag", "latest")); line(f"DEP_{i}_CMD", dcmd)
    line(f"DEP_{i}_READY", d.get("ready", ""))
    line(f"DEP_{i}_ENV", "\v".join(map(str, d.get("env", []))))
line("DEP_READY_TIMEOUT", str(s.get("dep_ready_timeout", 180)))
PYEOF
)
IFS=' ' read -ra FIXED <<<"${F[FIXED]}"
IFS=' ' read -ra CANDIDATES <<<"${F[CANDIDATES]}"

# Reject a non-empty `fixed` (see the header): every granted element must be a
# drop-tested `candidate`. A `fixed` element is granted and emitted in the minimum
# but never tested — an assertion masquerading as a derivation. Fail fast (before
# any docker work) so the spec author is pushed to the honest valve: a stronger
# correctness check (making it a testable candidate), or — for a genuine
# workload-coverage gap — a criteria-doc caveat + low confidence.
_fixed_nonempty=""
for _f in "${FIXED[@]}"; do [ -n "$_f" ] && _fixed_nonempty=1; done
if [ -n "$_fixed_nonempty" ]; then
  {
    echo "drop_test: spec has a non-empty 'fixed' [${FIXED[*]}] — not allowed."
    echo "  Every granted element must be a 'candidate' (drop-tested for necessity);"
    echo "  a 'fixed' element is emitted in the minimum but never tested. If the"
    echo "  drop-test can't prove one needed, strengthen the correctness check so it"
    echo "  becomes a testable candidate; if it truly can't be exercised in the"
    echo "  observation window, record it as a criteria-doc caveat + low confidence,"
    echo "  not a fixed (untested) minimum entry."
  } >&2
  exit 5
fi
IFS=$'\v' read -ra RUN_CAPADD <<<"${F[RUN_CAPADD]}"
# run.cap_add is sibling-dimension context for NON-caps dimensions only: a
# capabilities spec expresses its grant via candidates (drop-tested), so a
# run.cap_add there would be an untested grant — the same laundering `fixed`
# is rejected for. Fail fast, before any docker work.
_capadd_nonempty=""
for _c in "${RUN_CAPADD[@]}"; do [ -n "$_c" ] && _capadd_nonempty=1; done
if [ -n "$_capadd_nonempty" ] && [ "${F[DIM]}" = capabilities ]; then
  {
    echo "drop_test: spec has run.cap_add [${RUN_CAPADD[*]}] with dimension=capabilities — not allowed."
    echo "  run.cap_add carries the capabilities dimension's recommendation into a"
    echo "  NON-caps derivation (cap_drop:ALL + these adds). A capabilities spec"
    echo "  must express every granted cap as a 'candidate' so it is drop-tested."
  } >&2
  exit 5
fi
IFS=$'\v' read -ra RUN_ENV <<<"${F[ENV]}"
IFS=$'\v' read -ra RUN_SYSCTLS <<<"${F[SYSCTLS]}"
IFS=$'\v' read -ra RUN_MOUNTS <<<"${F[MOUNTS]}"
IFS=$'\v' read -ra RUN_SECOPT <<<"${F[SECOPT]}"
IFS=$'\v' read -ra RUN_DEVICES <<<"${F[DEVICES]}"
IFS=$'\v' read -ra RUN_TMPFS <<<"${F[RUN_TMPFS]}"
IFS=$'\v' read -ra RUN_CMD <<<"${F[CMD]}"
IFS=$'\v' read -ra RUN_VOLUMES_FROM <<<"${F[VOLUMES_FROM]}"
# \v-joined dep alias names, for the evidence run_config.deps (see the emit below).
DEPS_CSV=""; for (( _di=0; _di<${F[DEP_COUNT]:-0}; _di++ )); do DEPS_CSV+="${F[DEP_${_di}_NAME]}"$'\v'; done

# Confidence-guard input (csd#340 capstone): classify each mount's initial-state
# fidelity. A chown-class cap (CHOWN/FOWNER/DAC_OVERRIDE/DAC_READ_SEARCH/FSETID)
# derived REMOVABLE is only trustworthy if every path the container chowns/writes
# was in its worst-case initial state during the run. Two mount kinds are NOT:
#   - a ${VAR} fresh-vol (foreign-owned but EMPTY — reproduces a first deploy, not
#     a prior deploy's pre-existing foreign CONTENT), and
#   - a passed-through named volume (root-owned-empty).
# under either, a removable chown-class verdict is low-confidence (the #337 / item-2
# blind spot). Binds (real content + ownership reproduced), seed_mounts /
# worst_case_named_volumes (staged worst-case), tmpfs (fresh in prod too), and the
# no-mount rootfs cold-start (fresh every trial — item 6) are all GUARANTEED.
# Emitted as run-level `fidelity` so compose_verdict.py can suppress the drop.
UNGUARANTEED_MOUNTS=()
for _m in "${RUN_MOUNTS[@]:-}"; do
  [ -n "$_m" ] || continue
  _msrc="${_m%%:*}"; _mtgt="${_m#*:}"
  if [[ "$_msrc" == *'$'* ]]; then
    UNGUARANTEED_MOUNTS+=("$_mtgt")                                   # ${VAR} fresh-vol
  elif [[ "$_msrc" != /* && "$_msrc" != .* ]] && [ "${F[WCNV]}" != true ]; then
    UNGUARANTEED_MOUNTS+=("$_mtgt")                                   # passthrough named volume
  fi
done
UNGUARANTEED_CSV=""; for _u in "${UNGUARANTEED_MOUNTS[@]:-}"; do [ -n "$_u" ] && UNGUARANTEED_CSV+="$_u"$'\v'; done

IMAGE="${F[IMAGE]}"; TAG="${F[TAG]}"; DIM="${F[DIM]}"
CORRECTNESS="${REPO}/${F[CORRECTNESS]}"
DOCKER_GID="$(getent group docker | cut -d: -f3)"

if [ "${F[NO_PULL]}" = true ]; then
  docker image inspect "${IMAGE}:${TAG}" >/dev/null 2>&1 || { echo "no_pull set but ${IMAGE}:${TAG} is not present locally" >&2; exit 2; }
else
  docker pull -q "${IMAGE}:${TAG}" >/dev/null 2>&1 || { echo "pull failed: ${IMAGE}:${TAG}" >&2; exit 2; }
fi
# A locally-built image has no RepoDigests (never pushed/pulled) — fall back to the
# image id, so the evidence still records a content identifier for what ran.
DIGEST="$(docker inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "${IMAGE}:${TAG}" | sed -E 's/.*@//')"

# Numeric run-as uid[:gid], if the spec pins one (a compose `user:`). When set, a
# bind-mounted DIRECTORY has to be owned by that uid for the run to be faithful:
# on a real deployment the service runs AS the mount's owner (e.g. homepage runs
# as 1000:1000 and owns ./config), so it never needs DAC_OVERRIDE/FOWNER to use
# it. A fresh git clone owns ./config as the CLONING user instead, so a
# container-as-1000 gets EACCES and never becomes ready. The fix is to reproduce
# the OWNERSHIP, not loosen perms: making the mount world-writable would leave it
# owned by the wrong uid and so induce a spurious FOWNER/CHOWN requirement (the
# derived minimum is wrong either way). So stage a throwaway copy and chown it to
# the run uid — using the service image itself as a root-in-container helper, so
# no host root is needed and drop_test stays sudo-free.
RUN_UID=""
case "${F[RUN_USER]}" in
  '' | *[!0-9:]* ) : ;;             # unset, or a user NAME (can't map to a uid here)
  * ) RUN_UID="${F[RUN_USER]}" ;;   # numeric uid or uid:gid
esac
STAGE_SEQ=0

# prep_mount <src:tgt[:opts]> <stageroot>  -> echoes the -v value docker should use.
# For a bind-mounted directory under a numeric run uid, stages a private copy and
# chowns it to that uid so the run is faithful; everything else (named volumes,
# file binds, or no run uid) passes through untouched. The copy is chmod o+rwX'd
# as well so the (differently-owned) host user can still clean up $WORK on exit;
# that bit is invisible to the container, which uses the mount as its owner.
prep_mount() {
  local spec="$1" stageroot="$2"
  local src="${spec%%:*}" rest="${spec#*:}"     # rest = tgt[:opts]
  if [ -z "$RUN_UID" ] || [[ "$src" != */* ]] || [ ! -d "$src" ]; then
    printf '%s' "$spec"; return
  fi
  local dst="$stageroot/$(printf '%s' "$src" | tr '/' '_')"
  mkdir -p "$stageroot"
  cp -a "$src" "$dst" 2>/dev/null || { printf '%s' "$spec"; return; }
  if ! docker run --rm --user 0:0 --entrypoint sh -v "$dst:/csd-mnt" "${IMAGE}:${TAG}" \
        -c "chown -R ${RUN_UID} /csd-mnt && chmod -R o+rwX /csd-mnt" >/dev/null 2>&1; then
    echo "drop_test: could not chown staged bind ${src} to uid ${RUN_UID} (image lacks sh/chown?); using it un-owned" >&2
  fi
  printf '%s' "$dst:$rest"
}

# run_and_test <active element...>  -> sets PASS=0/1, OBS=<last correctness-check line>
run_and_test() {
  docker rm -f -v "$C" >/dev/null 2>&1   # -v: also drop the container's anonymous volumes
  local args=(-d --name "$C")
  [ -n "${F[RUN_PID]}" ] && args+=(--pid "${F[RUN_PID]}")
  # In-stack: the target joins the deps' shared network (so it resolves them by
  # name), which overrides any run.network; a leaf uses run.network as before.
  if [ -n "$DEP_NET" ]; then
    args+=(--network "$DEP_NET")
    local vf; for vf in "${RUN_VOLUMES_FROM[@]}"; do [ -n "$vf" ] && args+=(--volumes-from "csd-dep-$vf"); done
  elif [ -n "${F[RUN_NET]}" ]; then
    args+=(--network "${F[RUN_NET]}")
  fi
  [ -n "${F[RUN_USER]}" ] && args+=(--user "${F[RUN_USER]}")
  [ -n "${F[RUN_ENTRYPOINT]}" ] && args+=(--entrypoint "${F[RUN_ENTRYPOINT]}")
  # Each candidate trial gets a fresh staging root, so a container writing into a
  # staged bind (e.g. homepage's config/logs) can't leak state into the next trial.
  local stageroot="$WORK/stage.$STAGE_SEQ"; STAGE_SEQ=$((STAGE_SEQ + 1))
  local m vseq=0
  for m in "${RUN_MOUNTS[@]}"; do
    [ -n "$m" ] || continue
    if [[ "${m%%:*}" == *'$'* ]]; then
      # A mount whose source is an unresolved ${VAR}/$VAR is a host path absent
      # here (a data dir set from .env). Give it a FRESH empty dir per trial, owned
      # by this (non-container) user — so a service that chowns/chmods its data dir
      # on first boot (postgres) exercises CHOWN/FOWNER as it would on a real first
      # deploy, instead of falling back to the image's pre-owned dir and masking
      # those startup caps. Fresh per trial so an initialized dir can't leak into
      # the next iteration.
      local tgt="${m#*:}" fv="$stageroot/freshvol.$vseq"; vseq=$((vseq + 1))
      mkdir -p "$fv"; STAGED_ANY=1; args+=(-v "$fv:$tgt")
    elif [ "${F[WCNV]}" = true ] && [[ "${m%%:*}" != /* && "${m%%:*}" != .* ]]; then
      # A NAMED-VOLUME mount (source is neither an absolute/relative path nor a
      # ${VAR}), and run.worst_case_named_volumes is set. Docker would create it
      # root-owned-EMPTY on first use — but a real deployment's named volume can be
      # foreign-owned/populated (csd#340 item 4), so root-owned-empty UNDER-derives
      # any cap needed to use a foreign-owned volume (a root write into it needs
      # DAC_OVERRIDE; an ownership repair needs CHOWN) — the same masking class as
      # #337. Stage the WORST CASE instead: a fresh dir per trial chowned to a
      # foreign uid, mounted in place of the docker named volume (so no untrusted
      # root-owned-empty volume is ever consulted, and nothing persists across
      # trials/runs). OPT-IN (not the default) — see the WCNV note in the parser and
      # the header; pin exact prod ownership/mode with run.seed_mounts when known.
      local ntgt="${m#*:}" nv="$stageroot/namedvol.$vseq"; vseq=$((vseq + 1))
      mkdir -p "$nv"; STAGED_ANY=1
      docker run --rm --user 0:0 --entrypoint sh -v "$nv:/csd-nv" "${IMAGE}:${TAG}" \
        -c "chown 9999:9999 /csd-nv" >/dev/null 2>&1 \
        || echo "drop_test: could not stage named volume ${m%%:*} worst-case foreign-owned (image lacks sh/chown?); using it un-owned" >&2
      args+=(-v "$nv:$ntgt")
    else
      args+=(-v "$(prep_mount "$m" "$stageroot")")
    fi
  done
  # seed_mounts (csd#340 item 2): stage a mount with PRE-EXISTING, foreign-owned
  # content. The default fresh-empty-dir staging masks any cap only exercised
  # against already-populated, other-uid data (a migration's `chown -R`, a backup
  # reader over another service's files, a restart that repairs existing state) —
  # the inverse of the #337 fresh-masked-as-pre-owned bug. Each trial gets its own
  # freshly-seeded copy (under the per-trial stageroot) so state can't leak. The
  # chown-to-a-foreign-uid + restrictive file mode are applied via a root-in-
  # container helper (the target image), keeping drop_test sudo-free; STAGED_ANY
  # arms the cleanup reclaim that chowns $WORK back to this host user on exit.
  local si
  for (( si=0; si<${F[SEED_COUNT]:-0}; si++ )); do
    local starget="${F[SEED_${si}_TARGET]}" sowner="${F[SEED_${si}_OWNER]}"
    local sdirmode="${F[SEED_${si}_DIRMODE]}" sfile="${F[SEED_${si}_FILE]}"
    local sfilemode="${F[SEED_${si}_FILEMODE]}" scontent_b64="${F[SEED_${si}_CONTENT_B64]}"
    local sro="${F[SEED_${si}_RO]:-}" sfromimg="${F[SEED_${si}_FROMIMAGE]:-}"
    local sdir="$stageroot/seed.$si"
    mkdir -p "$sdir"
    STAGED_ANY=1
    # from_image: copy the image's existing content at $starget into the staging
    # (so a service that rewrites its own multi-file config/lib dir gets a
    # WRITABLE copy with the shipped content intact, instead of a shadowing tmpfs).
    if [ -n "$sfromimg" ]; then
      docker run --rm --user 0:0 --entrypoint sh -v "$sdir:/csd-seed" "${IMAGE}:${TAG}" -c \
        "cp -a ${starget}/. /csd-seed/ 2>/dev/null || true" >/dev/null 2>&1 \
        || echo "drop_test: could not copy image dir ${starget} into the writable seed (image lacks sh/cp?)" >&2
    fi
    [ -n "$sfile" ] && printf '%s' "$scontent_b64" | base64 -d > "$sdir/$sfile"
    if ! docker run --rm --user 0:0 --entrypoint sh -v "$sdir:/csd-seed" "${IMAGE}:${TAG}" -c \
          "chown -R ${sowner} /csd-seed && chmod ${sdirmode} /csd-seed${sfile:+ && chmod ${sfilemode} /csd-seed/${sfile}}" >/dev/null 2>&1; then
      echo "drop_test: could not seed foreign-owned content for ${starget} (image lacks sh/chown?); using it un-owned" >&2
    fi
    # read_only seed -> mount :ro (a read-only config fixture); else writable (the
    # foreign-owned-content case that tests chown-class caps).
    args+=(-v "$sdir:$starget${sro:+:ro}")
  done
  local so; for so in "${RUN_SECOPT[@]}"; do [ -n "$so" ] && args+=(--security-opt "$so"); done
  # Pin the kernel sysctl posture the caps are derived under (item 5): a namespaced
  # net.* sysctl (e.g. ip_unprivileged_port_start=1024) makes a low-port bind need
  # NET_BIND_SERVICE, instead of docker's loose default (0) hiding it as removable.
  local sc; for sc in "${RUN_SYSCTLS[@]}"; do [ -n "$sc" ] && args+=(--sysctl "$sc"); done
  local dv; for dv in "${RUN_DEVICES[@]}"; do [ -n "$dv" ] && args+=(--device "$dv"); done
  local e; for e in "${RUN_ENV[@]}"; do [ -n "$e" ] && args+=(-e "${e/__DOCKER_GID__/$DOCKER_GID}"); done
  # run.tmpfs: fixed writable dirs the container needs to run that are NOT part of
  # this dimension's derived output, so never counted in the tmpfs minimum. Two
  # uses: a sibling dimension's recommended tmpfs (deriving caps under the fs
  # read_only+tmpfs, so the minimum holds when the whole profile is applied), and
  # a stand-in for a persistent VOLUME the real deployment provides (homepage's
  # /app/config). Applied for every dimension.
  local ft; for ft in "${RUN_TMPFS[@]}"; do [ -n "$ft" ] && args+=(--tmpfs "$ft"); done
  # run.read_only derives a NON-fs dimension under the fs dimension's read_only
  # recommendation; the fs dimension supplies its own --read-only via base_fs.
  if [ "$DIM" != filesystem ]; then
    [ "${F[RUN_READONLY]}" = true ] && args+=(--read-only)
  fi
  # run.cap_add: derive a NON-caps dimension under the capabilities dimension's
  # recommendation (cap_drop:ALL + exactly these adds) — the caps mirror of
  # run.read_only above. Guarded to non-caps dims at parse time.
  if [ "$DIM" != capabilities ] && [ -n "$_capadd_nonempty" ]; then
    args+=(--cap-drop ALL)
    local rc; for rc in "${RUN_CAPADD[@]}"; do [ -n "$rc" ] && args+=(--cap-add "$rc"); done
  fi
  if [ "$DIM" = capabilities ]; then
    args+=(--cap-drop ALL); local c; for c in "$@"; do args+=(--cap-add "$c"); done
  elif [ "$DIM" = filesystem ]; then
    [ "${F[BASE_FS]}" = read_only ] && args+=(--read-only)
    local t; for t in "$@"; do args+=(--tmpfs "$t"); done
  fi
  [ -n "${DROP_TEST_DEBUG:-}" ] && printf 'DEBUG docker run %s %s %s\n' "${args[*]}" "${IMAGE}:${TAG}" "${RUN_CMD[*]}" >&2
  # RUN_CMD (the spec's command override) is positional, so it follows the image.
  docker run "${args[@]}" "${IMAGE}:${TAG}" ${RUN_CMD[@]+"${RUN_CMD[@]}"} >/dev/null 2>&1
  # Assert the container actually came up before probing. Otherwise a start
  # failure (bad config; or, under --network host, the service failing to bind
  # its already-taken port) surfaces only as an opaque correctness-check failure — and
  # for a candidate drop that would be misattributed to the removed element.
  local up="" i
  for i in 1 2 3 4 5 6; do
    up="$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null || echo false)"
    [ "$up" = true ] && break
    sleep 0.5
  done
  if [ "$up" != true ]; then
    PASS=0; OBS="container failed to start: $(docker logs "$C" 2>&1 | grep -v '^[[:space:]]*$' | tail -1)"
    return
  fi
  DROP_TEST_CONTAINER="$C" bash "$CORRECTNESS" >"$WORK/pred.out" 2>&1 && PASS=1 || PASS=0
  OBS="$(grep -v '^[[:space:]]*$' "$WORK/pred.out" | tail -1)"
}

# bring_up_deps: start every `deps:` entry on a shared network (reachable by its
# name), wait for its `ready` check, and leave them up for the whole run. Fails
# loudly (exit 6) if a dep can't start or never becomes ready — so a
# dependency-down state never masquerades as a target capability requirement.
bring_up_deps() {
  local n="${F[DEP_COUNT]:-0}"
  [ "$n" != 0 ] || return 0
  DEP_NET="csd-drop-net-$$"
  docker network create "$DEP_NET" >/dev/null 2>&1 || { echo "could not create network $DEP_NET" >&2; exit 6; }
  local i dname dimage dtag dcmd dready
  for (( i=0; i<n; i++ )); do
    dname="${F[DEP_${i}_NAME]}"; dimage="${F[DEP_${i}_IMAGE]}"; dtag="${F[DEP_${i}_TAG]}"
    dcmd="${F[DEP_${i}_CMD]}"; dready="${F[DEP_${i}_READY]}"
    local cname="csd-dep-$dname"
    docker rm -f -v "$cname" >/dev/null 2>&1
    local dargs=(-d --name "$cname" --network "$DEP_NET" --network-alias "$dname")
    local -a evs=(); IFS=$'\v' read -ra evs <<<"${F[DEP_${i}_ENV]}"
    local ev; for ev in "${evs[@]}"; do [ -n "$ev" ] && dargs+=(-e "$ev"); done
    docker pull -q "$dimage:$dtag" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086  # dcmd is an optional whitespace-split command override
    docker run "${dargs[@]}" "$dimage:$dtag" $dcmd >/dev/null 2>&1 || { echo "dep '$dname' failed to start" >&2; exit 6; }
    DEP_NAMES+=("$cname")
    if [ -n "$dready" ]; then
      local dl=$((SECONDS + ${F[DEP_READY_TIMEOUT]}))
      until docker exec "$cname" sh -c "$dready" >/dev/null 2>&1; do
        (( SECONDS >= dl )) && { echo "dep '$dname' never became ready in ${F[DEP_READY_TIMEOUT]}s: $(docker logs "$cname" 2>&1 | tail -1)" >&2; exit 6; }
        [ "$(docker inspect -f '{{.State.Running}}' "$cname" 2>/dev/null)" = true ] || { echo "dep '$dname' exited: $(docker logs "$cname" 2>&1 | tail -1)" >&2; exit 6; }
        sleep 2
      done
    fi
  done
}

# --- preflight: refuse to run if a foreign instance already holds the service
# port. With network: host the port is host-wide, so a stale/leftover container
# (or running this on a host that already serves the image) would answer the
# correctness check and silently grade the WRONG container. We only ever run a single
# container ($C, rm'd each iteration), so before we start it the port must be free.
if [ -n "${F[HEALTH_PORT]}" ] && (exec 3<>"/dev/tcp/127.0.0.1/${F[HEALTH_PORT]}") 2>/dev/null; then
  exec 3>&- 3<&-
  echo "port ${F[HEALTH_PORT]} is already in use before start — a foreign instance would pollute the drop-test; stop it and retry" >&2
  exit 4
fi

# --- bring up dependencies (in-stack derivation); no-op for a leaf spec
bring_up_deps

# --- baseline: full candidate set must be correct (else config isn't representative)
run_and_test "${FIXED[@]}" "${CANDIDATES[@]}"
[ "$PASS" = 1 ] || { echo "baseline FAILED (config not representative): ${OBS}" >&2; exit 3; }

# --- drop-test each candidate: required iff removing it breaks correctness ---------
: > "$WORK/checks.tsv"
required=()
for cand in "${CANDIDATES[@]}"; do
  [ -n "$cand" ] || continue
  active=("${FIXED[@]}")
  for c in "${CANDIDATES[@]}"; do [ "$c" != "$cand" ] && active+=("$c"); done
  run_and_test "${active[@]}"
  if [ "$PASS" = 1 ]; then
    printf '%s\tfalse\t%s\n' "$cand" "${OBS:-container correct without it}" >> "$WORK/checks.tsv"
  else
    required+=("$cand")
    printf '%s\ttrue\t%s\n' "$cand" "${OBS:-container broke without it}" >> "$WORK/checks.tsv"
  fi
done

# --- emit JSON evidence --------------------------------------------------------
MINIMUM="$(printf '%s\n' "${FIXED[@]}" "${required[@]}" | grep -v '^$' | sort -u | paste -sd' ')"
IMAGE="$IMAGE" TAG="$TAG" DIGEST="$DIGEST" DIM="$DIM" MINIMUM="$MINIMUM" \
  RUN_USER="${F[RUN_USER]}" RUN_PID="${F[RUN_PID]}" RUN_NET="${F[RUN_NET]}" \
  RUN_ENTRYPOINT="${F[RUN_ENTRYPOINT]}" RUN_CMD="${F[CMD]}" RUN_DEVICES="${F[DEVICES]}" \
  RUN_SECOPT="${F[SECOPT]}" RUN_MOUNTS="${F[MOUNTS]}" RUN_ENV="${F[ENV]}" \
  RUN_SYSCTLS="${F[SYSCTLS]}" RUN_UNGUARANTEED="$UNGUARANTEED_CSV" \
  RUN_DEPS="$DEPS_CSV" RUN_VOLUMES_FROM="${F[VOLUMES_FROM]}" \
  FEATURES_B64="${F[FEATURES_B64]}" \
  "$PY" - "$WORK/checks.tsv" <<'PYEOF'
import os, sys, json, base64
checks = []
for ln in open(sys.argv[1]):
    parts = ln.rstrip("\n").split("\t")
    if len(parts) == 3:
        checks.append({"removed": parts[0], "required": parts[1] == "true", "observed": parts[2]})
def vsplit(s):
    return [x for x in s.split("\v") if x]
# The invocation the minimum was derived under — the orthogonal run context
# (NOT the derived dimension itself). A consumer applying this profile can diff a
# target service against it and warn when a load-bearing axis (user, mounts, etc.)
# diverges: e.g. postgres run with `user:` set skips the root->user drop and so
# needs none of the startup caps this default-invocation profile lists.
# env is emitted as KEYS ONLY (no values): the load-bearing signal is which vars
# are set, not their contents, and keys-only keeps a secret out of the committed
# evidence entirely.
run_config = {
    "user": os.environ.get("RUN_USER", ""),
    "command": vsplit(os.environ.get("RUN_CMD", "")),
    "entrypoint": os.environ.get("RUN_ENTRYPOINT", ""),
    "network": os.environ.get("RUN_NET", ""),
    "pid": os.environ.get("RUN_PID", ""),
    "devices": vsplit(os.environ.get("RUN_DEVICES", "")),
    "security_opt": vsplit(os.environ.get("RUN_SECOPT", "")),
    "mounts": vsplit(os.environ.get("RUN_MOUNTS", "")),
    "env": [e.split("=", 1)[0] for e in vsplit(os.environ.get("RUN_ENV", ""))],
}
# The kernel sysctl posture the minimum was derived under — a load-bearing axis for
# posture-dependent caps (NET_BIND_SERVICE hinges on ip_unprivileged_port_start), so
# a consumer knows the profile is valid only under this posture. Emitted whole
# (key=value): a sysctl value is not a secret.
sysctls = vsplit(os.environ.get("RUN_SYSCTLS", ""))
if sysctls:
    run_config["sysctls"] = sysctls
# In-stack context: the dependency services the minimum was derived alongside (the
# target could not be exercised without them). Names only.
deps = [x for x in os.environ.get("RUN_DEPS", "").split("\v") if x]
if deps:
    run_config["deps"] = deps
    vf = [x for x in os.environ.get("RUN_VOLUMES_FROM", "").split("\v") if x]
    if vf:
        run_config["volumes_from"] = vf
out = {
    "image": os.environ["IMAGE"], "tag": os.environ["TAG"],
    "digest": os.environ["DIGEST"], "dimension": os.environ["DIM"],
    "minimum": os.environ["MINIMUM"].split() if os.environ["MINIMUM"] else [],
    "run_config": run_config,
    "checks": checks,
}
# The feature ledger (spec `features:`, passed through verbatim): which
# privilege-relevant features the workload did and did not drive — data for the
# catalog profile's derivation.features (schema 1.6). Omitted when the spec
# declares none.
feats = json.loads(base64.b64decode(os.environ.get("FEATURES_B64", "") or "W10=").decode())
if feats:
    out["features"] = feats
# Confidence-guard input (csd#340 capstone): the mounts whose worst-case initial
# state the drop-test could NOT guarantee (a ${VAR} fresh-vol or a passed-through
# named volume — see the bash classification). A chown-class cap derived removable
# is only trustworthy if there is no such mount; compose_verdict.py suppresses such
# a drop (keeps the cap, low-confidence) when unguaranteed_mounts is non-empty.
# `guaranteed` is true exactly when the list is empty (rootfs cold-start, staged/
# real binds, tmpfs — all faithful). Capabilities dimension only: the fidelity
# question is about the mount state caps are derived against.
unguaranteed = [x for x in os.environ.get("RUN_UNGUARANTEED", "").split("\v") if x]
if os.environ["DIM"] == "capabilities":
    out["fidelity"] = {"guaranteed": not unguaranteed, "unguaranteed_mounts": unguaranteed}
print(json.dumps(out, indent=2))
PYEOF
