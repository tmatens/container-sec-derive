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
#   2. If it genuinely can't be exercised in the observation window (workload
#      coverage), that's a CRITERIA-DOC caveat + low confidence, NOT an untested
#      entry laundered into the derived minimum.
# NOTE: this is the caps/paths `fixed` LIST. The invocation + sibling-dimension
# context you derive UNDER — `run.read_only`/`run.tmpfs`/`run.user`/`run.mounts` —
# IS legitimately held constant; that's expressed via `run.*`, not `fixed`.
#
#   sudo? no — needs only docker; the correctness check may need more.
#   PY=python3 scripts/drop_test.sh <spec.yaml>
set -uo pipefail

SPEC="${1:?usage: drop_test.sh <spec.yaml>}"
PY="${PY:-python3}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
C="csd-drop-test-run"
WORK="$(mktemp -d)"
STAGED_ANY=""   # set when a fresh ephemeral volume was created (see run_and_test)
cleanup() {
  docker rm -f "$C" >/dev/null 2>&1
  # A fresh ephemeral volume can be chowned to the container's user (e.g. postgres
  # 999) during a run, leaving files under $WORK this host user can't remove.
  # Reclaim them via a root-in-container helper before rm.
  if [ -n "$STAGED_ANY" ] && [ -n "${IMAGE:-}" ]; then
    docker run --rm --user 0:0 -v "$WORK:/w" --entrypoint chown "${IMAGE}:${TAG}" \
      -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- parse spec (TSV; arrays are space/newline-joined, safe for caps/paths) ----
declare -A F
while IFS=$'\t' read -r k v; do F["$k"]="$v"; done < <("$PY" - "$SPEC" <<'PYEOF'
import sys, yaml
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
# command may be a YAML list or a bare string (compose accepts both).
cmd = run.get("command", [])
line("CMD", "\v".join(cmd if isinstance(cmd, list) else [cmd]))
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
IFS=$'\v' read -ra RUN_ENV <<<"${F[ENV]}"
IFS=$'\v' read -ra RUN_MOUNTS <<<"${F[MOUNTS]}"
IFS=$'\v' read -ra RUN_SECOPT <<<"${F[SECOPT]}"
IFS=$'\v' read -ra RUN_DEVICES <<<"${F[DEVICES]}"
IFS=$'\v' read -ra RUN_TMPFS <<<"${F[RUN_TMPFS]}"
IFS=$'\v' read -ra RUN_CMD <<<"${F[CMD]}"
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
  docker rm -f "$C" >/dev/null 2>&1
  local args=(-d --name "$C")
  [ -n "${F[RUN_PID]}" ] && args+=(--pid "${F[RUN_PID]}")
  [ -n "${F[RUN_NET]}" ] && args+=(--network "${F[RUN_NET]}")
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
    else
      args+=(-v "$(prep_mount "$m" "$stageroot")")
    fi
  done
  local so; for so in "${RUN_SECOPT[@]}"; do [ -n "$so" ] && args+=(--security-opt "$so"); done
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
  "$PY" - "$WORK/checks.tsv" <<'PYEOF'
import os, sys, json
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
out = {
    "image": os.environ["IMAGE"], "tag": os.environ["TAG"],
    "digest": os.environ["DIGEST"], "dimension": os.environ["DIM"],
    "minimum": os.environ["MINIMUM"].split() if os.environ["MINIMUM"] else [],
    "run_config": run_config,
    "checks": checks,
}
print(json.dumps(out, indent=2))
PYEOF
