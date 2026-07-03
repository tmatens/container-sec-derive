#!/usr/bin/env bash
# csd drop-test producer (compose-lint#360): derive a *required* minimum by
# drop-and-restart, and emit structured evidence.
#
# This is csd's EXPERIMENT layer, complementary to its OBSERVATION layer (the ig
# gadgets). It is not a gadget and uses no eBPF of its own: for each candidate it
# launches the container WITHOUT that element, restarts, and runs a per-image
# correctness predicate. Observation answers "was it exercised"; drop-test answers
# "is it required" — the only way to catch startup-time requirements (a root->user
# privilege drop's SETUID/SETGID, a socket dir's tmpfs) that attach-window
# observation is blind to.
#
# Emits JSON to stdout:
#   {image, tag, digest, dimension, minimum:[...],
#    run_config:{user,command,entrypoint,network,pid,devices,security_opt,mounts,env},
#    checks:[{removed,required,observed}]}
# where `minimum` = the fixed set + every candidate found required, and
# `run_config` is the invocation the minimum was derived under — the orthogonal
# run context a consumer diffs a target service against (a divergent `user:` or
# mount can change the minimum, so the profile is only valid for this context).
#
#   sudo? no — needs only docker; the predicate may need more.
#   PY=python3 scripts/drop_test.sh <spec.yaml>
set -uo pipefail

SPEC="${1:?usage: drop_test.sh <spec.yaml>}"
PY="${PY:-python3}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
C="csd-drop-test-run"
WORK="$(mktemp -d)"; trap 'docker rm -f "$C" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

# --- parse spec (TSV; arrays are space/newline-joined, safe for caps/paths) ----
declare -A F
while IFS=$'\t' read -r k v; do F["$k"]="$v"; done < <("$PY" - "$SPEC" <<'PYEOF'
import sys, yaml
s = yaml.safe_load(open(sys.argv[1])) or {}
run = s.get("run", {}) or {}
def line(k, v): print(f"{k}\t{v}")
line("IMAGE", s["image"]); line("TAG", s["tag"]); line("DIM", s["dimension"])
line("PREDICATE", s["predicate"]); line("BASE_FS", s.get("base_fs", ""))
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
IFS=$'\v' read -ra RUN_ENV <<<"${F[ENV]}"
IFS=$'\v' read -ra RUN_MOUNTS <<<"${F[MOUNTS]}"
IFS=$'\v' read -ra RUN_SECOPT <<<"${F[SECOPT]}"
IFS=$'\v' read -ra RUN_DEVICES <<<"${F[DEVICES]}"
IFS=$'\v' read -ra RUN_TMPFS <<<"${F[RUN_TMPFS]}"
IFS=$'\v' read -ra RUN_CMD <<<"${F[CMD]}"
IMAGE="${F[IMAGE]}"; TAG="${F[TAG]}"; DIM="${F[DIM]}"
PREDICATE="${REPO}/${F[PREDICATE]}"
DOCKER_GID="$(getent group docker | cut -d: -f3)"

docker pull -q "${IMAGE}:${TAG}" >/dev/null 2>&1 || { echo "pull failed: ${IMAGE}:${TAG}" >&2; exit 2; }
DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "${IMAGE}:${TAG}" | sed -E 's/.*@//')"

# run_and_test <active element...>  -> sets PASS=0/1, OBS=<last predicate line>
run_and_test() {
  docker rm -f "$C" >/dev/null 2>&1
  local args=(-d --name "$C")
  [ -n "${F[RUN_PID]}" ] && args+=(--pid "${F[RUN_PID]}")
  [ -n "${F[RUN_NET]}" ] && args+=(--network "${F[RUN_NET]}")
  [ -n "${F[RUN_USER]}" ] && args+=(--user "${F[RUN_USER]}")
  [ -n "${F[RUN_ENTRYPOINT]}" ] && args+=(--entrypoint "${F[RUN_ENTRYPOINT]}")
  local m; for m in "${RUN_MOUNTS[@]}"; do [ -n "$m" ] && args+=(-v "$m"); done
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
  DROP_TEST_CONTAINER="$C" bash "$PREDICATE" >"$WORK/pred.out" 2>&1 && PASS=1 || PASS=0
  OBS="$(grep -v '^[[:space:]]*$' "$WORK/pred.out" | tail -1)"
}

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
