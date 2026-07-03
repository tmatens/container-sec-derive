#!/usr/bin/env bash
# Re-derive catalog profiles from a manifest (compose-lint#360 step 4).
#
# One manifest-driven loop, dispatching per the manifest entry's `method`:
#
#   method: drop-test       -> scripts/drop_test.sh (the EXPERIMENT layer):
#       drop-a-candidate / restart / run a correctness predicate. Covers the full
#       container lifetime, so it derives the minimum that startup-only behavior
#       makes invisible to runtime observation (a socket dir's tmpfs, a
#       root->user privilege drop's SETUID/SETGID). No eBPF, needs only docker.
#   method: bpf-observation -> csd --observe (the OBSERVATION layer):
#       the ig gadgets, for dimensions whose requirements are purely runtime.
#       Needs root + CAP_BPF/CAP_PERFMON + the pinned `ig`.
#
# For each entry: resolve the tag's current digest; if it differs from the
# profile's pinned digest (or FORCE=1), re-derive and compare to the committed
# profile. Verdicts:
#   FRESH       — pinned digest == current; nothing to do.
#   REVALIDATE  — recommendation unchanged; only the digest + validated_date move
#                 (with APPLY=1, bumped in place — preserves validated_via/ci-smoke).
#   CHANGED     — recommendation differs; left for human review (never auto-applied).
#
# A drop-test entry is matched to its csd spec (testdata/drop-test/*.yaml) by
# image + dimension — no filename coupling, and the spec (candidates, predicate,
# representative run config) stays authoritative in csd.
#
# Runs on the self-hosted BPF runner. The drop-test path needs only docker; the
# observation path additionally needs root (csd under sudo) + the pinned ig.
#
#   CATALOG=/path/to/catalog [CSD=./csd] [FORCE=1] [APPLY=1] scripts/derive_profiles.sh
set -uo pipefail

CATALOG="${CATALOG:?set CATALOG to a catalog checkout}"
CSD="${CSD:-./csd}"
PY="${PY:-python3}"
FORCE="${FORCE:-0}"
APPLY="${APPLY:-0}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${CATALOG}/derivation/manifest.yaml"
SPECDIR="${REPO}/testdata/drop-test"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

[ -f "${MANIFEST}" ] || { echo "no manifest at ${MANIFEST}" >&2; exit 2; }

# --- manifest -> one TSV line per entry: method, profile, image, tag, dimension, workload
readarray -t ENTRIES < <("${PY}" - "${MANIFEST}" <<'PYEOF'
import sys, yaml
for e in (yaml.safe_load(open(sys.argv[1])) or {}).get("images", []):
    print("\t".join(str(e.get(k, "")) for k in
          ("method", "profile", "image", "tag", "dimension", "workload")))
PYEOF
)

# current_digest <image> <tag>  -> sha256:...  (pulls, reads RepoDigests)
current_digest() {
  docker pull -q "$1:$2" >/dev/null 2>&1 || return 1
  docker inspect --format '{{index .RepoDigests 0}}' "$1:$2" 2>/dev/null | sed -E 's/.*@//'
}

# pinned_digest <committed-profile>  -> sha256:...  (from validated_image)
pinned_digest() {
  grep -m1 validated_image "$1" | sed -E 's/.*@(sha256:[a-f0-9]+).*/\1/'
}

# find_spec <image> <dimension>  -> path to the matching csd drop-test spec (or empty)
find_spec() {
  local want_img="$1" want_dim="$2" f
  for f in "${SPECDIR}"/*.yaml; do
    [ -f "$f" ] || continue
    "${PY}" - "$f" "$want_img" "$want_dim" <<'PYEOF'
import sys, yaml
s = yaml.safe_load(open(sys.argv[1])) or {}
sys.exit(0 if str(s.get("image")) == sys.argv[2]
             and str(s.get("dimension")) == sys.argv[3] else 1)
PYEOF
    [ $? -eq 0 ] && { echo "$f"; return 0; }
  done
  return 1
}

# committed_reco <committed-profile> <dimension>  -> canonical recommendation string
#   capabilities: "CAP,CAP,..."   filesystem: "read_only|tmpfs,tmpfs,..."
committed_reco() {
  "${PY}" - "$1" "$2" <<'PYEOF'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])) or {}
dim = (d.get("dimensions") or {}).get(sys.argv[2]) or {}
if sys.argv[2] == "capabilities":
    print(",".join(sorted(dim.get("cap_add") or [])))
elif sys.argv[2] == "filesystem":
    print("%s|%s" % (str(bool(dim.get("read_only"))).lower(),
                     ",".join(sorted(dim.get("tmpfs") or []))))
else:
    print("")
PYEOF
}

# derived_reco <drop-test-json> <spec> <dimension>  -> canonical recommendation string
#   (base_fs read_only is the spec's fixed decision; the drop-test derives tmpfs/caps)
derived_reco() {
  "${PY}" - "$1" "$2" "$3" <<'PYEOF'
import sys, json, yaml
out = json.load(open(sys.argv[1]))
spec = yaml.safe_load(open(sys.argv[2])) or {}
minimum = sorted(out.get("minimum") or [])
if sys.argv[3] == "capabilities":
    print(",".join(minimum))
elif sys.argv[3] == "filesystem":
    ro = str(spec.get("base_fs") == "read_only").lower()
    print("%s|%s" % (ro, ",".join(minimum)))
else:
    print("")
PYEOF
}

# apply_bump <committed-profile> <new-digest>  -> rewrite validated_image + validated_date
apply_bump() {
  local committed="$1" digest="$2" today
  today="$(date -u +%Y-%m-%d)"
  sed -i -E "s#(validated_image: [^@]*@)sha256:[a-f0-9]+#\1${digest}#" "${committed}"
  sed -i -E "s#(validated_date: )\"[0-9-]+\"#\1\"${today}\"#" "${committed}"
}

overall=0
for line in "${ENTRIES[@]}"; do
  IFS=$'\t' read -r method profile image tag dimension workload <<<"${line}"
  committed="${CATALOG}/${profile}"
  [ -f "${committed}" ] || { echo "MISS  ${profile}: committed profile not found"; overall=1; continue; }

  cur="$(current_digest "${image}" "${tag}")"
  [ -n "${cur}" ] || { echo "WARN  ${profile}: could not resolve ${image}:${tag}"; overall=1; continue; }
  pinned="$(pinned_digest "${committed}")"
  if [ "${cur}" = "${pinned}" ] && [ "${FORCE}" != "1" ]; then
    echo "FRESH ${profile}: ${image}:${tag} still ${cur:0:19}…"
    continue
  fi

  want="$(committed_reco "${committed}" "${dimension}")"
  got=""
  case "${method}" in
    drop-test)
      spec="$(find_spec "${image}" "${dimension}")" || {
        echo "WARN  ${profile}: no csd drop-test spec matches ${image} (${dimension})"; overall=1; continue; }
      if ! PY="${PY}" bash "${REPO}/scripts/drop_test.sh" "${spec}" \
             >"${WORKDIR}/dt.json" 2>"${WORKDIR}/dt.err"; then
        echo "WARN  ${profile}: drop_test.sh failed — $(tail -1 "${WORKDIR}/dt.err" 2>/dev/null)"; overall=1; continue
      fi
      got="$(derived_reco "${WORKDIR}/dt.json" "${spec}" "${dimension}")"
      ;;
    bpf-observation)
      [ -x "${CSD}" ] || { echo "WARN  ${profile}: csd not executable at ${CSD} (needed for bpf-observation)"; overall=1; continue; }
      if [ "${dimension}" != "filesystem" ]; then
        echo "SKIP  ${profile}: bpf-observation for '${dimension}' not wired — no such catalog entry yet"; continue
      fi
      cont="csd-derive-$(echo "${image}" | tr '/:' '__')"
      docker rm -f "${cont}" >/dev/null 2>&1
      if ! docker run -d --name "${cont}" "${image}:${tag}" >/dev/null 2>&1; then
        echo "WARN  ${profile}: docker run failed"; overall=1; continue
      fi
      ( cd "${CATALOG}" && sudo -n "${CSD}" --observe fs --container "${cont}" --duration 310s \
          --workload "${workload}" --format compose-lint-profile --allow-exploratory \
          --out "${WORKDIR}/sidecar.json" > "${WORKDIR}/derived.yaml" 2>"${WORKDIR}/csd.err" ) &
      csd_pid=$!
      sleep 3
      ( export PGCONTAINER="${cont}" CONTAINER="${cont}"; bash "${CATALOG}/${workload}" >/dev/null 2>&1 || true ) &
      wait "${csd_pid}"; rc=$?
      docker rm -f "${cont}" >/dev/null 2>&1
      if [ "${rc}" != "0" ] || [ ! -s "${WORKDIR}/derived.yaml" ]; then
        echo "WARN  ${profile}: csd derive failed (rc=${rc}); $(head -1 "${WORKDIR}/csd.err" 2>/dev/null)"; overall=1; continue
      fi
      got="$(committed_reco "${WORKDIR}/derived.yaml" "${dimension}")"
      ;;
    *)
      echo "WARN  ${profile}: unknown method '${method}'"; overall=1; continue
      ;;
  esac

  if [ "${want}" = "${got}" ]; then
    echo "REVALIDATE ${profile}: recommendation unchanged (${got}); digest ${pinned:0:19}… -> ${cur:0:19}… [${method}]"
    if [ "${APPLY}" = "1" ]; then
      apply_bump "${committed}" "${cur}"
      echo "        applied: validated_image + validated_date bumped in ${profile}"
    fi
  else
    echo "CHANGED ${profile}: recommendation differs — committed [${want}] vs derived [${got}] — HUMAN REVIEW [${method}]"
    overall=1
  fi
done

exit "${overall}"
