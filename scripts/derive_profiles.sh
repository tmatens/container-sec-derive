#!/usr/bin/env bash
# Re-derive catalog profiles from a manifest (compose-lint#360 step 4).
#
# One manifest-driven loop, dispatching per the manifest entry's `method`:
#
#   method: drop-test       -> scripts/drop_test.sh (the EXPERIMENT layer):
#       drop-a-candidate / restart / run a correctness check. Covers the full
#       container lifetime, so it derives the minimum that startup-only behavior
#       makes invisible to runtime observation (a socket dir's tmpfs, a
#       root->user privilege drop's SETUID/SETGID). No eBPF, needs only docker.
#       Derives capabilities and filesystem only (the candidate kinds
#       drop_test.sh knows how to drop).
#   method: bpf-observation -> csd --observe (the OBSERVATION layer):
#       the ig gadgets, for dimensions whose requirements are purely runtime.
#       Needs root + CAP_BPF/CAP_PERFMON + the pinned `ig`. Handles all five
#       catalog dimensions (capabilities, filesystem, devices,
#       cap_add_validation, privileged_decomposition). A conditional dimension
#       is only meaningful under its grant, so the manifest entry supplies:
#         run_args: extra `docker run` flags for the representative run
#                   (e.g. "--device /dev/dri", "--cap-add SYS_ADMIN",
#                   "--privileged"); whitespace-split, no quoting.
#         csd_args: extra csd flags for the observer
#                   (e.g. "--cap-add SYS_ADMIN,NET_RAW" for capadd).
#       Note capabilities-via-observation is attach-window-blind to startup
#       caps — the catalog derives caps by drop-test for exactly that reason;
#       the dispatch supports it but the manifest chooses the method.
#
# For each entry: resolve the tag's current digest; if it differs from the
# profile's pinned digest (or FORCE=1), re-derive and compare to the committed
# profile. Verdicts:
#   FRESH       — pinned digest == current; nothing to do.
#   REVALIDATE  — recommendation unchanged; only the digest + validated_date move
#                 (with APPLY=1, bumped in place — preserves validated_via/ci-smoke).
#   CHANGED     — recommendation differs; left for human review (never auto-applied).
#
# Exit codes — so the caller can tell "couldn't check" from a review signal
# (mirrors deploy_check.sh; a transient WARN must never masquerade as CHANGED):
#   0  — every entry FRESH or REVALIDATE.
#   10 — advisory: ≥1 entry could not be checked (WARN/MISS/unknown method) but
#        no recommendation changed — a coverage gap, not a review signal.
#   12 — ≥1 CHANGED recommendation — human review needed. Dominates 10.
#
# A drop-test entry is matched to its csd spec (testdata/drop-test/*.yaml) by
# image + dimension — no filename coupling, and the spec (candidates, correctness check,
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

# --- manifest -> one TSV line per entry:
#     method, profile, image, tag, dimension, workload, run_args, csd_args
# (run_args/csd_args are optional and empty for the caps/fs entries; values may
# contain spaces but never tabs, so TSV stays unambiguous)
readarray -t ENTRIES < <("${PY}" - "${MANIFEST}" <<'PYEOF'
import sys, yaml
for e in (yaml.safe_load(open(sys.argv[1])) or {}).get("images", []):
    print("\t".join(str(e.get(k, "")) for k in
          ("method", "profile", "image", "tag", "dimension", "workload",
           "run_args", "csd_args")))
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
#   capabilities:             "CAP,CAP,..."
#   filesystem:               "read_only|tmpfs,tmpfs,..."
#   devices:                  "dev,dev,...|derivedcap,derivedcap,..."
#   cap_add_validation:       "CAP,CAP,..." (recommended_cap_add; validated_caps
#                             is evidence, not a recommendation)
#   privileged_decomposition: "CAP,...|dev,...|partial=true/false"
# Works on both a committed catalog profile and csd's own compose-lint-profile
# output (same schema), so the bpf-observation path compares like with like.
# The else branch is unreachable — the loop rejects unknown dimensions up front
# so a typo can never canonicalize to "" on both sides and silently REVALIDATE.
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
elif sys.argv[2] == "devices":
    print("%s|%s" % (",".join(sorted(dim.get("devices") or [])),
                     ",".join(sorted(dim.get("derived_caps") or []))))
elif sys.argv[2] == "cap_add_validation":
    print(",".join(sorted(dim.get("recommended_cap_add") or [])))
elif sys.argv[2] == "privileged_decomposition":
    print("%s|%s|partial=%s" % (",".join(sorted(dim.get("cap_add") or [])),
                                ",".join(sorted(dim.get("devices") or [])),
                                str(bool(dim.get("partial"))).lower()))
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

advisory=0; changed=0
for line in "${ENTRIES[@]}"; do
  IFS=$'\t' read -r method profile image tag dimension workload run_args csd_args <<<"${line}"
  committed="${CATALOG}/${profile}"
  [ -f "${committed}" ] || { echo "MISS  ${profile}: committed profile not found"; advisory=10; continue; }

  # Map the catalog dimension to its csd observer, rejecting unknowns before
  # any docker work. This guard is load-bearing: an unknown dimension would
  # canonicalize to "" on both sides and silently REVALIDATE.
  case "${dimension}" in
    capabilities)             observer="caps" ;;
    filesystem)               observer="fs" ;;
    devices)                  observer="devices" ;;
    cap_add_validation)       observer="capadd" ;;
    privileged_decomposition) observer="privileged" ;;
    *) echo "WARN  ${profile}: unknown dimension '${dimension}'"; advisory=10; continue ;;
  esac

  cur="$(current_digest "${image}" "${tag}")"
  [ -n "${cur}" ] || { echo "WARN  ${profile}: could not resolve ${image}:${tag}"; advisory=10; continue; }
  pinned="$(pinned_digest "${committed}")"
  if [ "${cur}" = "${pinned}" ] && [ "${FORCE}" != "1" ]; then
    echo "FRESH ${profile}: ${image}:${tag} still ${cur:0:19}…"
    continue
  fi

  want="$(committed_reco "${committed}" "${dimension}")"
  got=""
  case "${method}" in
    drop-test)
      case "${dimension}" in
        capabilities|filesystem) ;;
        *) echo "WARN  ${profile}: drop-test cannot derive '${dimension}' (capabilities/filesystem only)"; advisory=10; continue ;;
      esac
      spec="$(find_spec "${image}" "${dimension}")" || {
        echo "WARN  ${profile}: no csd drop-test spec matches ${image} (${dimension})"; advisory=10; continue; }
      if ! PY="${PY}" bash "${REPO}/scripts/drop_test.sh" "${spec}" \
             >"${WORKDIR}/dt.json" 2>"${WORKDIR}/dt.err"; then
        echo "WARN  ${profile}: drop_test.sh failed — $(tail -1 "${WORKDIR}/dt.err" 2>/dev/null)"; advisory=10; continue
      fi
      got="$(derived_reco "${WORKDIR}/dt.json" "${spec}" "${dimension}")"
      ;;
    bpf-observation)
      [ -x "${CSD}" ] || { echo "WARN  ${profile}: csd not executable at ${CSD} (needed for bpf-observation)"; advisory=10; continue; }
      # run_args carries the representative grant a conditional dimension is
      # derived under (--device/--cap-add/--privileged); csd_args carries
      # observer flags (capadd's --cap-add list). Whitespace-split — manifest
      # values must not need shell quoting.
      read -r -a run_flags <<<"${run_args}"
      read -r -a csd_flags <<<"${csd_args}"
      cont="csd-derive-$(echo "${image}" | tr '/:' '__')"
      docker rm -f "${cont}" >/dev/null 2>&1
      if ! docker run -d --name "${cont}" "${run_flags[@]}" "${image}:${tag}" >/dev/null 2>&1; then
        echo "WARN  ${profile}: docker run failed"; advisory=10; continue
      fi
      ( cd "${CATALOG}" && sudo -n "${CSD}" --observe "${observer}" --container "${cont}" --duration 310s \
          "${csd_flags[@]}" \
          --workload "${workload}" --format compose-lint-profile --allow-exploratory \
          --out "${WORKDIR}/sidecar.json" > "${WORKDIR}/derived.yaml" 2>"${WORKDIR}/csd.err" ) &
      csd_pid=$!
      sleep 3
      ( export PGCONTAINER="${cont}" CONTAINER="${cont}"; bash "${CATALOG}/${workload}" >/dev/null 2>&1 || true ) &
      wait "${csd_pid}"; rc=$?
      docker rm -f "${cont}" >/dev/null 2>&1
      if [ "${rc}" != "0" ] || [ ! -s "${WORKDIR}/derived.yaml" ]; then
        echo "WARN  ${profile}: csd derive failed (rc=${rc}); $(head -1 "${WORKDIR}/csd.err" 2>/dev/null)"; advisory=10; continue
      fi
      got="$(committed_reco "${WORKDIR}/derived.yaml" "${dimension}")"
      ;;
    *)
      echo "WARN  ${profile}: unknown method '${method}'"; advisory=10; continue
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
    changed=12
  fi
done

# CHANGED (12) dominates advisory (10); both are distinct from a clean 0 so the
# workflow can open the review issue ONLY for a real recommendation change.
[ "${changed}" -ne 0 ] && exit "${changed}"
exit "${advisory}"
