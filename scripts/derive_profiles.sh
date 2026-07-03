#!/usr/bin/env bash
# Re-derive catalog profiles from a manifest (compose-lint#360 step 4).
#
# For each fs-dimension entry in <catalog>/derivation/manifest.yaml: resolve the
# tag's current digest; if it differs from the profile's pinned digest (or FORCE=1),
# re-derive the fs recommendation against the current image and compare it to the
# committed profile. Verdicts:
#   FRESH       — pinned digest == current; nothing to do.
#   REVALIDATE  — recommendation unchanged; only the digest + validated_date move
#                 (with APPLY=1, bumped in place — preserves validated_via/ci-smoke).
#   CHANGED     — recommendation differs; left for human review (never auto-applied).
# Bisection/manual entries (cap_add) are assisted, not auto-derived: printed + skipped.
#
# Runs on the self-hosted BPF runner (needs root + docker + pinned ig). csd is run
# under sudo for CAP_BPF/CAP_PERFMON + the docker socket.
#
#   CATALOG=/path/to/catalog CSD=./csd [FORCE=1] [APPLY=1] scripts/derive_profiles.sh
set -uo pipefail

CATALOG="${CATALOG:?set CATALOG to a catalog checkout}"
CSD="${CSD:-./csd}"
PY="${PY:-python3}"
FORCE="${FORCE:-0}"
APPLY="${APPLY:-0}"
MANIFEST="${CATALOG}/derivation/manifest.yaml"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

[ -f "${MANIFEST}" ] || { echo "no manifest at ${MANIFEST}" >&2; exit 2; }
[ -x "${CSD}" ] || { echo "csd not executable at ${CSD}" >&2; exit 2; }

# Emit one TSV line per manifest entry (MANUAL entries carry only image+note).
readarray -t ENTRIES < <("${PY}" - "${MANIFEST}" <<'PYEOF'
import sys, yaml
for e in (yaml.safe_load(open(sys.argv[1])) or {}).get("images", []):
    if e.get("manual") or e.get("dimension") != "fs":
        print("SKIP\t%s\t%s" % (e.get("image",""), " ".join((e.get("note") or e.get("dimension","")).split())))
        continue
    print("\t".join(["FS", e["profile"], e["image"], str(e["tag"]), e["workload"],
                     e.get("workload_env","CONTAINER"), e.get("duration","310s"),
                     ";".join((e.get("run") or {}).get("env", []))]))
PYEOF
)

# current_digest <image> <tag>  -> sha256:... (pulls, reads RepoDigests)
current_digest() {
  docker pull -q "$1:$2" >/dev/null 2>&1 || return 1
  docker inspect --format '{{index .RepoDigests 0}}' "$1:$2" 2>/dev/null | sed -E 's/.*@//'
}

# fs_reco <yaml-file> -> "read_only|tmpfs,csv" (the semantic recommendation)
fs_reco() {
  "${PY}" - "$1" <<'PYEOF'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])) or {}
fs = (d.get("dimensions") or {}).get("filesystem") or {}
print("%s|%s" % (fs.get("read_only"), ",".join(fs.get("tmpfs") or [])))
PYEOF
}

overall=0
for line in "${ENTRIES[@]}"; do
  IFS=$'\t' read -r kind a b c d e f g <<<"${line}"
  if [ "${kind}" = "SKIP" ]; then
    echo "SKIP  ${a}: ${b:-manual/non-fs — assisted, not auto-derived}"
    continue
  fi
  profile="${a}"; image="${b}"; tag="${c}"; workload="${d}"
  wenv="${e}"; duration="${f}"; envspec="${g}"
  committed="${CATALOG}/${profile}"
  [ -f "${committed}" ] || { echo "MISS  ${profile}: committed profile not found"; overall=1; continue; }

  cur="$(current_digest "${image}" "${tag}")"
  [ -n "${cur}" ] || { echo "WARN  ${profile}: could not resolve ${image}:${tag}"; overall=1; continue; }
  pinned="$(grep -m1 validated_image "${committed}" | sed -E 's/.*@(sha256:[a-f0-9]+).*/\1/')"

  if [ "${cur}" = "${pinned}" ] && [ "${FORCE}" != "1" ]; then
    echo "FRESH ${profile}: ${image}:${tag} still ${cur:0:19}…"
    continue
  fi

  # Re-derive fs against the current image.
  cont="csd-derive-$(echo "${image}" | tr '/:' '__')"
  docker rm -f "${cont}" >/dev/null 2>&1
  envargs=(); IFS=';' read -ra evs <<<"${envspec}"
  for ev in "${evs[@]}"; do [ -n "${ev}" ] && envargs+=(-e "${ev}"); done
  if ! docker run -d --name "${cont}" "${envargs[@]}" "${image}:${tag}" >/dev/null 2>&1; then
    echo "WARN  ${profile}: docker run failed"; overall=1; continue
  fi
  derived="${WORKDIR}/derived.yaml"
  ( cd "${CATALOG}" && sudo -n "${CSD}" --observe fs --container "${cont}" --duration "${duration}" \
      --workload "${workload}" --format compose-lint-profile --allow-exploratory \
      --out "${WORKDIR}/sidecar.json" > "${derived}" 2>"${WORKDIR}/csd.err" ) &
  csd_pid=$!
  sleep 3
  ( export "${wenv}=${cont}"; bash "${CATALOG}/${workload}" >/dev/null 2>&1 || true ) &
  wait "${csd_pid}"; rc=$?
  docker rm -f "${cont}" >/dev/null 2>&1
  if [ "${rc}" != "0" ] || [ ! -s "${derived}" ]; then
    echo "WARN  ${profile}: csd derive failed (rc=${rc}); $(head -1 "${WORKDIR}/csd.err" 2>/dev/null)"; overall=1; continue
  fi

  want="$(fs_reco "${committed}")"; got="$(fs_reco "${derived}")"
  if [ "${want}" = "${got}" ]; then
    echo "REVALIDATE ${profile}: recommendation unchanged (${got}); digest ${pinned:0:19}… -> ${cur:0:19}…"
    if [ "${APPLY}" = "1" ]; then
      today="$(date -u +%Y-%m-%d)"
      sed -i -E "s#(validated_image: [^@]*@)sha256:[a-f0-9]+#\1${cur}#" "${committed}"
      sed -i -E "s#(validated_date: )\"[0-9-]+\"#\1\"${today}\"#" "${committed}"
      echo "        applied: validated_image + validated_date bumped in ${profile}"
    fi
  else
    echo "CHANGED ${profile}: recommendation differs — committed [${want}] vs derived [${got}] — HUMAN REVIEW"
    overall=1
  fi
done

exit "${overall}"
