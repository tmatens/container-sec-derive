#!/usr/bin/env bash
# deploy-check driver (csd#240). Reads deploy-check/manifest.yaml and, per
# service, clones its LIVE compose from Forgejo and runs compose_derive.sh against
# it — deriving the capability minimum under the service's own invocation (on the
# posture-matched runner) and diffing it against the declared cap_add.
#
# Prints a per-service verdict table (Markdown, for a job summary).
#
# Exit codes — so the caller can tell "couldn't run" from a security verdict:
#   0  — all checked services match / advisory only (not_minimized, over_permissioned,
#        or a per-service clone failure). Report-only always lands here.
#   3  — cannot run: no clone credential (FORGEJO_RO_TOKEN empty and FORGEJO_SSH unset).
#   12 — (ENFORCE=1 only) ≥1 service is under_permissioned — a needed cap is missing,
#        so the hardened deploy would break. This is #240's security gate.
# ENFORCE unset (default) = report-only: verdicts print but the run only exits 0/3
# (never 12). A per-service clone failure stays advisory (exit 0) but is flagged as
# a coverage gap — so an ENFORCE=1 red (12) unambiguously means under_permissioned.
#
# Clone transport:
#   FORGEJO_SSH=1                -> git clone forgejo:<repo>.git   (SSH key; local)
#   else FORGEJO_RO_TOKEN=<tok>  -> HTTPS with an Authorization header (CI)
#     FORGEJO_BASE default https://git.matens.xyz
#
#   PY=python3 [ENFORCE=1] bash scripts/deploy_check.sh   [> summary.md]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PY:-python3}"
MANIFEST="${MANIFEST:-$REPO/deploy-check/manifest.yaml}"
FORGEJO_BASE="${FORGEJO_BASE:-https://git.matens.xyz}"
ENFORCE="${ENFORCE:-}"   # set to fail (exit 12) on an under_permissioned service
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
[ -f "$MANIFEST" ] || { echo "no manifest at $MANIFEST" >&2; exit 2; }

# Credential preflight — fail fast with a clear message (exit 3) instead of the
# cryptic mid-loop ${FORGEJO_RO_TOKEN:?} crash that leaves an empty verdict table.
# exit 3 keeps "cannot run" distinct from an under_permissioned verdict (exit 12).
if [ -z "${FORGEJO_SSH:-}" ] && [ -z "${FORGEJO_RO_TOKEN:-}" ]; then
  echo "deploy-check: cannot run — set FORGEJO_RO_TOKEN (read-only Forgejo token) or FORGEJO_SSH=1" >&2
  exit 3
fi

clone_repo() { # <forgejo_repo> <dest>
  local repo="$1" dest="$2"
  if [ -n "${FORGEJO_SSH:-}" ]; then
    git clone --depth 1 -q "forgejo:${repo}.git" "$dest"
  else
    : "${FORGEJO_RO_TOKEN:?set FORGEJO_RO_TOKEN or FORGEJO_SSH=1}"
    git -c "http.extraHeader=Authorization: token ${FORGEJO_RO_TOKEN}" \
      clone --depth 1 -q "${FORGEJO_BASE}/${repo}.git" "$dest"
  fi
}

# read the manifest into TSV: name<TAB>repo<TAB>compose_path<TAB>service<TAB>correctness
mapfile -t ENTRIES < <("$PY" - "$MANIFEST" <<'PYEOF'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1])) or {}
for s in (m.get("services") or []):
    print("\t".join(str(s.get(k, "")) for k in
          ("name", "forgejo_repo", "compose_path", "service", "correctness")))
PYEOF
)

printf '## deploy-check — %s\n\n' "$(TZ=UTC printf '%(%Y-%m-%d %H:%M UTC)T' -1 2>/dev/null || echo now)"
printf '| service | verdict | drop | add | detail |\n|---|---|---|---|---|\n'

worst=0        # most severe verdict seen (0 ok · 1 advisory · 2 under_permissioned)
unchecked=0    # services that could not be checked (clone failed) — a coverage gap
# Progress heartbeat goes to stderr (the caller leaves it un-redirected so it
# streams live to the console — the derivation is minutes per service).
total=0; for _l in "${ENTRIES[@]}"; do [ -n "$_l" ] && total=$((total + 1)); done
i=0
for line in "${ENTRIES[@]}"; do
  IFS=$'\t' read -r name repo cpath service correctness <<<"$line"
  [ -n "$name" ] || continue
  i=$((i + 1))
  echo "progress: [$i/$total] deriving $name ($repo)…" >&2
  cdir="$WORK/$name"
  if ! clone_repo "$repo" "$cdir" 2>"$WORK/clone.err"; then
    printf '| %s | ⚠️ clone-failed | | | %s |\n' "$name" "$(tail -1 "$WORK/clone.err" | tr '|' '/')"
    echo "progress: [$i/$total] $name → clone-failed" >&2
    worst=1; unchecked=$((unchecked + 1)); continue
  fi
  CORRECTNESS="$correctness" PY="$PY" \
    bash "$REPO/scripts/compose_derive.sh" "$cdir/$cpath" "$service" \
    >"$WORK/out.json" 2>"$WORK/derive.err"; rc=$?
  case "$rc" in
    0)  v="✅ matches";            sev=0 ;;
    10) v="🟠 not_minimized";      sev=1 ;;
    11) v="🟡 over_permissioned";  sev=1 ;;
    12) v="🔴 under_permissioned"; sev=2 ;;
    *)  v="⚠️ derive-error";       sev=1 ;;
  esac
  [ "$sev" -gt "$worst" ] && worst="$sev"
  echo "progress: [$i/$total] $name → $v" >&2
  if [ "$rc" = 0 ] || [ "$rc" -ge 10 ]; then
    drop="$("$PY" -c 'import json,sys; d=json.load(open(sys.argv[1]))["deploy_check"]; print(" ".join(d["drop"]) or "—")' "$WORK/out.json" 2>/dev/null || echo '—')"
    add="$("$PY" -c 'import json,sys; d=json.load(open(sys.argv[1]))["deploy_check"]; print(" ".join(d["add"]) or "—")' "$WORK/out.json" 2>/dev/null || echo '—')"
    detail="$(grep '^compose_derive: ' "$WORK/derive.err" | tail -1 | sed 's/^compose_derive: //; s/|/\//g')"
  else
    drop='—'; add='—'; detail="$(tail -1 "$WORK/derive.err" | tr '|' '/')"
  fi
  printf '| %s | %s | %s | %s | %s |\n' "$name" "$v" "$drop" "$add" "${detail:-—}"
done

echo
[ "$unchecked" -gt 0 ] && echo "deploy-check: $unchecked service(s) could NOT be checked (clone failed) — coverage gap, not a verdict" >&2
case "$worst" in
  0) echo "deploy-check: all checked services match their derived minimum" >&2 ;;
  1) echo "deploy-check: advisory only (not_minimized / over_permissioned / unchecked)" >&2 ;;
  2) echo "deploy-check: UNDER-permissioned service(s) found — a needed cap is missing" >&2 ;;
esac
# Enforce (ENFORCE=1) fails ONLY on under_permissioned (worst==2) with the derive
# exit code 12 — a needed cap is missing, so the hardened deploy would break.
# not_minimized / over_permissioned / clone-failed (worst==1) stay advisory.
# Unset ENFORCE = report-only: always exit 0.
if [ -n "$ENFORCE" ] && [ "$worst" -ge 2 ]; then
  exit 12
fi
exit 0
