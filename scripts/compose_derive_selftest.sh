#!/usr/bin/env bash
# Hermetic self-test for scripts/compose_to_spec.py (the compose -> drop_test spec
# transform). Pure Python + PyYAML, NO docker or images — so it runs in CI's unit
# lane like drop_test_selftest.sh.
#
# Locks the mount/tmpfs fidelity that decides whether a container's COLD-START
# asset creation is exercised (#337). immich's valkey runs read_only + tmpfs:/data
# and chowns /data on boot (needs CHOWN); when the transform dropped `tmpfs`/
# `read_only`, /data fell back to the image's pre-owned dir, the chown became a
# no-op, and CHOWN derived as falsely-removable — which then failed the live deploy
# (#111). This test fails if that propagation ever regresses again.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PY:-python3}"
T2S="${HERE}/compose_to_spec.py"
FAIL=0
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# check <spec-yaml> <python-bool-expr over `run`> <label>
check() {
  if printf '%s' "$1" | "$PY" -c 'import sys,yaml; run=yaml.safe_load(sys.stdin)["run"]; sys.exit(0 if ('"$2"') else 1)'; then
    echo "ok: $3"
  else
    echo "FAIL: $3"; FAIL=1
  fi
}

# --- fixture 1: the #337 shape — read_only + tmpfs:/data + a ${VAR} secret ---
cat > "$WORK/compose.yml" <<'YML'
services:
  redis:
    image: docker.io/valkey/valkey:9
    cap_add: [CHOWN, SETUID, SETGID]
    cap_drop: [ALL]
    read_only: true
    tmpfs:
      - /data
    command: ["valkey-server", "--requirepass", "${REDIS_PASSWORD}"]
    environment:
      FOO: ${SECRET_TOKEN}
YML
SPEC="$("$PY" "$T2S" "$WORK/compose.yml" redis check.sh "$WORK/decl.json" "$WORK/build.json")"

check "$SPEC" '"/data" in run["tmpfs"]'                       "tmpfs /data propagates to run.tmpfs"
check "$SPEC" 'run["read_only"] is True'                      "read_only propagates to run.read_only"
check "$SPEC" 'any("csdPlaceholder" in e for e in run["env"])' "unresolved compose var in env replaced by placeholder"
check "$SPEC" 'not any("SECRET_TOKEN" in e for e in run["env"])' "raw env secret ref not leaked"
if grep -q CHOWN "$WORK/decl.json"; then echo "ok: declared cap_add captured"; else echo "FAIL: declared cap_add captured"; FAIL=1; fi

# --- fixture 2: a plain service — tmpfs/read_only stay empty/false, not applied ---
cat > "$WORK/plain.yml" <<'YML'
services:
  web:
    image: nginx:1
YML
SPEC2="$("$PY" "$T2S" "$WORK/plain.yml" web check.sh "$WORK/d2.json" "$WORK/b2.json")"
check "$SPEC2" 'run["read_only"] is False' "no read_only -> False (not applied to plain services)"
check "$SPEC2" 'run["tmpfs"] == []'        "no tmpfs -> empty list"

# --- verdict logic (#340 item 1): empty minimum but declared caps -> suspect ---
# Pure json (no yaml), so this half runs even without PyYAML.
V2S="${HERE}/compose_verdict.py"
verdict() { # <minimum-json-array> <cap_add-json-array> -> sets VOUT, VRC
  printf '{"minimum": %s}\n' "$1" > "$WORK/res.json"
  printf '{"cap_add": %s, "cap_drop": ["ALL"]}\n' "$2" > "$WORK/dec.json"
  VOUT="$("$PY" "$V2S" "$WORK/res.json" "$WORK/dec.json" 2>"$WORK/verr")"; VRC=$?
}
vcheck() { if [ "$1" = "$2" ]; then echo "ok: $3"; else echo "FAIL: $3 (got '$1' want '$2')"; FAIL=1; fi; }

verdict '[]' '["CHOWN","SETUID"]'                 # declared caps, empty minimum
case "$VOUT" in *'"suspect_nondiscriminating": true'*) echo "ok: empty-min+declared flags suspect";; *) echo "FAIL: suspect flag missing"; FAIL=1;; esac
vcheck "$VRC" 11 "suspect stays over_permissioned (exit 11, not a new gate code)"
if grep -q SUSPECT "$WORK/verr"; then echo "ok: suspect stderr caveat"; else echo "FAIL: no SUSPECT caveat"; FAIL=1; fi

verdict '["CHOWN"]' '["CHOWN","SETUID"]'          # real over-grant (non-empty minimum)
case "$VOUT" in *suspect*) echo "FAIL: non-empty minimum wrongly flagged suspect"; FAIL=1;; *) echo "ok: real over-grant not flagged suspect";; esac
vcheck "$VRC" 11 "real over-grant -> over_permissioned exit 11"

verdict '["CHOWN","SETUID"]' '["CHOWN","SETUID"]' # matches
vcheck "$VRC" 0 "matches -> exit 0"

verdict '[]' '[]'                                 # genuinely no caps declared
case "$VOUT" in *suspect*) echo "FAIL: no-caps-declared wrongly flagged suspect"; FAIL=1;; *) echo "ok: empty declared -> not suspect (real no-caps service)";; esac

if [ "$FAIL" = 0 ]; then echo "compose_derive_selftest: all assertions passed"; else echo "compose_derive_selftest: FAILURES"; fi
exit "$FAIL"
