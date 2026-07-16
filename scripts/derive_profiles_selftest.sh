#!/usr/bin/env bash
# Hermetic self-test for scripts/derive_profiles.sh's manifest loop.
#
# Stubs docker / sudo / csd on PATH, so no Docker, images, root, or ig are
# needed — this exercises the loop's own logic: the dimension->observer
# dispatch (all five catalog dimensions), the per-dimension canonicalizers,
# run_args/csd_args pass-through, the FRESH / REVALIDATE / CHANGED / WARN
# verdicts and their exit codes, and APPLY=1's in-place digest bump.
# What it deliberately does NOT cover: real observation (the self-hosted
# integration lane owns that) and the drop-test derivation path (drop_test.sh
# has its own selftest; here only its dimension guard is asserted).
# Run: make derive-profiles-selftest.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/derive_profiles.sh"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

FAILED=0
assert_eq() { # <got> <want> <label>
    if [[ "$1" == "$2" ]]; then echo "PASS: $3"; else
        echo "FAIL: $3 — got [$1] want [$2]"
        FAILED=1
    fi
}
assert_contains() { # <haystack> <needle> <label>
    if [[ "$1" == *"$2"* ]]; then echo "PASS: $3"; else
        echo "FAIL: $3 — [$1] does not contain [$2]"
        FAILED=1
    fi
}

DIGEST_OLD="$(printf 'a%.0s' {1..64})"
DIGEST_NEW="$(printf 'b%.0s' {1..64})"
TODAY="$(date -u +%Y-%m-%d)"

# --- stubs ------------------------------------------------------------------
mkdir -p "$WORK/bin" "$WORK/fixtures"
DOCKER_LOG="$WORK/docker-run.log"
CSD_LOG="$WORK/csd-args.log"

# docker: pull ok; inspect returns a per-image digest (the "fresh" image pins
# to DIGEST_OLD like its committed profile, everything else moved to
# DIGEST_NEW); run is logged and returns a fake id; rm is a no-op.
cat > "$WORK/bin/docker" <<EOF
#!/usr/bin/env bash
cmd="\$1"; shift
case "\$cmd" in
  pull) exit 0 ;;
  inspect)
    img="\${@: -1}"; name="\${img%:*}"
    case "\$name" in
      example.test/fresh) echo "\${name}@sha256:${DIGEST_OLD}" ;;
      *)                  echo "\${name}@sha256:${DIGEST_NEW}" ;;
    esac ;;
  run) echo "\$@" >> "${DOCKER_LOG}"; echo fakecid ;;
  rm) exit 0 ;;
  *) exit 0 ;;
esac
EOF

# sudo: drop leading flags (-n), exec the command.
cat > "$WORK/bin/sudo" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do shift; done
exec "$@"
EOF

# csd: log argv, emit the per-observer compose-lint-profile fixture on stdout.
cat > "$WORK/bin/csd" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "${CSD_LOG}"
observer=""
while [ \$# -gt 0 ]; do
  [ "\$1" = "--observe" ] && observer="\$2"
  shift
done
cat "$WORK/fixtures/\${observer}.yaml"
EOF
chmod +x "$WORK/bin/docker" "$WORK/bin/sudo" "$WORK/bin/csd"

# --- catalog fixtures --------------------------------------------------------
CATALOG="$WORK/catalog"
mkdir -p "$CATALOG/derivation" "$CATALOG/catalog/test" "$CATALOG/profiles/workloads"
printf '#!/bin/sh\nexit 0\n' > "$CATALOG/profiles/workloads/noop.sh"
chmod +x "$CATALOG/profiles/workloads/noop.sh"

committed_profile() { # <path> <dimension-block...>
    local path="$1"; shift
    { echo 'schema_version: "1.0"'
      echo 'image: example.test/img'
      echo 'status: validated'
      echo 'dimensions:'
      printf '%s\n' "$@"
    } > "$path"
}

# devices — pinned to OLD (stale), stub re-derives the same recommendation.
committed_profile "$CATALOG/catalog/test/devices.yaml" \
  '  devices:' \
  '    devices: [/dev/dri]' \
  '    derived_caps: []' \
  '    derivation:' \
  "      validated_image: example.test/devimg@sha256:${DIGEST_OLD}" \
  '      validated_date: "2026-07-01"'
cat > "$WORK/fixtures/devices.yaml" <<'EOF'
schema_version: "1.0"
image: example.test/devimg
status: validated
dimensions:
  devices:
    devices: [/dev/dri]
    derived_caps: []
EOF

# privileged_decomposition — stale, unchanged recommendation incl. partial flag.
committed_profile "$CATALOG/catalog/test/priv.yaml" \
  '  privileged_decomposition:' \
  '    cap_add: [SYS_NICE]' \
  '    devices: [/dev/dri]' \
  '    partial: true' \
  '    derivation:' \
  "      validated_image: example.test/privimg@sha256:${DIGEST_OLD}" \
  '      validated_date: "2026-07-01"'
cat > "$WORK/fixtures/privileged.yaml" <<'EOF'
schema_version: "1.0"
image: example.test/privimg
status: validated
dimensions:
  privileged_decomposition:
    cap_add: [SYS_NICE]
    devices: [/dev/dri]
    partial: true
EOF

# cap_add_validation — stale, and the stub derives a DIFFERENT recommendation.
committed_profile "$CATALOG/catalog/test/capadd.yaml" \
  '  cap_add_validation:' \
  '    recommended_cap_add: [NET_RAW]' \
  '    derivation:' \
  "      validated_image: example.test/capaddimg@sha256:${DIGEST_OLD}" \
  '      validated_date: "2026-07-01"'
cat > "$WORK/fixtures/capadd.yaml" <<'EOF'
schema_version: "1.0"
image: example.test/capaddimg
status: validated
dimensions:
  cap_add_validation:
    recommended_cap_add: []
EOF

# fresh — pinned digest equals the stub's current digest; never re-derived.
committed_profile "$CATALOG/catalog/test/fresh.yaml" \
  '  capabilities:' \
  '    cap_add: [CHOWN]' \
  '    derivation:' \
  "      validated_image: example.test/fresh@sha256:${DIGEST_OLD}" \
  '      validated_date: "2026-07-01"'

run_loop() { # <manifest-body> [env-overrides...] -> sets RC and OUT
    printf 'images:\n%s\n' "$1" > "$CATALOG/derivation/manifest.yaml"
    shift
    : > "$DOCKER_LOG"; : > "$CSD_LOG"
    OUT="$(PATH="$WORK/bin:$PATH" CATALOG="$CATALOG" CSD="$WORK/bin/csd" \
           "$@" bash "$SCRIPT" 2>&1)"; RC=$?
}

# --- 1. FRESH + two REVALIDATEs (devices, privileged) -> exit 0; APPLY bumps
run_loop '
  - profile: catalog/test/fresh.yaml
    image: example.test/fresh
    tag: "1"
    dimension: capabilities
    method: bpf-observation
    workload: profiles/workloads/noop.sh
  - profile: catalog/test/devices.yaml
    image: example.test/devimg
    tag: "1"
    dimension: devices
    method: bpf-observation
    workload: profiles/workloads/noop.sh
    run_args: "--device /dev/dri"
  - profile: catalog/test/priv.yaml
    image: example.test/privimg
    tag: "1"
    dimension: privileged_decomposition
    method: bpf-observation
    workload: profiles/workloads/noop.sh
    run_args: "--privileged"
' env APPLY=1
assert_eq "$RC" "0" "fresh + unchanged revalidations -> exit 0"
assert_contains "$OUT" "FRESH catalog/test/fresh.yaml" "digest-matched entry is FRESH"
assert_contains "$OUT" "REVALIDATE catalog/test/devices.yaml" "unchanged devices reco REVALIDATEs"
assert_contains "$OUT" "REVALIDATE catalog/test/priv.yaml" "unchanged privileged reco REVALIDATEs"
assert_contains "$(cat "$DOCKER_LOG")" "--device /dev/dri" "devices run_args reach docker run"
assert_contains "$(cat "$DOCKER_LOG")" "--privileged" "privileged run_args reach docker run"
assert_contains "$(cat "$CSD_LOG")" "--observe devices" "devices dimension dispatches --observe devices"
assert_contains "$(cat "$CSD_LOG")" "--observe privileged" "privileged_decomposition dispatches --observe privileged"
assert_contains "$(cat "$CATALOG/catalog/test/devices.yaml")" "sha256:${DIGEST_NEW}" "APPLY=1 bumps validated_image digest"
assert_contains "$(cat "$CATALOG/catalog/test/devices.yaml")" "validated_date: \"${TODAY}\"" "APPLY=1 bumps validated_date"

# --- 2. capadd recommendation differs -> CHANGED, exit 12, csd_args forwarded
run_loop '
  - profile: catalog/test/capadd.yaml
    image: example.test/capaddimg
    tag: "1"
    dimension: cap_add_validation
    method: bpf-observation
    workload: profiles/workloads/noop.sh
    run_args: "--cap-add NET_RAW --cap-add SYS_ADMIN"
    csd_args: "--cap-add NET_RAW,SYS_ADMIN"
' env
assert_eq "$RC" "12" "changed recommendation -> exit 12"
assert_contains "$OUT" "CHANGED catalog/test/capadd.yaml" "capadd reco diff surfaces as CHANGED"
assert_contains "$OUT" "committed [NET_RAW] vs derived []" "verdict shows both canonical recommendations"
assert_contains "$(cat "$CSD_LOG")" "--observe capadd" "cap_add_validation dispatches --observe capadd"
assert_contains "$(cat "$CSD_LOG")" "--cap-add NET_RAW,SYS_ADMIN" "csd_args reach the csd invocation"
assert_contains "$(cat "$CATALOG/catalog/test/capadd.yaml")" "sha256:${DIGEST_OLD}" "CHANGED is never auto-applied"

# --- 3. coverage gaps stay advisory: unknown dimension + drop-test on devices
run_loop '
  - profile: catalog/test/devices.yaml
    image: example.test/devimg
    tag: "1"
    dimension: filesytem
    method: bpf-observation
    workload: profiles/workloads/noop.sh
  - profile: catalog/test/capadd.yaml
    image: example.test/capaddimg
    tag: "1"
    dimension: devices
    method: drop-test
    workload: profiles/workloads/noop.sh
' env
assert_eq "$RC" "10" "coverage gaps -> advisory exit 10"
assert_contains "$OUT" "unknown dimension 'filesytem'" "a dimension typo is rejected, not silently revalidated"
assert_contains "$OUT" "drop-test cannot derive 'devices'" "drop-test guards its caps/fs-only scope"
assert_eq "$(wc -l < "$DOCKER_LOG" | tr -d ' ')" "0" "neither gap entry reaches docker run"

if [ "$FAILED" = 0 ]; then echo "derive_profiles selftest: all PASS"; else echo "derive_profiles selftest: FAILURES"; fi
exit "$FAILED"
