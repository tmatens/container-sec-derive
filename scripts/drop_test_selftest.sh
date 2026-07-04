#!/usr/bin/env bash
# Hermetic self-test for scripts/drop_test.sh's spec guards.
#
# Asserts the "no non-empty `fixed`" rule: every granted element must be a
# drop-tested candidate, so a spec that declares a `fixed` cap is rejected (exit 5)
# BEFORE any docker work — which is why this runs in CI with no Docker or images.
# The principle: under leave-one-out a truly-required element is always provable as
# a candidate, so `fixed` only ever means "granted, emitted, never tested" (see the
# drop_test.sh header). Run: make drop-test-selftest.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DROP_TEST="${HERE}/drop_test.sh"
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

# run_spec <fixed-yaml-list> -> sets RC and ERR (stderr). The guard runs before
# `docker pull`, so these never reach Docker regardless of what's installed.
run_spec() {
    local fixed="$1"
    cat > "$WORK/spec.yaml" <<EOF
image: example.invalid/no-such-image
tag: latest
dimension: capabilities
fixed: ${fixed}
candidates: ["SETUID", "SETGID"]
correctness: testdata/drop-test/correctness/compose_generic.sh
EOF
    ERR="$(PY=python3 bash "$DROP_TEST" "$WORK/spec.yaml" 2>&1 >/dev/null)"; RC=$?
}

# --- 1. a single fixed cap is rejected with exit 5 and a message naming `fixed`
run_spec '["SYS_ADMIN"]'
assert_eq "$RC" "5" "single fixed cap -> exit 5"
assert_contains "$ERR" "fixed" "rejection message names 'fixed'"

# --- 2. multiple fixed caps are likewise rejected (not a one-element artifact)
run_spec '["SYS_PTRACE", "DAC_OVERRIDE"]'
assert_eq "$RC" "5" "multiple fixed caps -> exit 5"

# NOTE: the accepted path (fixed: []) is exercised by every real spec and the live
# smoke suite; it isn't asserted here because passing the guard proceeds to
# `docker pull`, which this hermetic test deliberately avoids.

if [ "$FAILED" = 0 ]; then echo "drop_test selftest: all PASS"; else echo "drop_test selftest: FAILURES"; fi
exit "$FAILED"
