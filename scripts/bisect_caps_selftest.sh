#!/usr/bin/env bash
# Hermetic self-test for the scripts/bisect_caps.sh capability minimizer.
#
# Drives greedy_minimize / multi_order_minimize / verify_minimal with SYNTHETIC
# oracles (no Docker, no images) so the algorithm — and specifically the issue
# #32 stabilization fix — is validated in CI, where the real container-driven
# bisection (make ground-truth-*) is dispatch-only. Run: make bisect-selftest.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Source the minimizer; the source-guard in bisect_caps.sh keeps main() from
# running, so only the functions + DEFAULT_CAPS are pulled in.
# shellcheck source=scripts/bisect_caps.sh
source "${HERE}/bisect_caps.sh"
set +e # the self-test manages control flow with explicit status checks

FAILED=0
assert_eq() { # <got> <want> <label>
    if [[ "$1" == "$2" ]]; then echo "PASS: $3"; else
        echo "FAIL: $3 — got [$1] want [$2]"
        FAILED=1
    fi
}

DEFAULT="${DEFAULT_CAPS[*]}"

# --- synthetic oracles ($1 = space-separated cap set; 0 = workload passes) ---

# Distinct, non-substitutable: needs exactly SETGID + SETUID.
oracle_distinct() { _has SETGID "$1" && _has SETUID "$1"; }

# Substitutable: needs SETUID AND (CHOWN OR KILL) — either alternative suffices.
oracle_subst() { _has SETUID "$1" && { _has CHOWN "$1" || _has KILL "$1"; }; }

# Order-locked-in (#32): needs SETUID; KILL is needed ONLY while CHOWN is
# present. A greedy single pass that tests KILL while CHOWN is still kept locks
# KILL in; once CHOWN is later dropped KILL is unneeded, but plain greedy never
# re-tests it. The stabilization fixpoint must drop it — for EVERY order.
oracle_locked() { _has SETUID "$1" && { _has KILL "$1" || ! _has CHOWN "$1"; }; }

# Only SETUID needed (for the verify_minimal subset-detection test).
oracle_onlysetuid() { _has SETUID "$1"; }

# --- 1. distinct caps → the exact set, order-independent ---
CSD_BISECT_ORACLE=oracle_distinct
MIN_LOG=()
greedy_minimize "$DEFAULT"
assert_eq "$GM_RESULT" "SETGID SETUID" "distinct caps minimize to {SETGID,SETUID}"

# --- 2. order-locked-in: stabilization yields {SETUID} for EVERY order (the
#        core #32 fix — a plain greedy single pass would keep KILL for the
#        adversarial 'KILL before CHOWN' order). ---
CSD_BISECT_ORACLE=oracle_locked
for order in \
    "KILL CHOWN SETUID FOWNER" \
    "CHOWN KILL SETUID" \
    "SETUID FOWNER KILL CHOWN" \
    "$DEFAULT"; do
    MIN_LOG=()
    greedy_minimize "$order"
    assert_eq "$GM_RESULT" "SETUID" "order-locked-in fixed by stabilization (order: ${order})"
done

# --- 3. substitutability is order-dependent in IDENTITY but stable in SIZE ---
CSD_BISECT_ORACLE=oracle_subst
MIN_LOG=()
greedy_minimize "KILL SETUID CHOWN" # KILL tested first → KILL dropped, CHOWN kept
r1="$GM_RESULT"
MIN_LOG=()
greedy_minimize "CHOWN SETUID KILL" # CHOWN tested first → CHOWN dropped, KILL kept
r2="$GM_RESULT"
assert_eq "$r1" "CHOWN SETUID" "substitutable: KILL-first keeps {CHOWN,SETUID}"
assert_eq "$r2" "KILL SETUID" "substitutable: CHOWN-first keeps {KILL,SETUID}"
if [[ "$r1" != "$r2" ]]; then
    echo "PASS: substitutability manifests as order-dependent identity (same size)"
else
    echo "FAIL: expected different kept sets across orders"
    FAILED=1
fi
# multi-order picks a size-2 set and flags substitutability (20 shuffles → the
# chance both alternatives never both appear is ~2*0.5^20, negligible).
MIN_LOG=()
SUBSTITUTABLE=0
ORDERS=20 multi_order_minimize "$DEFAULT"
assert_eq "$(_count "$MOM_RESULT")" "2" "multi-order keeps a size-2 set"
assert_eq "$SUBSTITUTABLE" "1" "multi-order flags substitutability"

# --- 4. verify_minimal ---
# 4a. a truly 1-minimal set → no proper subset passes (returns 0).
CSD_BISECT_ORACLE=oracle_distinct
if verify_minimal "SETGID SETUID" >/dev/null; then
    echo "PASS: verify_minimal confirms {SETGID,SETUID} is 1-minimal"
else
    echo "FAIL: verify_minimal wrongly flagged {SETGID,SETUID}"
    FAILED=1
fi
# 4b. a NON-minimal set → finds the passing proper subset (returns 1 + subset).
CSD_BISECT_ORACLE=oracle_onlysetuid
smaller="$(verify_minimal "SETGID SETUID")"
rc=$?
if ((rc == 1)); then
    assert_eq "$smaller" "SETUID" "verify_minimal finds the passing proper subset {SETUID}"
else
    echo "FAIL: verify_minimal missed the smaller passing subset (rc=${rc})"
    FAILED=1
fi

echo "----"
if ((FAILED)); then
    echo "bisect-selftest: FAILURES"
    exit 1
fi
echo "bisect-selftest: all passed"
