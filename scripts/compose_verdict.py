#!/usr/bin/env python3
# Compare a drop_test result's derived minimum to a service's declared caps and
# emit the deploy_check verdict block. Pure (json only, no docker/yaml), so it is
# unit-testable hermetically — see scripts/compose_derive_selftest.sh.
#
#   compose_verdict.py <result.json> <declared.json>   # prints the augmented result JSON
import sys, json

result = json.load(open(sys.argv[1]))
declared = json.load(open(sys.argv[2]))
minimum = set(result.get("minimum") or [])
cap_add = set(declared.get("cap_add") or [])
drops_all = "ALL" in {c.upper() for c in declared.get("cap_drop") or []}

# Confidence guard (csd#340 capstone). A chown-class cap derived REMOVABLE is only
# trustworthy if every path the container chowns/writes was in its worst-case
# initial state during the run. drop_test emits `fidelity.guaranteed=false` +
# `unguaranteed_mounts` when a mount's initial state could not be reproduced (a
# ${VAR} fresh-vol has no pre-existing foreign CONTENT; a passed-through named
# volume inits root-owned-empty) — the #337 / item-2 blind spot. In that case a
# chown-class cap that is DECLARED but derived removable is NOT confidently
# droppable: we SUPPRESS the drop (keep the cap) and record it in
# `low_confidence_keep` rather than emit a "drop" we can't prove. A false-removable
# breaks prod; a kept-but-unneeded cap is merely non-minimal — the safe direction.
# Only chown-class caps are guarded (their necessity is what mount-state fidelity
# governs); a removable non-chown cap is unaffected. The guard never adds a drop or
# changes an under_permissioned verdict, so it can only make deploy-check MORE
# conservative — it cannot red the gate.
CHOWN_CLASS = {"CHOWN", "FOWNER", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FSETID"}
fidelity = result.get("fidelity") or {}
guaranteed = fidelity.get("guaranteed", True)
low_confidence_keep = []
if not guaranteed:
    # A declared chown-class cap not in the derived minimum would otherwise be a
    # "drop"; keep it (add to the effective minimum) and flag it low-confidence.
    low_confidence_keep = sorted((cap_add & CHOWN_CLASS) - minimum)
    minimum = minimum | set(low_confidence_keep)

recommended = {"cap_drop": ["ALL"], "cap_add": sorted(minimum)}
if drops_all:
    over = sorted(cap_add - minimum)      # granted but not needed -> drop
    add = sorted(minimum - cap_add)       # needed but not granted -> would break
    verdict = ("under_permissioned" if add
               else "over_permissioned" if over
               else "matches")
else:
    over = sorted(cap_add)                # everything, since we recommend cap_drop: ALL
    add = sorted(minimum - cap_add)
    verdict = "not_minimized"

# An EMPTY derived minimum while the service DECLARED caps is suspect (#340 item 1):
# it is either a real total over-grant, or a non-discriminating correctness check
# (the netdata trap) that would derive [] for anything. We cannot tell which from
# the caps alone, so flag it rather than emit a confident "drop everything." The
# robust disambiguation is a per-service negative control (apptier over_hardening,
# #260). Only meaningful when caps were actually declared and dropped-by-default.
suspect_nondiscriminating = drops_all and bool(cap_add) and not minimum

deploy_check = {
    "recommended": recommended,
    "declared": {"cap_drop": sorted(declared.get("cap_drop") or []),
                 "cap_add": sorted(cap_add)},
    "verdict": verdict,
    "drop": over,
    "add": add,
}
if suspect_nondiscriminating:
    deploy_check["suspect_nondiscriminating"] = True
if low_confidence_keep:
    deploy_check["low_confidence_keep"] = low_confidence_keep
    deploy_check["low_confidence_reason"] = (
        "chown-class cap(s) kept despite deriving removable: the drop-test could not "
        "guarantee the worst-case initial state of " + ", ".join(fidelity.get("unguaranteed_mounts") or []) +
        " (a ${VAR} fresh-vol carries no pre-existing foreign content; a passed-through named "
        "volume inits root-owned-empty), so removability is unproven (#340). Not recommending the drop.")
result["deploy_check"] = deploy_check
print(json.dumps(result, indent=2))

msg = {
    "matches": "declared cap_add matches the derived minimum",
    "over_permissioned": f"over-permissioned: drop {over} (declared, not needed)",
    "under_permissioned": f"UNDER-permissioned: missing {add} (needed — would break); also drop {over}",
    "not_minimized": f"no cap_drop: ALL — recommend cap_drop:[ALL] + cap_add:{sorted(minimum)}",
}[verdict]
if suspect_nondiscriminating:
    msg += (" — SUSPECT: empty minimum but caps were declared; the correctness check may be "
            "non-discriminating (rubber-stamp / netdata trap). Verify it fails on a too-tight "
            "config before trusting 'drop all' (#340).")
if low_confidence_keep:
    msg += (f" — LOW-CONFIDENCE KEEP {low_confidence_keep}: derived removable but mount-state "
            "fidelity unguaranteed, so the drop is suppressed (kept), not recommended (#340).")
print(f"compose_derive: {verdict} — {msg}", file=sys.stderr)

# Exit codes make it a gate (mirrors csd verify): 0 matches, 10 not-minimized,
# 11 over-permissioned, 12 under-permissioned (missing caps — would break, the
# hard failure). A caller picks its threshold (e.g. fail >=12, warn on 10/11).
# suspect_nondiscriminating is a caveat on the verdict, not its own exit code.
sys.exit({"matches": 0, "not_minimized": 10,
          "over_permissioned": 11, "under_permissioned": 12}[verdict])
