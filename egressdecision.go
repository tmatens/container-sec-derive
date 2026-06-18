package main

// egressRecommendation is the v0.8 egress decision: the minimum outbound
// allowlist derived from the destinations the workload actually contacted.
// Allowlist is the sorted set of (addr, port) destinations the formatters
// render into nftables / k8s NetworkPolicy rules.
//
// INVERTED RISK (issue #136): unlike caps/devices/fs where the danger is
// *over*-permission, a too-tight egress allowlist BREAKS the app — a
// destination the workload never exercised during the window will be blocked
// by a default-deny ruleset built from this list. Caveat makes that explicit
// and is non-strippable (carried in the JSON, not just stdout), mirroring the
// capadd unused-cap treatment.
type egressRecommendation struct {
	Allowlist []egressDest `json:"allowlist"`
	Caveat    string       `json:"caveat"`
}

// EgressCaveat is the inverted-risk warning carried on every egress
// recommendation: an allowlist is only as complete as the workload that
// produced it, and a missing destination is a hard failure (blocked), not a
// recoverable over-grant.
const EgressCaveat = "Egress allowlist reflects only destinations contacted during observation. A destination the workload did not exercise will be BLOCKED by these rules — verify completeness before enforcing default-deny."

// egressToRecommendation builds the allowlist from the observed (sorted,
// deduplicated) destinations. dests is expected sorted, as aggregateEgress
// returns it; the output preserves that order.
func egressToRecommendation(dests []egressDest) egressRecommendation {
	return egressRecommendation{
		Allowlist: append([]egressDest(nil), dests...),
		Caveat:    EgressCaveat,
	}
}
