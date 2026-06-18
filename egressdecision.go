package main

import "github.com/tmatens/container-sec-derive/internal/sidecar"

// EgressCaveat is the inverted-risk warning carried on every egress
// recommendation: an allowlist is only as complete as the workload that
// produced it, and a missing destination is a hard failure (blocked), not a
// recoverable over-grant.
const EgressCaveat = "Egress allowlist reflects only destinations contacted during observation. A destination the workload did not exercise will be BLOCKED by these rules — verify completeness before enforcing default-deny."

// egressToRecommendation builds the allowlist from the observed (sorted,
// deduplicated) destinations. dests is expected sorted, as aggregateEgress
// returns it; the output preserves that order.
func egressToRecommendation(dests []sidecar.EgressDest) sidecar.EgressRecommendation {
	return sidecar.EgressRecommendation{
		Allowlist: append([]sidecar.EgressDest(nil), dests...),
		Caveat:    EgressCaveat,
	}
}
