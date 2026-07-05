package egress

import (
	"fmt"

	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// computeEgressConfidence is the v0.8 egress observer's analog of
// computeDeviceConfidence. The risk it prices is *incompleteness* — and for
// egress that risk is the sharpest of any observer: a destination the workload
// never contacted is invisible, and a default-deny ruleset built from this
// allowlist will BLOCK it at runtime (the inverted risk of issue #136). So
// workload presence is the dominant completeness factor here, weighted harder
// than in the device rubric.
//
// Like the device rubric there is NO event-count floor: outbound connections
// are sparse (an app dials its database once and a CDN a handful of times), so
// raw connect volume is not a useful coverage proxy. Drop rate, duration floor,
// and replica disagreement transfer unchanged. The grade is reproducible from
// Factors and capped at moderate while the deferred preconditions stand.
func computeEgressConfidence(s *sidecar.Sidecar) {
	var c observe.ConfidenceBuilder

	// Destination volume is reported for auditability but never forces a grade
	// down: outbound connections are sparse by nature.
	switch n := len(s.EgressDestinations); {
	case n == 0:
		c.Info("no outbound connections observed; an empty allowlist would deny all egress — confirm this is intended")
	default:
		c.Info(fmt.Sprintf("%d distinct destination(s) observed across %d connect events", n, s.TraceHealth.EventsRecorded))
	}

	// Drop rate. Same thresholds as the other rubrics; the runner aborts at
	// >=10%, so a sidecar that still carries that rate is surfaced as low.
	c.AddDropRateFactors(s.TraceHealth.DropRate)

	// Multi-replica egress-set disagreement.
	switch n := len(s.Target.ReplicaEgressDisagreement); {
	case n > 1:
		c.Low(fmt.Sprintf("replica egress disagreement spans %d destinations: %v", n, s.Target.ReplicaEgressDisagreement))
	case n == 1:
		c.Moderate(fmt.Sprintf("replica egress disagreement: %v", s.Target.ReplicaEgressDisagreement))
	}

	// Duration soft floor. 0 means "not measured" (fixture mode).
	if s.DurationSeconds > 0 && s.DurationSeconds < 60 {
		c.Low(fmt.Sprintf("observation duration %ds < 60s soft floor", s.DurationSeconds))
	}

	// Workload script presence. An egress allowlist is only as complete as the
	// traffic the workload generated, and an incomplete allowlist breaks the app
	// (inverted risk) — so absence is forced LOW here, not merely moderate as in
	// the device/fs rubrics.
	if s.Workload != "" {
		c.Info("workload script provided (" + s.Workload + ")")
	} else {
		c.Low("no workload script provided (startup + idle only) — an allowlist from idle traffic will almost certainly be incomplete")
	}

	// Hostname (trace_dns) correlation: when DNS was observed the allowlist gains
	// hostname annotations and the resolver endpoint (issue #159), lifting the
	// raw-IP limitation and — via the resolver rule — removing the most common
	// default-deny breakage. It does not raise the grade (incompleteness still
	// dominates), but the factor must reflect reality rather than the old
	// "not implemented" deferral.
	if egressDNSObserved(s) {
		annotated := 0
		for _, d := range s.EgressDestinations {
			if len(d.Hostnames) > 0 {
				annotated++
			}
		}
		c.Factors = append(c.Factors, fmt.Sprintf(
			"ok: hostnames correlated via trace_dns (%d/%d destination(s) named); %d DNS resolver(s) included in the allowlist",
			annotated, len(s.EgressDestinations), len(s.EgressRecommendation.Resolvers)))
	} else {
		c.Factors = append(c.Factors,
			"deferred: no DNS observed (trace_dns) — allowlist is raw IPs and omits the resolver; ensure UDP/53 egress is permitted separately")
	}
	c.Factors = append(c.Factors, "deferred: steady-state detection not yet implemented")

	s.Confidence.Factors = c.Factors
	switch {
	case c.ForceLow, c.ModerateHits >= 2:
		s.Confidence.Level = sidecar.ConfidenceLow
	default:
		s.Confidence.Level = sidecar.ConfidenceModerate
	}
}

// egressDNSObserved reports whether trace_dns correlation was applied: a
// resolver was recorded or at least one destination carries hostnames. Either
// implies the DNS signal was present for this run.
func egressDNSObserved(s *sidecar.Sidecar) bool {
	if s.EgressRecommendation != nil && len(s.EgressRecommendation.Resolvers) > 0 {
		return true
	}
	for _, d := range s.EgressDestinations {
		if len(d.Hostnames) > 0 {
			return true
		}
	}
	return false
}
