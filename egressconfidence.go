package main

import "fmt"

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
func computeEgressConfidence(s *Sidecar) {
	var factors []string
	moderateHits := 0
	forceLow := false

	addLow := func(msg string) {
		factors = append(factors, "low: "+msg)
		forceLow = true
	}
	addModerate := func(msg string) {
		factors = append(factors, "moderate: "+msg)
		moderateHits++
	}
	addInfo := func(msg string) {
		factors = append(factors, "ok: "+msg)
	}

	// Destination volume is reported for auditability but never forces a grade
	// down: outbound connections are sparse by nature.
	switch n := len(s.EgressDestinations); {
	case n == 0:
		addInfo("no outbound connections observed; an empty allowlist would deny all egress — confirm this is intended")
	default:
		addInfo(fmt.Sprintf("%d distinct destination(s) observed across %d connect events", n, s.TraceHealth.EventsRecorded))
	}

	// Drop rate. Same thresholds as the other rubrics; the runner aborts at
	// >=10%, so a sidecar that still carries that rate is surfaced as low.
	switch r := s.TraceHealth.DropRate; {
	case r >= 0.01:
		addLow(fmt.Sprintf("drop rate %.4f >= 1%%", r))
	case r > 0:
		addModerate(fmt.Sprintf("drop rate %.4f > 0 but < 1%%", r))
	}

	// Multi-replica egress-set disagreement.
	switch n := len(s.Target.ReplicaEgressDisagreement); {
	case n > 1:
		addLow(fmt.Sprintf("replica egress disagreement spans %d destinations: %v", n, s.Target.ReplicaEgressDisagreement))
	case n == 1:
		addModerate(fmt.Sprintf("replica egress disagreement: %v", s.Target.ReplicaEgressDisagreement))
	}

	// Duration soft floor. 0 means "not measured" (fixture mode).
	if s.DurationSeconds > 0 && s.DurationSeconds < 60 {
		addLow(fmt.Sprintf("observation duration %ds < 60s soft floor", s.DurationSeconds))
	}

	// Workload script presence. An egress allowlist is only as complete as the
	// traffic the workload generated, and an incomplete allowlist breaks the app
	// (inverted risk) — so absence is forced LOW here, not merely moderate as in
	// the device/fs rubrics.
	if s.Workload != "" {
		addInfo("workload script provided (" + s.Workload + ")")
	} else {
		addLow("no workload script provided (startup + idle only) — an allowlist from idle traffic will almost certainly be incomplete")
	}

	factors = append(factors,
		"deferred: hostname (trace_dns) correlation not yet implemented — allowlist is raw IPs",
		"deferred: steady-state detection not yet implemented",
	)

	s.Confidence.Factors = factors
	switch {
	case forceLow, moderateHits >= 2:
		s.Confidence.Level = ConfidenceLow
	default:
		s.Confidence.Level = ConfidenceModerate
	}
}
