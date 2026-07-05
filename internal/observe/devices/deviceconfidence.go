package devices

import (
	"fmt"

	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// ComputeDeviceConfidence is the v0.3 device observer's analog of
// computeFSConfidence. The risk the grade prices is the same shape as fs —
// *incompleteness* of the recommendation (a device the workload never opened is
// invisible, and omitting it breaks the container at runtime) — so workload
// presence and the deferred steady-state caveat carry the completeness signal.
//
// The deliberate divergence from the fs rubric: there is NO event-count floor.
// Device opens are inherently sparse — a GPU node is opened once at startup, a
// tun device a handful of times — so write-style "< 100 events ⇒ low" would
// force every honest device observation to low confidence. Coverage for devices
// is a function of whether the workload exercised the device paths at all, which
// the workload-script factor already prices; raw event volume is not a useful
// proxy here. Drop rate, duration floor, and replica disagreement transfer
// unchanged. Like the other rubrics the grade is reproducible from Factors and
// capped at moderate while the deferred preconditions stand.
func ComputeDeviceConfidence(s *sidecar.Sidecar) {
	var c observe.ConfidenceBuilder

	// Device-open volume is reported for auditability but never forces a grade
	// down (see the doc comment): device access is sparse by nature.
	switch n := len(s.DevicePaths); {
	case n == 0:
		c.Info("no non-default device opens observed; no device grants needed for the window")
	default:
		c.Info(fmt.Sprintf("%d non-default device(s) observed across %d open events", n, s.TraceHealth.EventsRecorded))
	}

	// Drop rate. Same thresholds as the cap/fs rubrics; the runner aborts at
	// >=10%, so a sidecar that still carries that rate is surfaced as low.
	c.AddDropRateFactors(s.TraceHealth.DropRate)

	// Multi-replica device-set disagreement (populated in PR5).
	switch n := len(s.Target.ReplicaDeviceDisagreement); {
	case n > 1:
		c.Low(fmt.Sprintf("replica device disagreement spans %d nodes: %v", n, s.Target.ReplicaDeviceDisagreement))
	case n == 1:
		c.Moderate(fmt.Sprintf("replica device disagreement: %v", s.Target.ReplicaDeviceDisagreement))
	}

	// Duration soft floor. 0 means "not measured" (fixture mode).
	if s.DurationSeconds > 0 && s.DurationSeconds < 60 {
		c.Low(fmt.Sprintf("observation duration %ds < 60s soft floor", s.DurationSeconds))
	}

	// Workload script presence. Device access is workload-driven, so absence is
	// the primary completeness caveat for this observer — moderate, per the cap
	// and fs rubrics.
	if s.Workload != "" {
		c.Info("workload script provided (" + s.Workload + ")")
	} else {
		c.Moderate("no workload script provided (startup + idle only)")
	}

	c.Factors = append(c.Factors,
		"deferred: steady-state detection not yet implemented",
		"deferred: target-exited-early signal not yet wired",
	)

	s.Confidence.Factors = c.Factors
	switch {
	case c.ForceLow, c.ModerateHits >= 2:
		s.Confidence.Level = sidecar.ConfidenceLow
	default:
		s.Confidence.Level = sidecar.ConfidenceModerate
	}
}
