package main

import "fmt"

// computeConfidence populates s.Confidence by mechanically applying
// PLAN.md §Confidence scoring to the inputs available on the sidecar.
// The grade must be reproducible from s.Confidence.Factors -- every
// factor that fires is appended verbatim, never per-image-special-cased.
//
// Step 6 implements the deterministic subset of the rubric. Inputs we
// don't yet collect are surfaced as "deferred:" factors and cap the
// achievable level at moderate; later steps wire them in:
//
//   - workload script presence -- ships with the formatter / contribution flow
//   - entrypoint cross-check  -- Step 9
//   - steady-state detection  -- needs time-windowed aggregation
//   - target exited early     -- needs observe()-side instrumentation
//
// Reporting deferred factors honestly (rather than silently grading
// High) keeps the rubric trustworthy while the rest of the inputs land.
func computeConfidence(s *Sidecar) {
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

	// Event count (post-init-filter).
	eventCount := 0
	for _, n := range s.Target.PerReplicaEventCounts {
		eventCount += n
	}
	switch {
	case eventCount < 100:
		addLow(fmt.Sprintf("event count %d < 100", eventCount))
	case eventCount < 1000:
		addModerate(fmt.Sprintf("event count %d in 100-999", eventCount))
	default:
		addInfo(fmt.Sprintf("event count %d >= 1000", eventCount))
	}

	// Drop rate. The runner is meant to abort at >=10%; if a sidecar with
	// that rate still reaches us, surface it as low rather than trust it.
	switch r := s.TraceHealth.DropRate; {
	case r >= 0.01:
		addLow(fmt.Sprintf("drop rate %.4f >= 1%%", r))
	case r > 0:
		addModerate(fmt.Sprintf("drop rate %.4f > 0 but < 1%%", r))
	}

	// Replica disagreement under --all-matching.
	switch n := len(s.Target.ReplicaCapDisagreement); {
	case n > 1:
		addLow(fmt.Sprintf("replica cap disagreement spans %d caps: %v", n, s.Target.ReplicaCapDisagreement))
	case n == 1:
		addModerate(fmt.Sprintf("replica cap disagreement: %v", s.Target.ReplicaCapDisagreement))
	}

	// Duration soft floor. DurationSeconds == 0 means "not measured"
	// (e.g. fixture mode); only fire the floor when we actually know.
	if s.DurationSeconds > 0 && s.DurationSeconds < 60 {
		addLow(fmt.Sprintf("observation duration %ds < 60s soft floor", s.DurationSeconds))
	}

	// Comm diversity (post-init-window). Skip when there were no events
	// at all -- the event-count factor already covers that case.
	if eventCount > 0 {
		switch d := s.Target.DistinctComms; {
		case d < 2:
			addLow(fmt.Sprintf("distinct comms = %d < 2", d))
		case d == 2:
			addModerate("distinct comms = 2")
		default:
			addInfo(fmt.Sprintf("distinct comms = %d", d))
		}
	}

	// Deferred preconditions for High. These cap the achievable grade at
	// moderate until later steps wire in the inputs.
	factors = append(factors,
		"deferred: workload script presence not yet recorded",
		"deferred: entrypoint cross-check not yet implemented (Step 9)",
		"deferred: steady-state detection not yet implemented",
		"deferred: target-exited-early signal not yet wired",
	)

	s.Confidence.Factors = factors
	switch {
	case forceLow, moderateHits >= 2:
		s.Confidence.Level = ConfidenceLow
	default:
		// Capped at moderate while deferred preconditions stand.
		s.Confidence.Level = ConfidenceModerate
	}
}
