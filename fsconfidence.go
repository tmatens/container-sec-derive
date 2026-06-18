package main

import (
	"fmt"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// computeFSConfidence is the v0.2 fs observer's analog of computeConfidence.
// The cap rubric's factors are mostly cap-specific (comm diversity, entrypoint
// cross-check, replica *cap* disagreement), so the fs observer scores against
// the subset that transfers plus one fs-specific reading of event volume.
//
// The semantic difference worth stating: `read_only: true` is safe regardless
// of how much was observed — the risk the rubric must price is *incompleteness*
// of the tmpfs list (a write path the workload never exercised is invisible,
// and omitting it breaks the container at runtime). So a sparse observation is
// low-confidence about completeness even though the headline recommendation is
// sound. That is why low write-event volume and a missing workload script both
// pull the grade down here, exactly as under-observation does for caps.
//
// Like computeConfidence, the grade is reproducible from Factors and is capped
// at moderate while the deferred preconditions (steady-state detection,
// target-exited-early) stand. Multi-replica write-path disagreement is wired in
// PR-C; this function already reads s.Target.ReplicaWritePathDisagreement so the
// factor lights up automatically once that field is populated.
func computeFSConfidence(s *sidecar.Sidecar) {
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

	// Write-event volume = coverage proxy for the tmpfs list's completeness.
	switch n := s.TraceHealth.EventsRecorded; {
	case n < 100:
		addLow(fmt.Sprintf("write-event count %d < 100; tmpfs list may be incomplete", n))
	case n < 1000:
		addModerate(fmt.Sprintf("write-event count %d in 100-999", n))
	default:
		addInfo(fmt.Sprintf("write-event count %d >= 1000", n))
	}

	// Drop rate. Same thresholds as the cap rubric; the runner aborts at
	// >=10%, so a sidecar that still carries that rate is surfaced as low.
	switch r := s.TraceHealth.DropRate; {
	case r >= 0.01:
		addLow(fmt.Sprintf("drop rate %.4f >= 1%%", r))
	case r > 0:
		addModerate(fmt.Sprintf("drop rate %.4f > 0 but < 1%%", r))
	}

	// Multi-replica write-path disagreement (populated in PR-C).
	switch n := len(s.Target.ReplicaWritePathDisagreement); {
	case n > 1:
		addLow(fmt.Sprintf("replica write-path disagreement spans %d paths: %v", n, s.Target.ReplicaWritePathDisagreement))
	case n == 1:
		addModerate(fmt.Sprintf("replica write-path disagreement: %v", s.Target.ReplicaWritePathDisagreement))
	}

	// Duration soft floor. 0 means "not measured" (fixture mode).
	if s.DurationSeconds > 0 && s.DurationSeconds < 60 {
		addLow(fmt.Sprintf("observation duration %ds < 60s soft floor", s.DurationSeconds))
	}

	// Workload script presence. Writes are workload-driven, so absence is a
	// genuine coverage caveat — moderate, per the cap rubric's treatment.
	if s.Workload != "" {
		addInfo("workload script provided (" + s.Workload + ")")
	} else {
		addModerate("no workload script provided (startup + idle only)")
	}

	factors = append(factors,
		"deferred: steady-state detection not yet implemented",
		"deferred: target-exited-early signal not yet wired",
	)

	s.Confidence.Factors = factors
	switch {
	case forceLow, moderateHits >= 2:
		s.Confidence.Level = sidecar.ConfidenceLow
	default:
		s.Confidence.Level = sidecar.ConfidenceModerate
	}
}
