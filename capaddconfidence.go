package main

import "fmt"

// computeCapaddConfidence is the v0.5 validator's confidence rubric. The risk it
// prices is the inverse of the other observers' incompleteness risk: the cap
// observer worries about UNDER-reporting a needed cap; the validator's sharp edge
// is the unused -> removable call and the finer-cap substitution, both of which
// OVER-trust workload coverage — a cap that looks unused (or narrowly used) under
// a thin workload may be needed by an unexercised path. So workload presence is
// the dominant factor, and removal/substitution conclusions without a workload
// are surfaced as a moderate caveat. Like the other rubrics the grade is
// reproducible from Factors and capped at moderate while the deferred
// preconditions stand.
//
// There is NO event-count floor: a dangerous cap fires sparsely (a profiler hits
// perf_event_open at startup; a debugger ptraces a handful of times), so volume
// is not a useful proxy for coverage here — the same call the device rubric makes.
func computeCapaddConfidence(s *Sidecar) {
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

	val := s.CapaddValidation
	used, removable := 0, 0
	if val != nil {
		for _, f := range val.Findings {
			if f.Used {
				used++
			}
			if f.Removable {
				removable++
			}
		}
	}
	addInfo(fmt.Sprintf("%d capability/ies observed in use across %d held event(s)", used, s.TraceHealth.EventsRecorded))

	// The removal call is the workload-bounded edge: an "unused" cap is only as
	// trustworthy as the workload's coverage. Reported for auditability; the
	// workload factor below carries the actual grade weight.
	if removable > 0 {
		addInfo(fmt.Sprintf("%d cap(s) flagged removable (granted but no held check fired) — workload-bounded", removable))
	}

	// Drop rate. Same thresholds as the cap/fs/device rubrics; the runner aborts
	// at >=10%, so a sidecar that still carries that rate is surfaced as low.
	switch r := s.TraceHealth.DropRate; {
	case r >= 0.01:
		addLow(fmt.Sprintf("drop rate %.4f >= 1%%", r))
	case r > 0:
		addModerate(fmt.Sprintf("drop rate %.4f > 0 but < 1%%", r))
	}

	// Multi-replica dangerous-cap disagreement.
	switch n := len(s.Target.ReplicaCapDisagreement); {
	case n > 1:
		addLow(fmt.Sprintf("replica cap disagreement spans %d cap(s): %v", n, s.Target.ReplicaCapDisagreement))
	case n == 1:
		addModerate(fmt.Sprintf("replica cap disagreement: %v", s.Target.ReplicaCapDisagreement))
	}

	// Duration soft floor. 0 means "not measured" (fixture mode).
	if s.DurationSeconds > 0 && s.DurationSeconds < 60 {
		addLow(fmt.Sprintf("observation duration %ds < 60s soft floor", s.DurationSeconds))
	}

	// Workload script presence — the dominant completeness signal for this
	// observer, because the removal and substitution conclusions are only valid
	// over the paths the workload exercised. Absence is moderate, as in the cap
	// and device rubrics; with removable findings present it is the caveat a
	// reviewer most needs to see, so the message names that interaction.
	switch {
	case s.Workload != "":
		addInfo("workload script provided (" + s.Workload + ")")
	case removable > 0:
		addModerate("no workload script provided; removable-cap conclusions reflect startup + idle only — verify before dropping")
	default:
		addModerate("no workload script provided (startup + idle only)")
	}

	factors = append(factors,
		"deferred: steady-state detection not yet implemented",
		"deferred: target-exited-early signal not yet wired",
	)

	s.Confidence.Factors = factors
	switch {
	case forceLow, moderateHits >= 2:
		s.Confidence.Level = ConfidenceLow
	default:
		s.Confidence.Level = ConfidenceModerate
	}
}
