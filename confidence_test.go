package main

import (
	"strings"
	"testing"
)

// helperSidecar returns a Sidecar with one "clean" replica's worth of
// inputs that no rubric factor would downgrade. Tests then mutate one
// dimension at a time and assert the resulting grade transition.
func helperSidecar() *Sidecar {
	s := NewSidecar()
	s.Target.Mode = TargetModeContainer
	s.Target.Selector = "test"
	s.Target.ReplicasObserved = 1
	s.Target.PerReplicaEventCounts["r1"] = 5000
	s.Target.PerReplicaCaps["r1"] = []string{"CHOWN", "SETUID"}
	s.Target.DistinctComms = 5
	s.DurationSeconds = 120
	return s
}

// With every determinable factor green, the grade is moderate (capped by
// the deferred High preconditions documented in computeConfidence).
func TestConfidence_AllGreenCapsAtModerate(t *testing.T) {
	s := helperSidecar()
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceModerate {
		t.Fatalf("level = %q, want %q\nfactors: %v", s.Confidence.Level, ConfidenceModerate, s.Confidence.Factors)
	}
	// Deferred markers must be present so reviewers see why we capped.
	// Step 15 (v0.1.0-rc) removed the entrypoint cross-check deferred
	// marker -- that rubric input is now wired; see the dedicated
	// cross-check tests below.
	joined := strings.Join(s.Confidence.Factors, "\n")
	for _, want := range []string{
		"deferred: workload script presence",
		"deferred: steady-state detection",
		"deferred: target-exited-early",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing deferred factor %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "deferred: entrypoint cross-check") {
		t.Errorf("entrypoint cross-check is wired (Step 15); deferred marker should be gone:\n%s", joined)
	}
}

func TestConfidence_LowEventCountForcesLow(t *testing.T) {
	s := helperSidecar()
	s.Target.PerReplicaEventCounts["r1"] = 50
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("level = %q, want %q", s.Confidence.Level, ConfidenceLow)
	}
}

func TestConfidence_ModerateEventCountIsSingleHit(t *testing.T) {
	s := helperSidecar()
	s.Target.PerReplicaEventCounts["r1"] = 500
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceModerate {
		t.Errorf("level = %q, want %q\nfactors: %v", s.Confidence.Level, ConfidenceModerate, s.Confidence.Factors)
	}
}

func TestConfidence_TwoModerateHitsDowngradeToLow(t *testing.T) {
	s := helperSidecar()
	s.Target.PerReplicaEventCounts["r1"] = 500 // moderate hit #1
	s.Target.DistinctComms = 2                 // moderate hit #2
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("two moderates should yield low, got %q\nfactors: %v", s.Confidence.Level, s.Confidence.Factors)
	}
}

func TestConfidence_HighDropRateForcesLow(t *testing.T) {
	s := helperSidecar()
	s.TraceHealth.EventsRecorded = 1000
	s.TraceHealth.EventsDropped = 20
	s.TraceHealth.DropRate = 0.02
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("drop rate >= 1%% should force low, got %q", s.Confidence.Level)
	}
}

func TestConfidence_TinyDropRateIsModerate(t *testing.T) {
	s := helperSidecar()
	s.TraceHealth.EventsRecorded = 10000
	s.TraceHealth.EventsDropped = 1
	s.TraceHealth.DropRate = 0.0001
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceModerate {
		t.Errorf("drop rate <1%% should keep moderate, got %q\nfactors: %v", s.Confidence.Level, s.Confidence.Factors)
	}
}

func TestConfidence_OneCapDisagreementIsModerate(t *testing.T) {
	s := helperSidecar()
	s.Target.ReplicasObserved = 2
	s.Target.PerReplicaEventCounts["r2"] = 5000
	s.Target.PerReplicaCaps["r2"] = []string{"CHOWN"}
	s.Target.ReplicaCapDisagreement = []string{"SETUID"}
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceModerate {
		t.Errorf("1-cap disagreement should be moderate, got %q\nfactors: %v", s.Confidence.Level, s.Confidence.Factors)
	}
}

func TestConfidence_MultiCapDisagreementForcesLow(t *testing.T) {
	s := helperSidecar()
	s.Target.ReplicaCapDisagreement = []string{"FOWNER", "SETGID"}
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf(">1-cap disagreement should be low, got %q", s.Confidence.Level)
	}
}

func TestConfidence_ShortDurationForcesLow(t *testing.T) {
	s := helperSidecar()
	s.DurationSeconds = 30
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("duration <60s should force low, got %q", s.Confidence.Level)
	}
}

// DurationSeconds == 0 means "not measured" (fixture mode); the
// soft-floor must not fire.
func TestConfidence_UnmeasuredDurationDoesNotDowngrade(t *testing.T) {
	s := helperSidecar()
	s.DurationSeconds = 0
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceModerate {
		t.Errorf("duration=0 (unknown) should not force low, got %q\nfactors: %v", s.Confidence.Level, s.Confidence.Factors)
	}
}

func TestConfidence_LowCommDiversityForcesLow(t *testing.T) {
	s := helperSidecar()
	s.Target.DistinctComms = 1
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("comm diversity <2 should force low, got %q", s.Confidence.Level)
	}
}

// With zero events, the comm-diversity check should defer to the
// event-count factor and not stack a separate "comms = 0" low.
func TestConfidence_ZeroEventsDoesNotDoubleCount(t *testing.T) {
	s := helperSidecar()
	delete(s.Target.PerReplicaEventCounts, "r1")
	s.Target.DistinctComms = 0
	computeConfidence(s)
	// Only the event-count low should fire. Find exactly one "low: " in
	// the determinable section (deferreds use a different prefix).
	lows := 0
	for _, f := range s.Confidence.Factors {
		if strings.HasPrefix(f, "low:") {
			lows++
		}
	}
	if lows != 1 {
		t.Errorf("expected exactly 1 low factor (event count), got %d:\n%v", lows, s.Confidence.Factors)
	}
}

// Entrypoint cross-check (Step 15, phase A): skipped state contributes
// no factor and does not pressure the grade.
func TestConfidence_CrossCheckSkippedEmitsNoFactor(t *testing.T) {
	s := helperSidecar()
	// helperSidecar leaves crossCheckStatus empty -- the skipped case.
	computeConfidence(s)
	joined := strings.Join(s.Confidence.Factors, "\n")
	if strings.Contains(joined, "entrypoint cross-check") {
		t.Errorf("skipped cross-check must not emit a factor; got:\n%s", joined)
	}
}

// Clean run with signals matched + covered → informational "clean" factor.
// Phase A: grade stays at moderate (deferred cap), not high.
func TestConfidence_CrossCheckCleanEmitsOkFactor(t *testing.T) {
	s := helperSidecar()
	s.crossCheckStatus = crossCheckStatusOK
	s.ExpectedCapsFromEntrypoint = []string{"CHOWN", "SETUID"}
	// CoverageWarnings empty -- observed covers expected.
	computeConfidence(s)
	joined := strings.Join(s.Confidence.Factors, "\n")
	if !strings.Contains(joined, "entrypoint cross-check clean") {
		t.Errorf("expected clean-cross-check factor; got:\n%s", joined)
	}
	if s.Confidence.Level != ConfidenceModerate {
		t.Errorf("phase A clean cross-check should leave grade at moderate (deferred cap), got %q", s.Confidence.Level)
	}
}

// Ran but no static signals matched → distinct factor so the reviewer
// sees we tried. Distinguishes from skipped (no factor at all).
func TestConfidence_CrossCheckNoSignalsEmitsOkFactor(t *testing.T) {
	s := helperSidecar()
	s.crossCheckStatus = crossCheckStatusOK
	// ExpectedCapsFromEntrypoint empty; CoverageWarnings empty.
	computeConfidence(s)
	joined := strings.Join(s.Confidence.Factors, "\n")
	if !strings.Contains(joined, "entrypoint cross-check ran; no static signals matched") {
		t.Errorf("expected no-signals-matched factor; got:\n%s", joined)
	}
}

// Divergence (warnings non-empty) adds a moderate hit. On its own the
// grade stays at moderate; paired with another moderate it drops to
// low -- phase A keeps the force-low rule unwired.
func TestConfidence_CrossCheckWarningsContributeModerate(t *testing.T) {
	s := helperSidecar()
	s.crossCheckStatus = crossCheckStatusOK
	s.ExpectedCapsFromEntrypoint = []string{"CHOWN", "FOWNER"}
	s.CoverageWarnings = []string{
		"entrypoint references `chown` but FOWNER was not observed. Likely cause: workload did not exercise a code path that needs it.",
	}
	computeConfidence(s)
	joined := strings.Join(s.Confidence.Factors, "\n")
	if !strings.Contains(joined, "1 entrypoint coverage warnings present") {
		t.Errorf("expected warnings-present moderate factor; got:\n%s", joined)
	}
	// Phase A: warnings alone should not force low.
	if s.Confidence.Level != ConfidenceModerate {
		t.Errorf("warnings alone should not force low in phase A; got %q", s.Confidence.Level)
	}
}

// Stacking: warnings moderate + one other moderate → low. This is the
// only existing path to low through the cross-check in phase A.
func TestConfidence_CrossCheckWarningsStackWithAnotherModerateToLow(t *testing.T) {
	s := helperSidecar()
	s.crossCheckStatus = crossCheckStatusOK
	s.ExpectedCapsFromEntrypoint = []string{"CHOWN"}
	s.CoverageWarnings = []string{"dummy warning for test"}
	s.Target.DistinctComms = 2 // second moderate hit
	computeConfidence(s)
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("warnings + one other moderate should downgrade to low; got %q\nfactors: %v",
			s.Confidence.Level, s.Confidence.Factors)
	}
}

// Inspect-unavailable reason surfaces verbatim (truncated) as an
// informational factor. No grade pressure -- cross-check failure is not
// coverage-gap evidence.
func TestConfidence_CrossCheckUnavailableEmitsOkFactor(t *testing.T) {
	s := helperSidecar()
	s.crossCheckStatus = "docker inspect postgres:16: exec: \"docker\": executable file not found"
	computeConfidence(s)
	joined := strings.Join(s.Confidence.Factors, "\n")
	if !strings.Contains(joined, "entrypoint cross-check unavailable: docker inspect postgres:16") {
		t.Errorf("expected unavailable-with-reason factor; got:\n%s", joined)
	}
	if s.Confidence.Level != ConfidenceModerate {
		t.Errorf("unavailable cross-check should not change grade; got %q", s.Confidence.Level)
	}
}

// Aggregating a real fixture should produce a graded sidecar end-to-end.
func TestConfidence_PopulatedByAggregatePlusFinalize(t *testing.T) {
	input := `{"timestamp":1000,"cap":"CAP_CHOWN","proc":{"comm":"postgres","pid":1},"runtime":{"runtimeName":"docker","containerId":"a","containerName":"a","containerImageName":""}}
{"timestamp":1600,"cap":"CAP_SETUID","proc":{"comm":"initdb","pid":1},"runtime":{"runtimeName":"docker","containerId":"a","containerName":"a","containerImageName":""}}
`
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	// Distinct comms must include only post-init events: just "initdb".
	if s.Target.DistinctComms != 1 {
		t.Errorf("DistinctComms = %d, want 1 (post-init only)", s.Target.DistinctComms)
	}
	computeConfidence(s)
	// Two events + 1 distinct comm → low.
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("level = %q, want %q\nfactors: %v", s.Confidence.Level, ConfidenceLow, s.Confidence.Factors)
	}
}
