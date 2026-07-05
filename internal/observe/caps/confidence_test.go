package caps

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// White-box tests for the confidence rubric (#289). A grade-calc bug that still
// matched the golden JSON would ship undetected, so these drive each rubric
// factor directly and assert the level transition it causes. The rubric is
// currently capped at moderate (deferred preconditions), so every case is either
// moderate (baseline / a single moderate hit) or low (any low hit, or >=2
// moderate hits).

// cleanModerate returns a sidecar whose inputs all score "ok" — the rubric's
// best achievable grade today (moderate, capped by the deferred preconditions).
// Each test perturbs exactly one input to assert that factor's effect.
func cleanModerate() *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Target.PerReplicaEventCounts = map[string]int{"r0": 2000} // >=1000 -> info
	s.TraceHealth.DropRate = 0                                  // no factor
	s.Target.ReplicaCapDisagreement = nil                       // no factor
	s.DurationSeconds = 120                                     // above the 60s floor
	s.Target.DistinctComms = 5                                  // >2 -> info
	s.Workload = "workload.sh"                                  // present -> info
	s.CrossCheckStatus = sidecar.CrossCheckStatusOK
	s.ExpectedCapsFromEntrypoint = []string{"CHOWN"} // clean cross-check -> info
	s.CoverageWarnings = nil
	return s
}

func gradeOf(s *sidecar.Sidecar) string {
	ComputeConfidence(s)
	return s.Confidence.Level
}

func TestConfidence_CleanBaselineIsModerate(t *testing.T) {
	s := cleanModerate()
	if got := gradeOf(s); got != sidecar.ConfidenceModerate {
		t.Fatalf("clean baseline grade = %q, want moderate (capped by deferred preconditions):\n%s",
			got, strings.Join(s.Confidence.Factors, "\n"))
	}
	// The cap is explicit: deferred preconditions must be recorded so the grade
	// is reproducible from the factors.
	joined := strings.Join(s.Confidence.Factors, "\n")
	if !strings.Contains(joined, "deferred:") {
		t.Errorf("expected a deferred: factor capping the grade, got:\n%s", joined)
	}
}

func TestConfidence_LowFactorsForceLow(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*sidecar.Sidecar)
		factor string
	}{
		{"tiny event count", func(s *sidecar.Sidecar) { s.Target.PerReplicaEventCounts = map[string]int{"r0": 50} }, "event count"},
		{"drop rate >=1%", func(s *sidecar.Sidecar) { s.TraceHealth.DropRate = 0.02 }, "drop rate"},
		{"disagreement spans >1", func(s *sidecar.Sidecar) { s.Target.ReplicaCapDisagreement = []string{"CHOWN", "SETUID"} }, "replica cap disagreement"},
		{"below duration floor", func(s *sidecar.Sidecar) { s.DurationSeconds = 30 }, "soft floor"},
		{"single comm", func(s *sidecar.Sidecar) { s.Target.DistinctComms = 1 }, "distinct comms"},
		{"coverage warnings", func(s *sidecar.Sidecar) { s.CoverageWarnings = []string{"entrypoint references `chown`"} }, "coverage warnings"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := cleanModerate()
			c.mutate(s)
			if got := gradeOf(s); got != sidecar.ConfidenceLow {
				t.Errorf("grade = %q, want low:\n%s", got, strings.Join(s.Confidence.Factors, "\n"))
			}
			if joined := strings.Join(s.Confidence.Factors, "\n"); !strings.Contains(joined, c.factor) {
				t.Errorf("expected a factor mentioning %q, got:\n%s", c.factor, joined)
			}
		})
	}
}

func TestConfidence_SingleModerateHitStaysModerate(t *testing.T) {
	// One moderate hit alone does not demote to low — only >=2 (or any low) do.
	cases := []struct {
		name   string
		mutate func(*sidecar.Sidecar)
	}{
		{"event count 100-999", func(s *sidecar.Sidecar) { s.Target.PerReplicaEventCounts = map[string]int{"r0": 500} }},
		{"drop rate 0<r<1%", func(s *sidecar.Sidecar) { s.TraceHealth.DropRate = 0.005 }},
		{"disagreement of one", func(s *sidecar.Sidecar) { s.Target.ReplicaCapDisagreement = []string{"CHOWN"} }},
		{"exactly two comms", func(s *sidecar.Sidecar) { s.Target.DistinctComms = 2 }},
		{"no workload", func(s *sidecar.Sidecar) { s.Workload = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := cleanModerate()
			c.mutate(s)
			if got := gradeOf(s); got != sidecar.ConfidenceModerate {
				t.Errorf("grade = %q, want moderate (one moderate hit):\n%s", got, strings.Join(s.Confidence.Factors, "\n"))
			}
		})
	}
}

func TestConfidence_TwoModerateHitsForceLow(t *testing.T) {
	// event count 100-999 (moderate) + no workload (moderate) = 2 hits -> low.
	s := cleanModerate()
	s.Target.PerReplicaEventCounts = map[string]int{"r0": 500}
	s.Workload = ""
	if got := gradeOf(s); got != sidecar.ConfidenceLow {
		t.Errorf("grade = %q, want low (two moderate hits):\n%s", got, strings.Join(s.Confidence.Factors, "\n"))
	}
}

func TestConfidence_CrossCheckUnavailableIsInformationalOnly(t *testing.T) {
	// A cross-check that was attempted but couldn't run (daemon down, image
	// absent) is informational — it must not by itself demote the grade.
	s := cleanModerate()
	s.CrossCheckStatus = "docker inspect postgres:16: daemon not running"
	s.ExpectedCapsFromEntrypoint = nil
	if got := gradeOf(s); got != sidecar.ConfidenceModerate {
		t.Errorf("grade = %q, want moderate (unavailable cross-check is info):\n%s", got, strings.Join(s.Confidence.Factors, "\n"))
	}
	if joined := strings.Join(s.Confidence.Factors, "\n"); !strings.Contains(joined, "cross-check unavailable") {
		t.Errorf("expected an 'unavailable' info factor, got:\n%s", joined)
	}
}
